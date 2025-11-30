"""
PE Static Analyzer - CLI interface powered by argparse and rich.

Commands:
  - analyze: analyze a single executable
  - batch: analyze multiple executables
  - scan-dir: recursively scan a folder
  - watch: start a real-time watcher (on-create/on-modify)
  - list-modules: list registered modules
  - stats: show framework statistics
  - yara-sync: download YARA rules from GitHub and recompile them locally
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional
import threading

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
except ImportError:
    print("Instaleaza rich: pip install rich")
    sys.exit(1)

from src.core.analyzer import AnalysisResult, PEStaticAnalyzer
from src.modules import create_default_modules
from src.utils.quarantine import quarantine_if_needed
from src.utils.yara_sync import (
    DEFAULT_BRANCH,
    DEFAULT_FOLDERS,
    DEFAULT_OWNER,
    DEFAULT_REPO,
    sync_yara_rules,
)
from src.av.watcher import start_watch

console = Console()


class PEAnalyzerCLI:
    """Full-featured CLI wrapper over the analysis engine."""

    def __init__(self):
        self.analyzer = PEStaticAnalyzer()
        self._register_modules()

    def _register_modules(self):
        modules = create_default_modules()
        for module in modules:
            self.analyzer.plugin_manager.register_module(module)
        console.print(f"[green]OK[/green] Incarcate {len(modules)} module de analiza")

    def analyze_file(self, file_path: str, output: Optional[str] = None, verbose: bool = False):
        """Analyze a single PE file."""
        console.print(f"\n[bold cyan]Analiza statica PE[/bold cyan]")
        console.print(f"[dim]Fisier:[/dim] {file_path}\n")

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Analiza in curs...", total=None)
            result = self.analyzer.analyze_file(file_path)
            progress.update(task, completed=True)

        self._display_results(result, verbose)

        if output:
            self._save_report(result, output)

    def analyze_batch(self, file_paths: List[str], output_dir: Optional[str] = None):
        """Analyze multiple files."""
        console.print(f"\n[bold cyan]Analiza batch[/bold cyan]")
        console.print(f"[dim]Fisiere de procesat:[/dim] {len(file_paths)}\n")

        results = []
        with Progress(console=console) as progress:
            task = progress.add_task("Procesare...", total=len(file_paths))
            for file_path in file_paths:
                try:
                    result = self.analyzer.analyze_file(file_path)
                    results.append(result)
                    if output_dir:
                        output_path = Path(output_dir) / f"{Path(file_path).stem}_report.json"
                        self._save_report(result, str(output_path))
                except Exception as exc:  # noqa: BLE001
                    console.print(f"[red]Eroare {file_path}:[/red] {exc}")
                progress.advance(task)

        self._display_batch_summary(results)

    def list_modules(self):
        """List all registered modules."""
        console.print("\n[bold cyan]Module disponibile[/bold cyan]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Modul", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Versiune")

        for module_name in self.analyzer.plugin_manager.list_modules():
            module = self.analyzer.plugin_manager.get_module(module_name)
            status = "Activ" if module and module.enabled else "Inactiv"
            status_style = "green" if module and module.enabled else "red"
            metadata = module.get_metadata() if module else {}
            table.add_row(module_name, f"[{status_style}]{status}[/{status_style}]", metadata.get("version", "N/A"))

        console.print(table)

    def show_statistics(self):
        """Display framework statistics."""
        stats = self.analyzer.get_statistics()
        panel = Panel(
            f"""[bold]Total analize:[/bold] {stats['total_analyses']}
[bold green]Reusite:[/bold green] {stats['successful']}
[bold red]Esuate:[/bold red] {stats['failed']}
[bold]Rata succes:[/bold] {stats['success_rate']:.1f}%

[bold]Module active:[/bold] {len(stats['registered_modules'])}""",
            title="Statistici",
            border_style="cyan",
        )
        console.print("\n[bold cyan]Statistici Framework[/bold cyan]\n")
        console.print(panel)

    def sync_yara(
        self,
        owner: str,
        repo: str,
        branch: str,
        folders: Optional[List[str]],
        target_dir: Path,
        token: str,
    ):
        """Download YARA rules from GitHub and recompile the scanner."""
        resolved_token = token or os.getenv("GITHUB_TOKEN", "")
        saved = sync_yara_rules(owner=owner, repo=repo, branch=branch, folders=folders, target_dir=target_dir, token=resolved_token)
        if saved:
            console.print(f"[green]OK[/green] Descarcate {saved} fisiere YARA in {target_dir}")
        else:
            console.print(f"[yellow]Atentie[/yellow] Nu s-au descarcat fisiere noi (verifica conexiunea sau permisiunile).")

        yara_module = self.analyzer.plugin_manager.get_module("yara_scanner")
        if yara_module and hasattr(yara_module, "reload_rules"):
            yara_module.reload_rules()
            console.print("[cyan]Regulile YARA au fost recompilate si vor fi folosite la urmatoarea analiza.[/cyan]")
        else:
            console.print("[red]Modulul YARA nu este disponibil pentru recompilare.[/red]")

    # ---------------- internal helpers ---------------- #
    def _display_results(self, result: AnalysisResult, verbose: bool = False):
        """Pretty-print analysis result."""
        risk_colors = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "orange1", "CRITICAL": "red"}
        risk_color = risk_colors.get(result.risk_level, "white")

        console.print(
            Panel(
                f"[bold]Scor Suspiciune:[/bold] {result.suspicion_score:.1f}/100\n"
                f"[bold]Nivel Risc:[/bold] [{risk_color}]{result.risk_level}[/{risk_color}]\n"
                f"[bold]Durata:[/bold] {result.analysis_duration:.2f}s",
                title=f"Rezultat: {Path(result.file_path).name}",
                border_style=risk_color,
            )
        )

        console.print("\n[bold cyan]Hash-uri[/bold cyan]")
        hash_table = Table(show_header=False, box=None)
        hash_table.add_column("Tip", style="dim")
        hash_table.add_column("Valoare", style="cyan")
        for hash_type, hash_value in result.file_hash.items():
            if hash_type != "size":
                hash_table.add_row(hash_type.upper(), hash_value)
        console.print(hash_table)

        if result.entropy_data:
            console.print("\n[bold cyan]Entropie Sectiuni[/bold cyan]")
            entropy_table = Table(show_header=True, header_style="bold")
            entropy_table.add_column("Sectiune")
            entropy_table.add_column("Entropie", justify="right")
            entropy_table.add_column("Status")
            for section, entropy in result.entropy_data.items():
                if section != "_average":
                    status = "Ridicata" if entropy > 7.0 else "Normala"
                    entropy_table.add_row(section, f"{entropy:.3f}", status)
            console.print(entropy_table)

        if result.yara_matches:
            console.print(f"\n[bold red]Detectate {len(result.yara_matches)} match-uri YARA[/bold red]")
            for match in result.yara_matches[:5]:
                console.print(f"  • [red]{match['rule']}[/red] ({match['namespace']})")

        if result.packer_detected:
            console.print(f"\n[bold yellow]Packer detectat:[/bold yellow] {result.packer_detected}")

        if result.heuristic_flags:
            console.print(f"\n[bold yellow]Flag-uri Heuristice ({len(result.heuristic_flags)})[/bold yellow]")
            for flag in result.heuristic_flags[:10]:
                console.print(f"  • [yellow]{flag}[/yellow]")

        if verbose:
            self._display_verbose_details(result)

    def _display_verbose_details(self, result: AnalysisResult):
        """Print extended details."""
        if result.sections:
            console.print("\n[bold cyan]Sectiuni PE[/bold cyan]")
            section_table = Table(show_header=True)
            section_table.add_column("Nume", style="cyan")
            section_table.add_column("VA", style="dim")
            section_table.add_column("V.Size", justify="right")
            section_table.add_column("Raw Size", justify="right")
            section_table.add_column("Perms")

            for section in result.sections:
                perms = ""
                if section.get("readable"):
                    perms += "R"
                if section.get("writable"):
                    perms += "W"
                if section.get("executable"):
                    perms += "X"

                section_table.add_row(
                    section.get("name", "-"),
                    section.get("virtual_address", "-"),
                    str(section.get("virtual_size", "")),
                    str(section.get("raw_size", "")),
                    perms,
                )

            console.print(section_table)

        suspicious_imports = [
            imp
            for imp in result.imports
            if any(susp in imp.get("function", "") for susp in ["Virtual", "Process", "Thread", "Inject"])
        ]
        if suspicious_imports:
            console.print("\n[bold red]API-uri Suspicioase[/bold red]")
            for imp in suspicious_imports[:15]:
                console.print(f"  • {imp.get('dll', '')} -> [red]{imp.get('function', '')}[/red]")

    def _display_batch_summary(self, results: List[AnalysisResult]):
        """Print summary for batch run."""
        console.print("\n[bold cyan]Sumar Analiza Batch[/bold cyan]\n")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Fisier", style="cyan", no_wrap=True)
        table.add_column("Scor", justify="right")
        table.add_column("Risc", justify="center")
        table.add_column("YARA", justify="center")
        table.add_column("Packer")

        for result in results:
            risk_color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "orange1", "CRITICAL": "red"}.get(
                result.risk_level, "white"
            )
            table.add_row(
                Path(result.file_path).name,
                f"{result.suspicion_score:.1f}",
                f"[{risk_color}]{result.risk_level}[/{risk_color}]",
                str(len(result.yara_matches)),
                result.packer_detected or "-",
            )

        console.print(table)
        if results:
            avg_score = sum(r.suspicion_score for r in results) / len(results)
            high_risk = sum(1 for r in results if r.risk_level in ["HIGH", "CRITICAL"])
            console.print(f"\n[bold]Scor mediu:[/bold] {avg_score:.1f}")
            console.print(f"[bold]Risc ridicat/critic:[/bold] {high_risk}/{len(results)}")

    def _save_report(self, result: AnalysisResult, output_path: str):
        """Save analysis result to JSON."""
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
            console.print(f"\n[green]OK[/green] Raport salvat: {output_path}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Eroare salvare raport:[/red] {exc}")

    # -------------- AV helpers -------------- #
    def scan_directory(self, directory: str, recursive: bool = True):
        """Recursively scan a directory."""
        directory_path = Path(directory)
        if not directory_path.is_dir():
            console.print(f"[red]Director invalid:[/red] {directory}")
            return

        files = [p for p in directory_path.rglob("*") if p.is_file()] if recursive else list(directory_path.iterdir())
        console.print(f"[cyan]Scanare {len(files)} fisiere din {directory_path}[/cyan]")

        for path in files:
            try:
                res = self.analyzer.analyze_file(str(path))
                console.print(f"[green]OK[/green] {path} -> {res.risk_level} ({res.suspicion_score:.1f})")
            except Exception as exc:  # noqa: BLE001
                console.print(f"[red]Eroare {path}:[/red] {exc}")

    def watch_paths(self, paths: List[str], recursive: bool = True, yara_autoupdate: bool = True, interval_min: int = 60):
        """Start real-time watcher; blocks the thread."""
        console.print(f"[cyan]Pornire watcher pe {paths}[/cyan]")

        def _auto_update():
            while True:
                try:
                    saved = sync_yara_rules()
                    if saved:
                        module = self.analyzer.plugin_manager.get_module("yara_scanner")
                        if module and hasattr(module, "reload_rules"):
                            module.reload_rules()
                        console.print(f"[green]YARA update[/green]: +{saved} fisiere noi")
                except Exception as exc:  # noqa: BLE001
                    console.print(f"[yellow]YARA update esuat:[/yellow] {exc}")
                finally:
                    import time

                    time.sleep(interval_min * 60)

        if yara_autoupdate:
            threading.Thread(target=_auto_update, daemon=True).start()

        start_watch(
            paths=paths,
            analyzer=self.analyzer,
            recursive=recursive,
            on_result=lambda r: console.print(f"[magenta]WATCH[/magenta] {Path(r.file_path).name} -> {r.risk_level}"),
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PE Static Analyzer - framework de analiza statica pentru executabile Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemple de utilizare:
  %(prog)s analyze malware.exe
  %(prog)s analyze malware.exe --output report.json --verbose
  %(prog)s batch *.exe --output-dir reports/
  %(prog)s list-modules
  %(prog)s stats
  %(prog)s yara-sync --token <GITHUB_TOKEN>
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Comenzi disponibile")

    analyze_parser = subparsers.add_parser("analyze", help="Analizeaza un executabil")
    analyze_parser.add_argument("file", help="Calea catre executabil")
    analyze_parser.add_argument("-o", "--output", help="Fisier raport JSON")
    analyze_parser.add_argument("-v", "--verbose", action="store_true", help="Afisare detaliata")

    batch_parser = subparsers.add_parser("batch", help="Analiza batch multiple fisiere")
    batch_parser.add_argument("files", nargs="+", help="Liste fisiere")
    batch_parser.add_argument("-o", "--output-dir", help="Director rapoarte")

    scan_dir_parser = subparsers.add_parser("scan-dir", help="Scaneaza recursiv un director")
    scan_dir_parser.add_argument("directory", help="Director de scanat")
    scan_dir_parser.add_argument("--no-recursive", dest="recursive", action="store_false", help="Nu scana subfolderele")

    watch_parser = subparsers.add_parser("watch", help="Monitorizare real-time (on-create/on-modify)")
    watch_parser.add_argument("paths", nargs="+", help="Cai de monitorizat")
    watch_parser.add_argument("--no-recursive", dest="recursive", action="store_false", help="Nu urmari recursiv")
    watch_parser.add_argument("--no-yara-update", dest="yara_autoupdate", action="store_false", help="Dezactiveaza update automat YARA")
    watch_parser.add_argument("--interval-min", type=int, default=60, help="Interval update YARA (minute)")

    subparsers.add_parser("list-modules", help="Listeaza module disponibile")
    subparsers.add_parser("stats", help="Afiseaza statistici")

    yara_sync_parser = subparsers.add_parser(
        "yara-sync", help="Descarca reguli YARA dintr-un repo GitHub (ex: Yara-Rules/rules)"
    )
    yara_sync_parser.add_argument("--owner", default=DEFAULT_OWNER, help="Owner repo GitHub")
    yara_sync_parser.add_argument("--repo", default=DEFAULT_REPO, help="Numele repository-ului")
    yara_sync_parser.add_argument("--branch", default=DEFAULT_BRANCH, help="Branch (implicit master)")
    yara_sync_parser.add_argument(
        "--folder",
        dest="folders",
        action="append",
        help="Folder remote de unde sa ia reguli (poate fi specificat de mai multe ori). Implicit: "
        + ", ".join(DEFAULT_FOLDERS),
    )
    yara_sync_parser.add_argument(
        "--target-dir", default=str(Path("yara_rules") / "remote"), help="Director local pentru reguli descarcate"
    )
    yara_sync_parser.add_argument("--token", help="GitHub token (sau GITHUB_TOKEN din environment)")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    cli = PEAnalyzerCLI()

    try:
        if args.command == "analyze":
            cli.analyze_file(args.file, args.output, args.verbose)
        elif args.command == "batch":
            cli.analyze_batch(args.files, args.output_dir)
        elif args.command == "list-modules":
            cli.list_modules()
        elif args.command == "stats":
            cli.show_statistics()
        elif args.command == "yara-sync":
            cli.sync_yara(
                owner=args.owner,
                repo=args.repo,
                branch=args.branch,
                folders=args.folders,
                target_dir=Path(args.target_dir),
                token=args.token or "",
            )
        elif args.command == "scan-dir":
            cli.scan_directory(args.directory, recursive=getattr(args, "recursive", True))
        elif args.command == "watch":
            cli.watch_paths(
                paths=args.paths,
                recursive=getattr(args, "recursive", True),
                yara_autoupdate=getattr(args, "yara_autoupdate", True),
                interval_min=getattr(args, "interval_min", 60),
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]Intrerupt de utilizator[/yellow]")
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Eroare:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
