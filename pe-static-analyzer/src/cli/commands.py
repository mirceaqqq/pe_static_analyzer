"""
PE Static Analyzer - CLI Interface
Interfață completă linie de comandă cu argparse și rich

Comenzi disponibile:
- analyze: Analizează un executabil
- batch: Analizează multiple executabile
- report: Generează raport detaliat
- list-modules: Listează module disponibile
- stats: Afișează statistici
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional
import json

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.tree import Tree
except ImportError:
    print("Instalează rich: pip install rich")
    sys.exit(1)

# Import framework
from src.core.analyzer import PEStaticAnalyzer, AnalysisResult
from src.modules import create_default_modules


console = Console()


class PEAnalyzerCLI:
    """
    Interfață CLI completă pentru framework
    """
    
    def __init__(self):
        self.analyzer = PEStaticAnalyzer()
        self._register_modules()
    
    def _register_modules(self):
        """Înregistrează toate modulele default"""
        modules = create_default_modules()
        for module in modules:
            self.analyzer.plugin_manager.register_module(module)
        
        console.print(f"[green]✓[/green] Încărcate {len(modules)} module de analiză")
    
    def analyze_file(self, file_path: str, output: Optional[str] = None, verbose: bool = False):
        """
        Analizează un singur fișier
        
        Args:
            file_path: Calea către executabil
            output: Fișier pentru salvare raport JSON (opțional)
            verbose: Afișare detaliată
        """
        try:
            console.print(f"\n[bold cyan]🔍 Analiză statică PE[/bold cyan]")
            console.print(f"[dim]Fișier:[/dim] {file_path}\n")
            
            # Analiză cu progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Analiză în curs...", total=None)
                result = self.analyzer.analyze_file(file_path)
                progress.update(task, completed=True)
            
            # Afișare rezultate
            self._display_results(result, verbose)
            
            # Salvare raport
            if output:
                self._save_report(result, output)
        
        except Exception as e:
            console.print(f"[bold red]✗[/bold red] Eroare: {e}")
            sys.exit(1)
    
    def analyze_batch(self, file_paths: List[str], output_dir: Optional[str] = None):
        """
        Analizează multiple fișiere
        
        Args:
            file_paths: Listă căi executabile
            output_dir: Director pentru rapoarte (opțional)
        """
        console.print(f"\n[bold cyan]🔍 Analiză batch[/bold cyan]")
        console.print(f"[dim]Fișiere de procesat:[/dim] {len(file_paths)}\n")
        
        results = []
        
        with Progress(console=console) as progress:
            task = progress.add_task("Procesare...", total=len(file_paths))
            
            for file_path in file_paths:
                try:
                    result = self.analyzer.analyze_file(file_path)
                    results.append(result)
                    
                    # Salvare individuală
                    if output_dir:
                        output_path = Path(output_dir) / f"{Path(file_path).stem}_report.json"
                        self._save_report(result, str(output_path))
                
                except Exception as e:
                    console.print(f"[red]Eroare {file_path}:[/red] {e}")
                
                progress.advance(task)
        
        # Sumar final
        self._display_batch_summary(results)
    
    def list_modules(self):
        """Afișează toate modulele înregistrate"""
        console.print("\n[bold cyan]📦 Module disponibile[/bold cyan]\n")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Modul", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Versiune")
        
        for module_name in self.analyzer.plugin_manager.list_modules():
            module = self.analyzer.plugin_manager.get_module(module_name)
            status = "✓ Activ" if module.enabled else "✗ Inactiv"
            status_style = "green" if module.enabled else "red"
            
            metadata = module.get_metadata()
            table.add_row(
                module_name,
                f"[{status_style}]{status}[/{status_style}]",
                metadata.get('version', 'N/A')
            )
        
        console.print(table)
    
    def show_statistics(self):
        """Afișează statistici framework"""
        stats = self.analyzer.get_statistics()
        
        console.print("\n[bold cyan]📊 Statistici Framework[/bold cyan]\n")
        
        panel = Panel(
            f"""[bold]Total analize:[/bold] {stats['total_analyses']}
[bold green]Reușite:[/bold green] {stats['successful']}
[bold red]Eșuate:[/bold red] {stats['failed']}
[bold]Rată succes:[/bold] {stats['success_rate']:.1f}%

[bold]Module active:[/bold] {len(stats['registered_modules'])}""",
            title="📈 Statistici",
            border_style="cyan"
        )
        
        console.print(panel)
    
    def _display_results(self, result: AnalysisResult, verbose: bool = False):
        """Afișează rezultatele analizei în format fancy"""
        
        # Header
        risk_colors = {
            'LOW': 'green',
            'MEDIUM': 'yellow',
            'HIGH': 'orange1',
            'CRITICAL': 'red'
        }
        risk_color = risk_colors.get(result.risk_level, 'white')
        
        console.print(Panel(
            f"[bold]Scor Suspiciune:[/bold] {result.suspicion_score:.1f}/100\n"
            f"[bold]Nivel Risc:[/bold] [{risk_color}]{result.risk_level}[/{risk_color}]\n"
            f"[bold]Durată:[/bold] {result.analysis_duration:.2f}s",
            title=f"📊 Rezultat: {Path(result.file_path).name}",
            border_style=risk_color
        ))
        
        # Hash-uri
        console.print("\n[bold cyan]🔐 Hash-uri[/bold cyan]")
        hash_table = Table(show_header=False, box=None)
        hash_table.add_column("Tip", style="dim")
        hash_table.add_column("Valoare", style="cyan")
        
        for hash_type, hash_value in result.file_hash.items():
            if hash_type != 'size':
                hash_table.add_row(hash_type.upper(), hash_value)
        
        console.print(hash_table)
        
        # Entropie
        if result.entropy_data:
            console.print("\n[bold cyan]📈 Entropie Secțiuni[/bold cyan]")
            entropy_table = Table(show_header=True, header_style="bold")
            entropy_table.add_column("Secțiune")
            entropy_table.add_column("Entropie", justify="right")
            entropy_table.add_column("Status")
            
            for section, entropy in result.entropy_data.items():
                if section != '_average':
                    status = "🔴 Ridicată" if entropy > 7.0 else "🟢 Normală"
                    entropy_table.add_row(section, f"{entropy:.3f}", status)
            
            console.print(entropy_table)
        
        # Detecții YARA
        if result.yara_matches:
            console.print(f"\n[bold red]⚠️  Detectate {len(result.yara_matches)} match-uri YARA[/bold red]")
            
            for match in result.yara_matches[:5]:  # Primele 5
                console.print(f"  • [red]{match['rule']}[/red] ({match['namespace']})")
        
        # Packer
        if result.packer_detected:
            console.print(f"\n[bold yellow]📦 Packer detectat:[/bold yellow] {result.packer_detected}")
        
        # Flag-uri heuristice
        if result.heuristic_flags:
            console.print(f"\n[bold yellow]🚩 Flag-uri Heuristice ({len(result.heuristic_flags)})[/bold yellow]")
            
            for flag in result.heuristic_flags[:10]:  # Primele 10
                console.print(f"  • [yellow]{flag}[/yellow]")
        
        # Detalii verbose
        if verbose:
            self._display_verbose_details(result)
    
    def _display_verbose_details(self, result: AnalysisResult):
        """Afișare detalii complete"""
        
        # Secțiuni
        if result.sections:
            console.print("\n[bold cyan]📑 Secțiuni PE[/bold cyan]")
            section_table = Table(show_header=True)
            section_table.add_column("Nume", style="cyan")
            section_table.add_column("VA", style="dim")
            section_table.add_column("V.Size", justify="right")
            section_table.add_column("Raw Size", justify="right")
            section_table.add_column("Perms")
            
            for section in result.sections:
                perms = ""
                if section['readable']: perms += "R"
                if section['writable']: perms += "W"
                if section['executable']: perms += "X"
                
                section_table.add_row(
                    section['name'],
                    section['virtual_address'],
                    str(section['virtual_size']),
                    str(section['raw_size']),
                    perms
                )
            
            console.print(section_table)
        
        # Importuri suspicioase
        suspicious_imports = [
            imp for imp in result.imports 
            if any(susp in imp['function'] for susp in ['Virtual', 'Process', 'Thread', 'Inject'])
        ]
        
        if suspicious_imports:
            console.print("\n[bold red]⚠️  API-uri Suspicioase[/bold red]")
            for imp in suspicious_imports[:15]:
                console.print(f"  • {imp['dll']} → [red]{imp['function']}[/red]")
    
    def _display_batch_summary(self, results: List[AnalysisResult]):
        """Afișare sumar batch"""
        console.print("\n[bold cyan]📊 Sumar Analiză Batch[/bold cyan]\n")
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Fișier", style="cyan", no_wrap=True)
        table.add_column("Scor", justify="right")
        table.add_column("Risc", justify="center")
        table.add_column("YARA", justify="center")
        table.add_column("Packer")
        
        for result in results:
            risk_color = {
                'LOW': 'green',
                'MEDIUM': 'yellow',
                'HIGH': 'orange1',
                'CRITICAL': 'red'
            }.get(result.risk_level, 'white')
            
            table.add_row(
                Path(result.file_path).name,
                f"{result.suspicion_score:.1f}",
                f"[{risk_color}]{result.risk_level}[/{risk_color}]",
                str(len(result.yara_matches)),
                result.packer_detected or "-"
            )
        
        console.print(table)
        
        # Statistici
        avg_score = sum(r.suspicion_score for r in results) / len(results)
        high_risk = sum(1 for r in results if r.risk_level in ['HIGH', 'CRITICAL'])
        
        console.print(f"\n[bold]Scor mediu:[/bold] {avg_score:.1f}")
        console.print(f"[bold]Risc ridicat/critic:[/bold] {high_risk}/{len(results)}")
    
    def _save_report(self, result: AnalysisResult, output_path: str):
        """Salvează raport JSON"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
            
            console.print(f"\n[green]✓[/green] Raport salvat: {output_path}")
        
        except Exception as e:
            console.print(f"[red]✗[/red] Eroare salvare raport: {e}")


def main():
    """Entry point CLI"""
    parser = argparse.ArgumentParser(
        description="🛡️  PE Static Analyzer - Framework analiză statică executabile Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemple de utilizare:
  %(prog)s analyze malware.exe
  %(prog)s analyze malware.exe --output report.json --verbose
  %(prog)s batch *.exe --output-dir reports/
  %(prog)s list-modules
  %(prog)s stats
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Comenzi disponibile')
    
    # Comandă: analyze
    analyze_parser = subparsers.add_parser('analyze', help='Analizează un executabil')
    analyze_parser.add_argument('file', help='Calea către executabil')
    analyze_parser.add_argument('-o', '--output', help='Fișier raport JSON')
    analyze_parser.add_argument('-v', '--verbose', action='store_true', help='Afișare detaliată')
    
    # Comandă: batch
    batch_parser = subparsers.add_parser('batch', help='Analiză batch multiple fișiere')
    batch_parser.add_argument('files', nargs='+', help='Liste fișiere')
    batch_parser.add_argument('-o', '--output-dir', help='Director rapoarte')
    
    # Comandă: list-modules
    subparsers.add_parser('list-modules', help='Listează module disponibile')
    
    # Comandă: stats
    subparsers.add_parser('stats', help='Afișează statistici')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Inițializare CLI
    cli = PEAnalyzerCLI()
    
    # Execută comanda
    try:
        if args.command == 'analyze':
            cli.analyze_file(args.file, args.output, args.verbose)
        
        elif args.command == 'batch':
            cli.analyze_batch(args.files, args.output_dir)
        
        elif args.command == 'list-modules':
            cli.list_modules()
        
        elif args.command == 'stats':
            cli.show_statistics()
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Întrerupt de utilizator[/yellow]")
        sys.exit(0)
    
    except Exception as e:
        console.print(f"[bold red]Eroare:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()