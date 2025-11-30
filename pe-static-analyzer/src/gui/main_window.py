"""
PE Static Analyzer - GUI Interface
PySide6/PyQt5 desktop UI for interacting with the analysis engine.
"""

import sys
import json
import base64
import os
from pathlib import Path
from typing import Optional, Dict, Any, List


def _bootstrap_qt():
    """Ensure PySide6 DLL paths are visible on Windows before import."""
    qt_dir = Path(sys.prefix) / "Lib" / "site-packages" / "PySide6"
    if qt_dir.exists():
        try:
            os.add_dll_directory(str(qt_dir))
            os.environ["PATH"] = str(qt_dir) + os.pathsep + os.environ.get("PATH", "")
            plugins = qt_dir / "plugins"
            if plugins.exists():
                os.environ["QT_PLUGIN_PATH"] = str(plugins)
                os.environ["PATH"] = str(plugins) + os.pathsep + os.environ["PATH"]
            bin_dir = qt_dir / "bin"
            if bin_dir.exists():
                os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ["PATH"]
        except Exception:
            pass


_bootstrap_qt()

try:
    from PySide6.QtWidgets import (
        QApplication,
        QMainWindow,
        QWidget,
        QVBoxLayout,
        QHBoxLayout,
        QPushButton,
        QLabel,
        QTextEdit,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QFileDialog,
        QMessageBox,
        QProgressBar,
        QSplitter,
        QTreeWidget,
        QTreeWidgetItem,
        QComboBox,
        QScrollArea,
        QSpinBox,
        QFormLayout,
        QGraphicsDropShadowEffect,
        QGraphicsOpacityEffect,
        QDialog,
        QSplashScreen,
    )
    from PySide6.QtCore import Qt, QThread, Signal, QEasingCurve, QPropertyAnimation, QTimer
    from PySide6.QtGui import QFont, QPixmap
except Exception as e:
    print(f"PySide6 import failed: {e}")
    try:
        from PyQt5.QtWidgets import *  # type: ignore
        from PyQt5.QtCore import *  # type: ignore
        from PyQt5.QtGui import *  # type: ignore
        print("Using PyQt5 backend")
    except Exception as e2:
        print(f"PyQt5 import failed: {e2}")
        print("Install PySide6: pip install PySide6")
        sys.exit(1)

from src.core.analyzer import PEStaticAnalyzer, AnalysisResult
from src.modules import create_default_modules
from src.database.repository import AnalysisRepository
from src.reporting import report_generator
from src.gui.style import BASE_QSS


class AnalyzerThread(QThread):
    """Worker thread for running analysis without blocking the UI."""

    finished = Signal(object)
    error = Signal(str)
    progress = Signal(str)

    def __init__(self, analyzer: PEStaticAnalyzer, file_path: str):
        super().__init__()
        self.analyzer = analyzer
        self.file_path = file_path

    def run(self):
        try:
            self.progress.emit("Pornire analiza...")
            result = self.analyzer.analyze_file(self.file_path)
            self.progress.emit("Analiza finalizata")
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class PEAnalyzerGUI(QMainWindow):
    """Main window for the PE analyzer GUI."""

    def __init__(self):
        super().__init__()
        self.analyzer = PEStaticAnalyzer()
        for m in create_default_modules():
            self.analyzer.plugin_manager.register_module(m)
        self.repo = AnalysisRepository()
        self.current_result: Optional[AnalysisResult] = None
        self.thread: Optional[AnalyzerThread] = None
        self._build_ui()
        self.setAcceptDrops(True)

    # --- UI construction ---
    def _build_ui(self):
        self.setWindowTitle("PE Static Analyzer")
        self.setGeometry(80, 80, 1550, 980)
        self._apply_theme()

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        # Header
        header_frame = QWidget()
        header_frame.setObjectName("GlassPanel")
        header = QHBoxLayout(header_frame)
        header.setContentsMargins(12, 8, 12, 8)
        self.title = QLabel("PE Static Analyzer")
        self.title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        self.subtitle = QLabel("Drag & drop un executabil sau alege cu Select")
        self.subtitle.setFont(QFont("Segoe UI", 11))

        title_box = QVBoxLayout()
        title_box.addWidget(self.title)
        title_box.addWidget(self.subtitle)

        self.score_chip = QLabel("Score: --")
        self.score_chip.setObjectName("ChipPrimary")
        self.risk_chip = QLabel("Risk: UNKNOWN")
        self.risk_chip.setObjectName("ChipNeutral")
        self.modules_chip = QLabel(f"Modules: {len(self.analyzer.plugin_manager.modules)}")
        self.modules_chip.setObjectName("ChipSecondary")

        chip_box = QHBoxLayout()
        chip_box.addWidget(self.score_chip)
        chip_box.addWidget(self.risk_chip)
        chip_box.addWidget(self.modules_chip)
        chip_box.addStretch()

        header.addLayout(title_box)
        header.addStretch()
        header.addLayout(chip_box)
        layout.addWidget(header_frame)

        # Toolbar
        toolbar_frame = QWidget()
        toolbar_frame.setObjectName("GlassPanel")
        toolbar = QHBoxLayout(toolbar_frame)
        toolbar.setContentsMargins(12, 8, 12, 8)
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["Complet", "Rapid (fara VT/YARA)", "Offline (fara VT)"])
        self.profile_combo.currentIndexChanged.connect(self._apply_profile)

        self.btn_select = QPushButton("Selecteaza executabil")
        self.btn_select.clicked.connect(self.select_file)
        self.btn_analyze = QPushButton("Analizeaza")
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.clicked.connect(self.start_analysis)
        self.btn_export = QPushButton("Exporta JSON")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self.export_report)
        self.btn_export_html = QPushButton("Exporta HTML")
        self.btn_export_html.setEnabled(False)
        self.btn_export_html.clicked.connect(self.export_html)
        self.btn_clear = QPushButton("Curata")
        self.btn_clear.clicked.connect(self.clear_results)

        toolbar.addWidget(QLabel("Profil:"))
        toolbar.addWidget(self.profile_combo)
        for b in [self.btn_select, self.btn_analyze, self.btn_export, self.btn_export_html, self.btn_clear]:
            toolbar.addWidget(b)
        toolbar.addStretch()
        layout.addWidget(toolbar_frame)

        # Main splitter: top info + tabs
        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter)

        self.file_info = QTextEdit()
        self.file_info.setReadOnly(True)
        self.file_info.setMaximumHeight(180)
        splitter.addWidget(self.file_info)

        self.tabs = QTabWidget()
        splitter.addWidget(self.tabs)

        self.findings_view = QTextEdit()
        self.findings_view.setReadOnly(True)
        self.btn_charts = QPushButton("Grafice detaliate")
        self.btn_charts.clicked.connect(self._show_chart_dialog)
        findings_container = QWidget()
        findings_layout = QVBoxLayout()
        bar = QHBoxLayout()
        bar.addWidget(self.btn_charts)
        bar.addStretch()
        findings_layout.addLayout(bar)
        findings_layout.addWidget(self.findings_view)
        findings_container.setLayout(findings_layout)
        self.tabs.addTab(findings_container, "Findings")

        self.anomalies_table = QTableWidget()
        self.tabs.addTab(self.anomalies_table, "Anomalii")

        self.overview = QTextEdit(); self.overview.setReadOnly(True)
        self.hash_table = QTableWidget()
        self.sections = QTableWidget()
        self.headers_table = QTableWidget()
        self.imports = QTreeWidget(); self.imports.setHeaderLabels(["DLL / Functie", "Address"])
        self.exports = QTableWidget()
        self.resources_table = QTableWidget()
        self.strings_table = QTableWidget()
        self.disassembly_view = QTextEdit(); self.disassembly_view.setReadOnly(True)
        # Pseudo/CFG area with function selection
        self.func_list = QTreeWidget()
        self.func_list.setHeaderLabels(["Function", "Address"])
        self.func_list.itemSelectionChanged.connect(self._on_func_selected)
        self.pseudo_view = QTextEdit(); self.pseudo_view.setObjectName("PseudoView"); self.pseudo_view.setReadOnly(True); self.pseudo_view.setFont(QFont("Consolas", 10))
        self.cfg_view = QTextEdit(); self.cfg_view.setObjectName("CfgView"); self.cfg_view.setReadOnly(True); self.cfg_view.setFont(QFont("Consolas", 10))
        self.graphviz_label = QLabel("Selecteaza o functie pentru a genera CFG")
        self.graphviz_label.setAlignment(Qt.AlignCenter)
        self.graphviz_label.setMinimumHeight(240)
        self.graphviz_area = QScrollArea()
        self.graphviz_area.setWidgetResizable(True)
        self.graphviz_area.setWidget(self.graphviz_label)
        self.detections = QTextEdit(); self.detections.setReadOnly(True)
        self.timeline = QTextEdit(); self.timeline.setReadOnly(True)
        self.errors_tab = QTextEdit(); self.errors_tab.setReadOnly(True)
        self.json_raw = QTextEdit(); self.json_raw.setReadOnly(True)

        self.tabs.addTab(self.overview, "Overview")
        self.tabs.addTab(self.hash_table, "Hash-uri")
        self.tabs.addTab(self.sections, "Sectiuni")
        self.tabs.addTab(self.headers_table, "Headere")
        self.tabs.addTab(self.imports, "Importuri")
        self.tabs.addTab(self.exports, "Exporturi")
        self.tabs.addTab(self.resources_table, "Resurse")
        self.tabs.addTab(self.strings_table, "Strings")
        self.tabs.addTab(self.disassembly_view, "Disassembly")
        # Pseudo/CFG tab composed
        pseudo_tab = QWidget()
        pseudo_layout = QVBoxLayout()
        pseudo_tab.setLayout(pseudo_layout)

        header = QLabel("Ghidra View (C & CFG)")
        header.setFont(QFont("Segoe UI", 12, QFont.Bold))
        header.setStyleSheet("padding: 6px 8px; border-radius: 8px; background: #111827;")
        pseudo_layout.addWidget(header)

        gh_split = QSplitter(Qt.Horizontal)
        self.func_list.setMaximumWidth(260)
        gh_split.addWidget(self.func_list)

        right_split = QSplitter(Qt.Vertical)
        right_split.addWidget(self.pseudo_view)
        right_split.addWidget(self.cfg_view)
        right_split.addWidget(self.graphviz_area)
        gh_split.addWidget(right_split)

        pseudo_layout.addWidget(gh_split)
        self.tabs.addTab(pseudo_tab, "Ghidra View")
        self.rules_tab = QWidget()
        self._build_rules_lab()
        self.tabs.addTab(self.rules_tab, "Rules Lab")
        self.tabs.addTab(self.detections, "Detectii")
        self.tabs.addTab(self.timeline, "Timeline")
        self.tabs.addTab(self.errors_tab, "Erori")
        self.tabs.addTab(self.json_raw, "JSON")

        # Status bar
        self.status = self.statusBar()
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(200)
        self.progress.setVisible(False)
        self.status.addPermanentWidget(self.progress)
        self.status.showMessage("Pregatit")

        self._reset_tables()
        self._apply_shadows()
        # Animatiile de tab au fost dezactivate pentru stabilitate

    def _apply_theme(self):
        self.setStyleSheet(BASE_QSS)

    def _apply_shadows(self):
        # soft shadows pentru panouri (fara blur)
        effect = QGraphicsDropShadowEffect(self)
        effect.setBlurRadius(18)
        effect.setXOffset(0)
        effect.setYOffset(3)
        effect.setColor(Qt.black)
        self.file_info.setGraphicsEffect(effect)
        effect2 = QGraphicsDropShadowEffect(self)
        effect2.setBlurRadius(18)
        effect2.setXOffset(0)
        effect2.setYOffset(3)
        effect2.setColor(Qt.black)
        self.tabs.setGraphicsEffect(effect2)

    def _setup_tab_animation(self):
        # Animatiile de tab dezactivate pentru a evita buguri
        pass

    def _build_rules_lab(self):
        layout = QVBoxLayout()
        self.rules_tab.setLayout(layout)
        title = QLabel("Rules Lab - ajusteaza ponderile de scoring")
        title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        title.setStyleSheet("padding: 6px 8px; border-radius: 8px; background: #111827;")
        layout.addWidget(title)

        form = QFormLayout()
        self.spin_yara = QSpinBox(); self.spin_yara.setRange(0, 50)
        self.spin_yara.setValue(int(self.analyzer.score_weights.get("yara_match", 10)))
        self.spin_yara_max = QSpinBox(); self.spin_yara_max.setRange(0, 100)
        self.spin_yara_max.setValue(int(self.analyzer.score_weights.get("yara_max", 40)))
        self.spin_packer = QSpinBox(); self.spin_packer.setRange(0, 50)
        self.spin_packer.setValue(int(self.analyzer.score_weights.get("packer", 10)))
        self.spin_entropy_hi = QSpinBox(); self.spin_entropy_hi.setRange(0, 50)
        self.spin_entropy_hi.setValue(int(self.analyzer.score_weights.get("entropy_high", 10)))
        self.spin_entropy_med = QSpinBox(); self.spin_entropy_med.setRange(0, 50)
        self.spin_entropy_med.setValue(int(self.analyzer.score_weights.get("entropy_medium", 5)))
        self.spin_heur_flag = QSpinBox(); self.spin_heur_flag.setRange(0, 20)
        self.spin_heur_flag.setValue(int(self.analyzer.score_weights.get("heuristic_flag", 5)))
        self.spin_heur_max = QSpinBox(); self.spin_heur_max.setRange(0, 100)
        self.spin_heur_max.setValue(int(self.analyzer.score_weights.get("heuristic_max", 25)))
        self.spin_signed_bonus = QSpinBox(); self.spin_signed_bonus.setRange(0, 50)
        self.spin_signed_bonus.setValue(int(self.analyzer.score_weights.get("signed_bonus", 15)))

        form.addRow("YARA per match", self.spin_yara)
        form.addRow("YARA max", self.spin_yara_max)
        form.addRow("Packer", self.spin_packer)
        form.addRow("Entropie mare", self.spin_entropy_hi)
        form.addRow("Entropie medie", self.spin_entropy_med)
        form.addRow("Heuristic flag", self.spin_heur_flag)
        form.addRow("Heuristic max", self.spin_heur_max)
        form.addRow("Bonus semnatura valida (scade scor)", self.spin_signed_bonus)
        layout.addLayout(form)

        btn_row = QHBoxLayout()
        apply_btn = QPushButton("Aplica ponderi")
        apply_btn.setStyleSheet("padding:10px 14px;border-radius:10px;background:#2563eb;")
        apply_btn.clicked.connect(self._apply_rules_lab)
        save_btn = QPushButton("Salveaza profil")
        save_btn.clicked.connect(self._save_rules_profile)
        load_btn = QPushButton("Incarca profil")
        load_btn.clicked.connect(self._load_rules_profile)
        btn_row.addWidget(apply_btn)
        btn_row.addWidget(save_btn)
        btn_row.addWidget(load_btn)
        layout.addLayout(btn_row)
        layout.addStretch()

    def _apply_rules_lab(self):
        self.analyzer.score_weights.update(
            {
                "yara_match": self.spin_yara.value(),
                "yara_max": self.spin_yara_max.value(),
                "packer": self.spin_packer.value(),
                "entropy_high": self.spin_entropy_hi.value(),
                "entropy_medium": self.spin_entropy_med.value(),
                "heuristic_flag": self.spin_heur_flag.value(),
                "heuristic_max": self.spin_heur_max.value(),
                "signed_bonus": self.spin_signed_bonus.value(),
            }
        )
        self.status.showMessage("Ponderi actualizate - ruleaza o noua analiza pentru efect")
        QMessageBox.information(self, "Rules Lab", "Ponderile au fost aplicate. Ruleaza din nou analiza pentru a vedea efectul.")

    # --- Event handlers ---
    def _apply_profile(self, idx: int):
        """Enable/disable modules based on profile."""
        profile = self.profile_combo.currentText().lower()
        for mod in self.analyzer.plugin_manager.modules.values():
            mod.enabled = True
        if "rapid" in profile:
            for name in ["virus_total", "yara_scanner"]:
                if m := self.analyzer.plugin_manager.get_module(name):
                    m.enabled = False
        if "offline" in profile:
            if m := self.analyzer.plugin_manager.get_module("virus_total"):
                m.enabled = False
        enabled = [m for m in self.analyzer.plugin_manager.modules.values() if m.enabled]
        self.modules_chip.setText(f"Modules: {len(enabled)}/{len(self.analyzer.plugin_manager.modules)}")
        self.status.showMessage(f"Profil aplicat: {profile}")

    def _save_rules_profile(self):
        cfg_path = Path("config/config.yaml")
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"weights": self.analyzer.score_weights}
        try:
            cfg_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            QMessageBox.information(self, "Rules Lab", f"Profil salvat: {cfg_path}")
        except Exception as e:
            QMessageBox.warning(self, "Rules Lab", f"Eroare la salvare: {e}")

    def _load_rules_profile(self):
        cfg_path = Path("config/config.yaml")
        if not cfg_path.exists():
            QMessageBox.information(self, "Rules Lab", "Nu exista profil salvat.")
            return
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            weights = data.get("weights", {})
            self.analyzer.score_weights.update(weights)
            self.spin_yara.setValue(int(weights.get("yara_match", self.spin_yara.value())))
            self.spin_yara_max.setValue(int(weights.get("yara_max", self.spin_yara_max.value())))
            self.spin_packer.setValue(int(weights.get("packer", self.spin_packer.value())))
            self.spin_entropy_hi.setValue(int(weights.get("entropy_high", self.spin_entropy_hi.value())))
            self.spin_entropy_med.setValue(int(weights.get("entropy_medium", self.spin_entropy_med.value())))
            self.spin_heur_flag.setValue(int(weights.get("heuristic_flag", self.spin_heur_flag.value())))
            self.spin_heur_max.setValue(int(weights.get("heuristic_max", self.spin_heur_max.value())))
            self.spin_signed_bonus.setValue(int(weights.get("signed_bonus", self.spin_signed_bonus.value())))
            QMessageBox.information(self, "Rules Lab", "Profil incarcat.")
        except Exception as e:
            QMessageBox.warning(self, "Rules Lab", f"Eroare la incarcare: {e}")

    def select_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "Selecteaza executabil", "", "Executabile (*.exe *.dll *.sys)"
        )
        if file:
            self.file_info.setText(f"Fisier selectat:\n{file}")
            self.current_file = file
            self.btn_analyze.setEnabled(True)
            self.subtitle.setText("Apasa Analizeaza pentru a incepe")

    def start_analysis(self):
        if not hasattr(self, "current_file"):
            return
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.btn_analyze.setEnabled(False)
        self.btn_export.setEnabled(False)
        self.btn_export_html.setEnabled(False)
        self.status.showMessage("Analiza in curs...")
        self.thread = AnalyzerThread(self.analyzer, self.current_file)
        self.thread.finished.connect(self.on_complete)
        self.thread.error.connect(self.on_error)
        self.thread.progress.connect(self.status.showMessage)
        self.thread.start()

    def clear_results(self):
        self.current_result = None
        self._reset_tables()
        self.file_info.clear()
        self.subtitle.setText("Drag & drop un executabil sau alege cu Select")
        self.btn_export.setEnabled(False)
        self.btn_export_html.setEnabled(False)
        self.status.showMessage("Reset complet")

    def on_error(self, msg):
        QMessageBox.critical(self, "Eroare", msg)
        self.progress.setVisible(False)
        self.progress.setRange(0, 100)
        self.btn_analyze.setEnabled(True)
        self.status.showMessage("Eroare la analiza")

    def on_complete(self, result: AnalysisResult):
        self.progress.setVisible(False)
        self.progress.setRange(0, 100)
        self.current_result = result
        self.btn_export.setEnabled(True)
        self.btn_export_html.setEnabled(True)
        self.btn_analyze.setEnabled(True)
        self.status.showMessage("Analiza finalizata")
        self.show_results(result)
        # Persist in DB (best-effort)
        try:
            self.repo.save_analysis(result)
            self.status.showMessage("Analiza salvata in baza de date")
        except Exception as e:
            self.status.showMessage(f"Nu am putut salva in DB: {e}")
        # Genereaza raport PDF automat
        try:
            reports_dir = Path("reports")
            reports_dir.mkdir(parents=True, exist_ok=True)
            fname = reports_dir / f"report_{Path(result.file_path).stem}.pdf"
            report_generator.generate_pdf_report(result, str(fname))
            self.status.showMessage(f"Raport PDF generat: {fname}")
        except Exception as e:
            self.status.showMessage(f"PDF auto esuat: {e}")

    def export_report(self):
        """Save current analysis as JSON."""
        if not self.current_result:
            QMessageBox.information(self, "Info", "Niciun rezultat de exportat.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Exporta raport JSON", "report.json", "JSON (*.json)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.current_result.to_dict(), f, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Succes", f"Raport salvat:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Eroare", f"Nu am putut salva raportul:\n{e}")

    def export_html(self):
        """Save current analysis as pretty HTML."""
        if not self.current_result:
            QMessageBox.information(self, "Info", "Niciun rezultat de exportat.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Exporta raport", "report.html", "HTML (*.html);;PDF (*.pdf)"
        )
        if not path:
            return
        try:
            if path.lower().endswith(".pdf"):
                report_generator.generate_pdf_report(self.current_result, path)
            else:
                report_generator.generate_html_report(self.current_result, path)
            QMessageBox.information(self, "Succes", f"Raport salvat:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Eroare", f"Nu am putut salva raportul:\n{e}")

    # --- Populate UI with results ---
    def show_results(self, r: AnalysisResult):
        self._populate_findings(r)
        self._update_summary(r)
        self._update_file_info(r)
        self._populate_overview(r)
        self._populate_hashes(r.file_hash)
        self._populate_sections(r.sections)
        self._populate_headers(r.pe_info)
        self._populate_imports(r.imports)
        self._populate_exports(r.exports)
        self._populate_resources(r.resources)
        self._populate_strings(r.strings)
        self._populate_disassembly(r.disassembly)
        self._current_pseudo = r.pseudocode
        self._populate_pseudo(r.pseudocode)
        self._populate_cfg(r.func_graphs)
        self._populate_anomalies(r.anomalies)
        self._populate_detections(r)
        self._populate_timeline(r.analysis_log)
        self._populate_errors(r.errors)
        self.json_raw.setText(json.dumps(r.to_dict(), indent=2, ensure_ascii=False))
        self._update_graphviz_pixmap()

    def _update_summary(self, r: AnalysisResult):
        self.score_chip.setText(f"Score: {r.suspicion_score:.1f}")
        risk_color = {
            "LOW": "#22c55e",
            "MEDIUM": "#f59e0b",
            "HIGH": "#f97316",
            "CRITICAL": "#ef4444",
        }.get(r.risk_level, "#e2e8f0")
        self.risk_chip.setText(f"Risk: {r.risk_level}")
        self.risk_chip.setStyleSheet(
            f"padding:6px 10px; border-radius:14px; font-weight:700; background:#1f2937; color:{risk_color};"
        )
        self.subtitle.setText(f"Analizat: {Path(r.file_path).name}")

    def _update_file_info(self, r: AnalysisResult):
        size = r.file_hash.get("size", 0)
        vt_ratio = r.vt_report.get("detection_ratio", "-") if r.vt_report else "-"
        lines = [
            f"Fisier: {r.file_path}",
            f"Dimensiune: {self._format_size(size)}",
            f"Durata analiza: {r.analysis_duration:.2f}s",
            f"Packer: {r.packer_detected or '-'}",
            f"Semnatura: {self._signature_status(r)}",
            f"VirusTotal: {vt_ratio}",
            f"Module rulate: {', '.join(r.modules_used) or '-'}",
        ]
        self.file_info.setText("\n".join(lines))

    def _populate_overview(self, r: AnalysisResult):
        vt_ratio = r.vt_report.get("detection_ratio", "-") if r.vt_report else "-"
        info = [
            f"Risk: {r.risk_level} ({r.suspicion_score:.1f}/100)",
            f"Hashes: MD5 {r.file_hash.get('md5', '-')} | SHA256 {r.file_hash.get('sha256', '-')}",
            f"Entropy (avg): {r.entropy_data.get('_average', 0)}",
            f"YARA matches: {len(r.yara_matches)}",
            f"Heuristic flags: {len(r.heuristic_flags)}",
            f"VirusTotal: {vt_ratio}",
        ]
        self.overview.setText("\n".join(info))

    def _populate_findings(self, r: AnalysisResult):
        vt_ratio = r.vt_report.get("detection_ratio", "-") if r.vt_report else "-"
        packer = r.packer_detected or "-"
        signed = r.signatures.get("verified") if r.signatures else False
        signed_txt = "Valid" if signed else ("Unsigned" if r.signatures else "Unknown")
        flags = r.heuristic_flags[:10]
        yara_rules = [m.get("rule", "") for m in r.yara_matches[:10]]
        charts = {}
        try:
            charts = report_generator._chart_images(r)  # base64 imgs
        except Exception:
            charts = {}
        breakdown = r.scoring_breakdown or []
        cards_html = f"""
        <div style="display:flex;gap:12px;flex-wrap:wrap;font-family:'Segoe UI',sans-serif;">
          <div style="flex:1;min-width:200px;background:#0f172a;padding:14px;border-radius:12px;border:1px solid #1f2937;">
            <div style="color:#9ca3af;">Scor</div><div style="font-size:18px;font-weight:bold;">{r.suspicion_score:.1f} ({r.risk_level})</div>
          </div>
          <div style="flex:1;min-width:200px;background:#0f172a;padding:14px;border-radius:12px;border:1px solid #1f2937;">
            <div style="color:#9ca3af;">VirusTotal</div><div style="font-size:18px;font-weight:bold;">{vt_ratio}</div>
          </div>
          <div style="flex:1;min-width:200px;background:#0f172a;padding:14px;border-radius:12px;border:1px solid #1f2937;">
            <div style="color:#9ca3af;">Packer</div><div style="font-size:18px;font-weight:bold;">{packer}</div>
          </div>
          <div style="flex:1;min-width:200px;background:#0f172a;padding:14px;border-radius:12px;border:1px solid #1f2937;">
            <div style="color:#9ca3af;">Semnatura</div><div style="font-size:18px;font-weight:bold;">{signed_txt}</div>
          </div>
        </div>
        """
        charts_html = "<div style='display:flex;gap:16px;flex-wrap:wrap;margin-top:10px;'>"
        if charts.get("entropy"):
            charts_html += f"<div style='flex:1;min-width:300px;'><h4 style='margin:4px 0;'>Entropie</h4><img src='data:image/png;base64,{charts['entropy']}' style='max-width:100%;border:1px solid #1f2937;border-radius:8px;'/></div>"
        vt_stats = r.vt_report.get("stats", {}) if r.vt_report else {}
        if charts.get("vt") and len(vt_stats) <= 6:
            charts_html += f"<div style='flex:0 0 260px;'><h4 style='margin:4px 0;'>VirusTotal</h4><img src='data:image/png;base64,{charts['vt']}' style='max-width:100%;border:1px solid #1f2937;border-radius:8px;'/></div>"
        elif vt_stats:
            charts_html += "<div style='flex:0 0 260px;'><h4 style='margin:4px 0;'>VirusTotal</h4><ul>"
            charts_html += "".join(f"<li>{k}: {v}</li>" for k, v in vt_stats.items())
            charts_html += "</ul></div>"
        charts_html += "</div>"
        breakdown_html = "<h4 style='margin-top:12px;'>Why risk?</h4><ul>" + "".join(f"<li>{b}</li>" for b in breakdown) + "</ul>"
        lists_html = "<h4 style='margin-top:12px;'>Heuristic flags</h4><ul>" + "".join(f"<li>{f}</li>" for f in flags) + "</ul>"
        lists_html += "<h4>YARA</h4><ul>" + "".join(f"<li>{f}</li>" for f in yara_rules) + "</ul>"
        self.findings_view.setHtml(cards_html + charts_html + breakdown_html + lists_html)

    def _populate_hashes(self, hashes: Dict[str, Any]):
        self.hash_table.clear()
        self.hash_table.setColumnCount(2)
        self.hash_table.setHorizontalHeaderLabels(["Tip", "Valoare"])
        rows = [(k.upper(), v) for k, v in hashes.items()]
        self.hash_table.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            self.hash_table.setItem(i, 0, QTableWidgetItem(str(k)))
            self.hash_table.setItem(i, 1, QTableWidgetItem(str(v)))
        self.hash_table.resizeColumnsToContents()
        self.hash_table.horizontalHeader().setStretchLastSection(True)

    def _populate_sections(self, sections: List[Dict[str, Any]]):
        headers = ["Nume", "VA", "V.Size", "Raw Size", "Entropie", "Perms", "Exec/Writable"]
        self.sections.clear()
        self.sections.setColumnCount(len(headers))
        self.sections.setHorizontalHeaderLabels(headers)
        self.sections.setRowCount(len(sections))
        for row, section in enumerate(sections):
            perms = "".join(
                [
                    "R" if section.get("readable") else "-",
                    "W" if section.get("writable") else "-",
                    "X" if section.get("executable") else "-",
                ]
            )
            exec_writable = "DA" if (section.get("executable") and section.get("writable")) else "NU"
            values = [
                section.get("name", ""),
                section.get("virtual_address", ""),
                str(section.get("virtual_size", "")),
                str(section.get("raw_size", "")),
                str(section.get("entropy", "")),
                perms,
                exec_writable,
            ]
            for col, val in enumerate(values):
                self.sections.setItem(row, col, QTableWidgetItem(str(val)))
        self.sections.resizeColumnsToContents()
        self.sections.horizontalHeader().setStretchLastSection(True)

    def _populate_headers(self, info: Dict[str, Any]):
        rows = []
        dos = info.get("dos_header", {})
        pe = info.get("pe_header", {})
        opt = info.get("optional_header", {})
        rows.append(("DOS e_magic", dos.get("e_magic", "")))
        rows.append(("DOS e_lfanew", dos.get("e_lfanew", "")))
        rows.append(("PE machine", pe.get("machine", "")))
        rows.append(("PE sections", pe.get("number_of_sections", "")))
        rows.append(("PE timestamp", pe.get("time_date_stamp", "")))
        rows.append(("Opt entry point", opt.get("entry_point", "")))
        rows.append(("Opt image base", opt.get("image_base", "")))
        rows.append(("Opt subsystem", opt.get("subsystem", "")))
        rows.append(("Opt size of image", opt.get("size_of_image", "")))
        rows.append(("Opt DLL characteristics", opt.get("dll_characteristics", "")))
        self.headers_table.clear()
        self.headers_table.setColumnCount(2)
        self.headers_table.setHorizontalHeaderLabels(["Camp", "Valoare"])
        self.headers_table.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            self.headers_table.setItem(i, 0, QTableWidgetItem(str(k)))
            self.headers_table.setItem(i, 1, QTableWidgetItem(str(v)))
        self.headers_table.resizeColumnsToContents()
        self.headers_table.horizontalHeader().setStretchLastSection(True)

    def _populate_imports(self, imports: List[Dict[str, Any]]):
        self.imports.clear()
        self.imports.setHeaderLabels(["DLL / Functie", "Address"])
        if not imports:
            return
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for imp in imports:
            dll = imp.get("dll", "").lower()
            grouped.setdefault(dll, []).append(imp)
        for dll, funcs in grouped.items():
            dll_item = QTreeWidgetItem([dll, ""])
            for func in funcs:
                fn_item = QTreeWidgetItem(
                    ["  " + func.get("function", ""), func.get("address", "N/A")]
                )
                dll_item.addChild(fn_item)
            self.imports.addTopLevelItem(dll_item)
        self.imports.expandAll()
        self.imports.resizeColumnToContents(0)

    def _populate_exports(self, exports: List[Dict[str, Any]]):
        self.exports.clear()
        self.exports.setColumnCount(3)
        self.exports.setHorizontalHeaderLabels(["Nume", "Adresa", "Ordinal"])
        self.exports.setRowCount(len(exports))
        for i, exp in enumerate(exports):
            self.exports.setItem(i, 0, QTableWidgetItem(str(exp.get("name", ""))))
            self.exports.setItem(i, 1, QTableWidgetItem(str(exp.get("address", ""))))
            self.exports.setItem(i, 2, QTableWidgetItem(str(exp.get("ordinal", ""))))
        self.exports.resizeColumnsToContents()
        self.exports.horizontalHeader().setStretchLastSection(True)

    def _populate_resources(self, resources: List[Dict[str, Any]]):
        headers = ["Tip", "Nume/ID", "Lang", "Sublang", "Detalii"]
        self.resources_table.clear()
        self.resources_table.setColumnCount(len(headers))
        self.resources_table.setHorizontalHeaderLabels(headers)
        self.resources_table.setRowCount(len(resources))
        for i, res in enumerate(resources):
            self.resources_table.setItem(i, 0, QTableWidgetItem(str(res.get("type", ""))))
            self.resources_table.setItem(i, 1, QTableWidgetItem(str(res.get("name", ""))))
            self.resources_table.setItem(i, 2, QTableWidgetItem(str(res.get("lang", ""))))
            self.resources_table.setItem(i, 3, QTableWidgetItem(str(res.get("sublang", ""))))
            if "value" in res:
                detail = res.get("value", "")[:80]
            else:
                detail = f"{res.get('size','')} bytes"
            self.resources_table.setItem(i, 4, QTableWidgetItem(detail))
        self.resources_table.resizeColumnsToContents()
        self.resources_table.horizontalHeader().setStretchLastSection(True)

    def _populate_anomalies(self, anomalies: List[str]):
        self.anomalies_table.clear()
        self.anomalies_table.setColumnCount(1)
        self.anomalies_table.setHorizontalHeaderLabels(["Anomalie"])
        self.anomalies_table.setRowCount(len(anomalies))
        for i, a in enumerate(anomalies):
            self.anomalies_table.setItem(i, 0, QTableWidgetItem(str(a)))
        self.anomalies_table.resizeColumnsToContents()
        self.anomalies_table.horizontalHeader().setStretchLastSection(True)

    def _populate_strings(self, strings: Dict[str, List[str]]):
        rows = []
        for key, items in strings.items():
            for item in items:
                rows.append((key, item))
        self.strings_table.clear()
        self.strings_table.setColumnCount(2)
        self.strings_table.setHorizontalHeaderLabels(["Tip", "Valoare"])
        self.strings_table.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            self.strings_table.setItem(i, 0, QTableWidgetItem(str(k)))
            self.strings_table.setItem(i, 1, QTableWidgetItem(str(v)))
        self.strings_table.resizeColumnsToContents()
        self.strings_table.horizontalHeader().setStretchLastSection(True)

    def _populate_detections(self, r: AnalysisResult):
        lines = []
        if r.yara_matches:
            lines.append(f"YARA matches ({len(r.yara_matches)}):")
            for m in r.yara_matches[:10]:
                lines.append(f" - {m.get('rule')} ({m.get('namespace')})")
        if r.packer_detected:
            lines.append(f"Packer detectat: {r.packer_detected}")
        if r.vt_report:
            lines.append(f"VirusTotal: {r.vt_report.get('detection_ratio', '-')}")
            if link := r.vt_report.get("link"):
                lines.append(f"Link: {link}")
        if r.heuristic_flags:
            lines.append(f"Heuristic flags ({len(r.heuristic_flags)}):")
            for flag in r.heuristic_flags[:20]:
                lines.append(f" - {flag}")
        if not lines:
            lines.append("Nicio detectie raportata.")
        self.detections.setText("\n".join(lines))

    def _populate_disassembly(self, disasm: Any):
        if not disasm:
            self.disassembly_view.setText("Fara disassembly (Capstone poate lipsi).")
            return
        lines = [f"Arch: {disasm.get('arch','-')}", f"Entrypoint: {disasm.get('entrypoint','-')}", ""]
        for func in disasm.get("functions", []):
            lines.append(f"[Func] {func.get('name','')} @ {func.get('address','')}")
            for ins in func.get("instructions", [])[:200]:
                lines.append(f"  {ins.get('address','')}: {ins.get('mnemonic','')} {ins.get('op_str','')}")
            lines.append("")
        for sec in disasm.get("sections", []):
            lines.append(f"[Section] {sec.get('section','')} @ {sec.get('address','')} size={sec.get('size','')}")
            for ins in sec.get("instructions", [])[:200]:
                lines.append(f"  {ins.get('address','')}: {ins.get('mnemonic','')} {ins.get('op_str','')}")
            lines.append("")
        self.disassembly_view.setText("\n".join(lines))

    def _populate_pseudo(self, pseudocode: Any):
        self.func_list.clear()
        if not pseudocode:
            self.pseudo_view.setText("Fara pseudo-decompilare (Capstone poate lipsi).")
            self.cfg_view.setText("")
            return
        for func in pseudocode:
            item = QTreeWidgetItem([func.get("name", ""), func.get("address", "")])
            self.func_list.addTopLevelItem(item)
        # auto-select first
        if self.func_list.topLevelItemCount() > 0:
            self.func_list.setCurrentItem(self.func_list.topLevelItem(0))
            self._on_func_selected()

    def _populate_cfg(self, cfgs: Any):
        # CFG is updated when selecting a function; store for later lookup
        self._cfg_cache = cfgs or []
        if not cfgs:
            self.cfg_view.setText("Fara graf de functii.")
            self.graphviz_label.setText("Fara graf de functii.")
        else:
            self.cfg_view.setText("")

    def _populate_timeline(self, log_entries: List[Dict[str, Any]]):
        if not log_entries:
            self.timeline.setText("Fara log de executie.")
            return
        lines = []
        for entry in log_entries:
            module = entry.get("module", "")
            status = entry.get("status", "")
            detail = entry.get("detail", "")
            line = f"{module}: {status}"
            if detail:
                line += f" ({detail})"
            lines.append(line)
        self.timeline.setText("\n".join(lines))

    def _populate_errors(self, errors: List[str]):
        if not errors:
            self.errors_tab.setText("Fara erori.")
        else:
            self.errors_tab.setText("\n".join(errors))

    def _on_func_selected(self):
        item = self.func_list.currentItem()
        if not item:
            return
        func_name = item.text(0)
        func_addr = item.text(1)
        # find pseudo text
        pseudo_text = ""
        for func in getattr(self, "_current_pseudo", []):
            if func.get("name") == func_name and func.get("address") == func_addr:
                pseudo_text = func.get("source", "")
                break
        self.pseudo_view.setText(pseudo_text or "Fara pseudo pentru functie.")

        # update CFG view
        graph_text = "Fara graf."
        for cfg in getattr(self, "_cfg_cache", []):
            if cfg.get("name") == func_name:
                lines = [f"Function: {func_name}", "Nodes:"]
                for node in cfg.get("nodes", []):
                    lines.append(f"  {node.get('label','')}")
                lines.append("Edges:")
                for edge in cfg.get("edges", []):
                    lines.append(f"  {edge.get('src','')} -> {edge.get('dst','')}")
                graph_text = "\n".join(lines)
                break
        self.cfg_view.setText(graph_text)
        self._render_graphviz(func_name)

    def _render_graphviz(self, func_name: str):
        """Render func graph with graphviz (if available)."""
        try:
            import graphviz  # type: ignore
        except Exception:
            self.graphviz_label.setText("Instaleaza graphviz (pip + binarele Graphviz) pentru vizualizare.")
            return

        target_cfg = None
        for cfg in getattr(self, "_cfg_cache", []):
            if cfg.get("name") == func_name:
                target_cfg = cfg
                break
        if not target_cfg:
            self.graphviz_label.setText("Grafic indisponibil pentru functie.")
            return

        dot = graphviz.Digraph(comment=f"CFG {func_name}", format="png")
        for node in target_cfg.get("nodes", []):
            dot.node(node.get("label", ""), node.get("label", ""))
        for edge in target_cfg.get("edges", []):
            dot.edge(edge.get("src", ""), edge.get("dst", ""))

        try:
            out_dir = Path("temp") / "graphs"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{func_name}_cfg"
            dot.render(out_path, cleanup=True)
            png_path = str(out_path) + ".png"
            if Path(png_path).exists():
                pix = QPixmap(png_path)
                if not pix.isNull():
                    self._graph_pixmap = pix
                    self._update_graphviz_pixmap()
                else:
                    self.graphviz_label.setText("Nu am putut incarca imaginea generata.")
            else:
                self.graphviz_label.setText("FiČ™ier PNG nu a fost generat.")
        except Exception as e:
            self.graphviz_label.setText(f"Eroare graphviz: {e}")

    def _update_graphviz_pixmap(self):
        if not hasattr(self, "_graph_pixmap"):
            return
        vw = self.graphviz_area.viewport().width()
        vh = self.graphviz_area.viewport().height()
        pix = self._graph_pixmap.scaled(max(vw - 20, 200), max(vh - 20, 200), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.graphviz_label.setPixmap(pix)

    def _show_chart_dialog(self):
        if not self.current_result:
            QMessageBox.information(self, "Grafice", "Nu exista analiza curenta.")
            return
        try:
            charts = report_generator._chart_images(self.current_result)
        except Exception as e:
            QMessageBox.warning(self, "Grafice", f"Nu pot genera grafice: {e}")
            return
        if not charts:
            QMessageBox.information(self, "Grafice", "Nu exista grafice disponibile.")
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("Grafice detaliate")
        layout = QVBoxLayout()
        dlg.setLayout(layout)
        for title, img_b64 in charts.items():
            lbl = QLabel(title.capitalize())
            lbl.setFont(QFont("Segoe UI", 11, QFont.Bold))
            layout.addWidget(lbl)
            pix = QPixmap()
            try:
                pix.loadFromData(base64.b64decode(img_b64))
            except Exception:
                continue
            if not pix.isNull():
                view = QLabel()
                view.setPixmap(pix.scaled(900, 600, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                layout.addWidget(view)
        dlg.exec()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_graphviz_pixmap()

    # --- Utils ---
    def _reset_tables(self):
        self.hash_table.setRowCount(0)
        self.sections.setRowCount(0)
        self.headers_table.setRowCount(0)
        self.exports.setRowCount(0)
        self.resources_table.setRowCount(0)
        self.strings_table.setRowCount(0)
        self.disassembly_view.clear()
        self.pseudo_view.clear()
        self.cfg_view.clear()
        self.graphviz_label.setText("Selecteaza o functie pentru a genera CFG")
        self.graphviz_label.setPixmap(QPixmap())
        self.func_list.clear()
        self.imports.clear()
        self.detections.clear()
        self.timeline.clear()
        self.errors_tab.clear()
        self.overview.clear()
        self.json_raw.clear()

    def _format_size(self, size: int) -> str:
        if size <= 0:
            return "-"
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _signature_status(self, r: AnalysisResult) -> str:
        if not r.signatures:
            return "-"
        if r.signatures.get("signed") is False:
            return "Unsigned"
        if r.signatures.get("verified"):
            return "Valid"
        return "Invalid/Unknown"

    # --- Drag & drop ---
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        urls = e.mimeData().urls()
        if urls:
            f = urls[0].toLocalFile()
            if Path(f).is_file():
                self.current_file = f
                self.file_info.setText(f"Fisier selectat:\n{f}")
                self.btn_analyze.setEnabled(True)
                self.subtitle.setText("Apasa Analizeaza pentru a incepe")


def main():
    app = QApplication(sys.argv)
    # Splash screen pentru pornire mai smooth
    splash = QSplashScreen(QPixmap(), Qt.WindowStaysOnTopHint)
    splash.showMessage("PE Static Analyzer se incarca...", Qt.AlignCenter | Qt.AlignBottom, Qt.white)
    splash.show()
    app.processEvents()

    w = PEAnalyzerGUI()
    w.show()
    splash.finish(w)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

