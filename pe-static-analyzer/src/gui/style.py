BASE_QSS = """
QMainWindow { background-color: #0b1021; color: #e2e8f0; }
QLabel { color: #e2e8f0; }
QTextEdit, QTableWidget, QTreeWidget { background: #0c142a; color: #e2e8f0; border: 1px solid #1f2937; }
QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #7c3aed); color: #f8fafc; padding: 8px 14px; border-radius: 8px; font-weight: 600; }
QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1d4ed8, stop:1 #6d28d9); transform: scale(1.01); }
QPushButton:pressed { background: #0f172a; border: 1px solid #1d4ed8; }
QPushButton:disabled { background: #334155; color: #cbd5e1; }
QTabWidget::pane { border: 1px solid #1f2937; }
QTabBar::tab { padding: 8px 12px; background: #111827; color: #e2e8f0; border: 1px solid #1f2937; border-bottom: none; }
QTabBar::tab:selected { background: #1f2937; }
QTabBar::tab:hover { background: #162035; }
QHeaderView::section { background: #1f2937; color: #e2e8f0; border: none; padding: 4px; }
QProgressBar { background: #1f2937; color: #e2e8f0; border: 1px solid #1f2937; }
QProgressBar::chunk { background: #22c55e; }
#ChipPrimary, #ChipNeutral, #ChipSecondary { padding: 6px 10px; border-radius: 14px; font-weight: 700; }
#ChipPrimary { background: #172554; color: #a5b4fc; }
#ChipSecondary { background: #0b3d2c; color: #6ee7b7; }
#ChipNeutral { background: #1f2937; color: #e2e8f0; }
QTextEdit#PseudoView, QTextEdit#CfgView { font-family: Consolas, monospace; font-size: 12px; }
QTextEdit { selection-background-color: #1d4ed8; }
QScrollBar:vertical { background: #0c142a; width: 10px; }
QScrollBar::handle:vertical { background: #334155; border-radius: 4px; }
QScrollBar::handle:vertical:hover { background: #475569; }
QTreeWidget { border: 1px solid #1f2937; }
QTreeWidget::item:selected { background: #1d4ed8; color: #f8fafc; }
QMessageBox { background: #0b1021; color: #e2e8f0; }
QMessageBox QLabel { color: #e2e8f0; }
QMessageBox QPushButton { background: #2563eb; color: #f8fafc; border-radius: 6px; padding: 6px 12px; }
QMessageBox QPushButton:hover { background: #1d4ed8; }
QDialog { background: #0b1021; color: #e2e8f0; }
"""
