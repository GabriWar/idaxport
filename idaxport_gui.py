#!/usr/bin/env python3
"""Standalone GUI for idaxport - launches IDA headless and monitors progress."""

import sys
import os
import subprocess
import threading
import time
import signal
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QPlainTextEdit,
    QProgressBar, QCheckBox, QGroupBox, QGridLayout, QComboBox,
    QMessageBox, QSplitter
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor, QPalette, QTextCharFormat

# Default IDA path - adjust as needed
DEFAULT_IDA_PATH = os.path.expanduser("~/idapro/idat")

EXPORT_TASKS = [
    ("Binary Info", True),
    ("Strings", True),
    ("String Xrefs", True),
    ("Imports", True),
    ("Imports (grouped)", True),
    ("Exports", True),
    ("Entry Points", True),
    ("Segment Metadata", True),
    ("Loaded TILs", True),
    ("Structs/Enums/Typedefs", True),
    ("Function Prototypes", True),
    ("Comments & Labels", True),
    ("Cross-References", True),
    ("Call Graph", True),
    ("Data Xref Graph", True),
    ("Vtables", True),
    ("Patches", True),
    ("Pointers", True),
    ("Global Variables", True),
    ("Bookmarks", True),
    ("Stack Frames", True),
    ("Function Chunks", True),
    ("FLIRT Matches", True),
    ("Enum Usage", True),
    ("Switch Tables", True),
    ("Exceptions/SEH", True),
    ("Fixups/Relocations", True),
    ("Operand Info", True),
    ("ObjC Metadata", False),
    ("Debug Info", True),
    ("Color Markings", True),
    ("Applied Structs", True),
    ("Undefined Ranges", True),
    ("Hidden Ranges", True),
    ("Analysis Problems", True),
    ("Disassembly (ASM)", True),
    ("Memory Dump", True),
    ("Decompiled Functions", True),
    ("Microcode/Ctree", True),
]


class LogSignals(QObject):
    """Signals for thread-safe log updates."""
    append_text = pyqtSignal(str)
    export_finished = pyqtSignal(int)
    progress_update = pyqtSignal(int, int)  # current, total


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("idaxport - IDA Export for AI")
        self.setMinimumSize(900, 750)
        self.process = None
        self.log_signals = LogSignals()
        self.log_signals.append_text.connect(self._append_log)
        self.log_signals.export_finished.connect(self._on_finished)
        self.log_signals.progress_update.connect(self._on_progress)
        self._task_count = 0
        self._task_current = 0
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(8)

        # --- IDA path ---
        ida_group = QGroupBox("IDA Headless")
        ida_layout = QHBoxLayout(ida_group)
        ida_layout.addWidget(QLabel("idat path:"))
        self.ida_edit = QLineEdit(DEFAULT_IDA_PATH)
        self.ida_browse = QPushButton("Browse...")
        self.ida_browse.clicked.connect(self._browse_ida)
        ida_layout.addWidget(self.ida_edit, 1)
        ida_layout.addWidget(self.ida_browse)
        layout.addWidget(ida_group)

        # --- Input / Output ---
        io_group = QGroupBox("Input / Output")
        io_layout = QGridLayout(io_group)

        io_layout.addWidget(QLabel("Binary:"), 0, 0)
        self.binary_edit = QLineEdit()
        self.binary_edit.setPlaceholderText("Path to binary file to analyze...")
        self.binary_browse = QPushButton("Browse...")
        self.binary_browse.clicked.connect(self._browse_binary)
        io_layout.addWidget(self.binary_edit, 0, 1)
        io_layout.addWidget(self.binary_browse, 0, 2)

        io_layout.addWidget(QLabel("Output:"), 1, 0)
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Export directory (auto-filled from binary path)...")
        self.output_browse = QPushButton("Browse...")
        self.output_browse.clicked.connect(self._browse_output)
        io_layout.addWidget(self.output_edit, 1, 1)
        io_layout.addWidget(self.output_browse, 1, 2)

        layout.addWidget(io_group)

        # --- Export Tasks checkboxes ---
        tasks_group = QGroupBox("Export Tasks")
        tasks_layout = QVBoxLayout(tasks_group)

        # Select All / Deselect All
        btn_row = QHBoxLayout()
        sel_all = QPushButton("Select All")
        sel_all.setStyleSheet("padding: 3px 12px;")
        sel_all.clicked.connect(lambda: self._set_all_checks(True))
        desel_all = QPushButton("Deselect All")
        desel_all.setStyleSheet("padding: 3px 12px;")
        desel_all.clicked.connect(lambda: self._set_all_checks(False))
        btn_row.addWidget(sel_all)
        btn_row.addWidget(desel_all)
        btn_row.addStretch()
        tasks_layout.addLayout(btn_row)

        # Checkbox grid
        grid = QGridLayout()
        grid.setSpacing(2)
        self.task_checkboxes = {}
        cols = 4
        for idx, (name, default_on) in enumerate(EXPORT_TASKS):
            cb = QCheckBox(name)
            cb.setChecked(default_on)
            self.task_checkboxes[name] = cb
            grid.addWidget(cb, idx // cols, idx % cols)
        tasks_layout.addLayout(grid)
        layout.addWidget(tasks_group)

        # --- Progress ---
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        progress_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v / %m tasks")
        progress_layout.addWidget(self.progress_bar)

        layout.addWidget(progress_group)

        # --- Log ---
        log_group = QGroupBox("Log Output")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumBlockCount(10000)
        font = QFont("Monospace", 9)
        font.setStyleHint(QFont.TypeWriter)
        self.log_text.setFont(font)
        log_layout.addWidget(self.log_text)
        layout.addWidget(log_group, 1)  # stretch

        # --- Buttons ---
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.start_btn = QPushButton("  Start Export  ")
        self.start_btn.setStyleSheet(
            "QPushButton { background-color: #2d7d46; color: white; font-weight: bold; "
            "padding: 8px 24px; border-radius: 4px; font-size: 13px; }"
            "QPushButton:hover { background-color: #359952; }"
            "QPushButton:disabled { background-color: #555; color: #999; }"
        )
        self.start_btn.clicked.connect(self._on_start)

        self.cancel_btn = QPushButton("  Cancel  ")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setStyleSheet(
            "QPushButton { background-color: #8b2d2d; color: white; font-weight: bold; "
            "padding: 8px 24px; border-radius: 4px; font-size: 13px; }"
            "QPushButton:hover { background-color: #a33; }"
            "QPushButton:disabled { background-color: #555; color: #999; }"
        )
        self.cancel_btn.clicked.connect(self._on_cancel)

        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

    def _set_all_checks(self, state):
        for cb in self.task_checkboxes.values():
            cb.setChecked(state)

    # --- Browse dialogs ---

    def _browse_ida(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select idat binary", os.path.dirname(self.ida_edit.text()))
        if f:
            self.ida_edit.setText(f)

    def _browse_binary(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select binary to analyze", os.path.expanduser("~"))
        if f:
            self.binary_edit.setText(f)
            # Auto-fill output dir
            base = os.path.splitext(f)[0]
            self.output_edit.setText(base + "-export")

    def _browse_output(self):
        d = QFileDialog.getExistingDirectory(self, "Select output directory", self.output_edit.text())
        if d:
            self.output_edit.setText(d)

    # --- Export ---

    def _on_start(self):
        ida_path = self.ida_edit.text().strip()
        binary_path = self.binary_edit.text().strip()
        output_path = self.output_edit.text().strip()

        if not ida_path or not os.path.isfile(ida_path):
            QMessageBox.warning(self, "Error", "idat binary not found: {}".format(ida_path))
            return
        if not binary_path or not os.path.isfile(binary_path):
            QMessageBox.warning(self, "Error", "Binary file not found: {}".format(binary_path))
            return
        if not output_path:
            QMessageBox.warning(self, "Error", "Please specify an output directory.")
            return

        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.log_text.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(EXPORT_TASKS))
        self.progress_bar.setFormat("%v / %m tasks")
        self.status_label.setText("Starting IDA headless...")
        self._task_current = 0

        # Get the script path (INP.py in same directory as this script)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(script_dir, "INP.py")

        if not os.path.isfile(script_path):
            QMessageBox.warning(self, "Error", "INP.py not found at: {}".format(script_path))
            self.start_btn.setEnabled(True)
            self.cancel_btn.setEnabled(False)
            return

        self._append_log("[*] IDA: {}".format(ida_path))
        self._append_log("[*] Binary: {}".format(binary_path))
        self._append_log("[*] Output: {}".format(output_path))
        self._append_log("[*] Script: {}".format(script_path))
        self._append_log("")

        # Write skip file for unchecked tasks
        skipped = [name for name, cb in self.task_checkboxes.items() if not cb.isChecked()]
        skip_file = output_path + ".skip"
        if skipped:
            os.makedirs(os.path.dirname(skip_file) if os.path.dirname(skip_file) else ".", exist_ok=True)
            with open(skip_file, 'w') as f:
                for name in skipped:
                    f.write(name + "\n")
            self._append_log("[*] Skipping {} tasks: {}".format(len(skipped), ", ".join(skipped)))
        elif os.path.exists(skip_file):
            os.remove(skip_file)

        enabled_count = len(EXPORT_TASKS) - len(skipped)
        self._append_log("[*] Running {} export tasks".format(enabled_count))
        self._append_log("")

        # Build command
        log_file = output_path + ".ida.log"
        cmd = [
            ida_path,
            "-A",
            "-L{}".format(log_file),
            '-S{} {}'.format(script_path, output_path),
            binary_path
        ]

        self._append_log("[*] Running: {}".format(" ".join(cmd)))
        self._append_log("")

        # Launch in background thread
        self._log_file = log_file
        self._thread = threading.Thread(target=self._run_export, args=(cmd, log_file), daemon=True)
        self._thread.start()

        # Start log tail timer
        self._log_pos = 0
        self._timer = QTimer()
        self._timer.timeout.connect(self._tail_log)
        self._timer.start(200)

    def _run_export(self, cmd, log_file):
        """Run IDA headless in a background thread."""
        try:
            env = os.environ.copy()
            env["IDAUSR"] = os.path.expanduser("~/.idapro")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                preexec_fn=os.setsid
            )
            returncode = self.process.wait()
            self.process = None
            self.log_signals.export_finished.emit(returncode)
        except Exception as e:
            self.log_signals.append_text.emit("[!] Error: {}".format(str(e)))
            self.log_signals.export_finished.emit(-1)

    def _tail_log(self):
        """Read new lines from the IDA log file."""
        if not hasattr(self, '_log_file'):
            return
        try:
            if not os.path.exists(self._log_file):
                return
            with open(self._log_file, 'r', errors='replace') as f:
                f.seek(self._log_pos)
                new_data = f.read()
                self._log_pos = f.tell()

            if new_data:
                for line in new_data.splitlines():
                    line = line.rstrip()
                    if not line:
                        continue

                    # Parse progress from log lines
                    if line.startswith("[*] ["):
                        try:
                            # e.g. "[*] [5/39] Exporting Strings..."
                            bracket = line.split("]")[0] + "]"
                            nums = bracket.replace("[*] [", "").replace("]", "")
                            current, total = nums.split("/")
                            self._task_current = int(current)
                            self._task_count = int(total)
                            self.log_signals.progress_update.emit(int(current), int(total))
                        except:
                            pass

                    self.log_signals.append_text.emit(line)

        except Exception:
            pass

    def _on_progress(self, current, total):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.status_label.setText("Exporting... ({}/{})".format(current, total))

    def _append_log(self, text):
        self.log_text.appendPlainText(text)
        # Auto-scroll
        sb = self.log_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_finished(self, returncode):
        if hasattr(self, '_timer'):
            self._timer.stop()
            # Final tail to catch remaining lines
            self._tail_log()

        if returncode == 0:
            self.status_label.setText("Export completed!")
            self.status_label.setStyleSheet("font-weight: bold; font-size: 13px; color: #4caf50;")
            self.progress_bar.setValue(self.progress_bar.maximum())
            self._append_log("")
            self._append_log("=" * 60)
            self._append_log("[+] Export completed successfully!")
            output = self.output_edit.text().strip()
            if os.path.isdir(output):
                files = os.listdir(output)
                self._append_log("[+] {} files/dirs in output".format(len(files)))
        elif returncode == -999:
            self.status_label.setText("Cancelled")
            self.status_label.setStyleSheet("font-weight: bold; font-size: 13px; color: #ff9800;")
            self._append_log("[!] Export cancelled by user")
        else:
            self.status_label.setText("Export failed (exit code {})".format(returncode))
            self.status_label.setStyleSheet("font-weight: bold; font-size: 13px; color: #f44336;")
            self._append_log("[!] IDA exited with code {}".format(returncode))

        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

    def _on_cancel(self):
        if self.process:
            self._append_log("[!] Killing IDA process...")
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except:
                try:
                    self.process.kill()
                except:
                    pass
            self.log_signals.export_finished.emit(-999)

    def closeEvent(self, event):
        if self.process:
            reply = QMessageBox.question(
                self, "Export Running",
                "An export is still running. Kill it and exit?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
            self._on_cancel()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Dark theme
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(30, 30, 30))
    palette.setColor(QPalette.WindowText, QColor(220, 220, 220))
    palette.setColor(QPalette.Base, QColor(20, 20, 20))
    palette.setColor(QPalette.AlternateBase, QColor(40, 40, 40))
    palette.setColor(QPalette.ToolTipBase, QColor(220, 220, 220))
    palette.setColor(QPalette.ToolTipText, QColor(220, 220, 220))
    palette.setColor(QPalette.Text, QColor(220, 220, 220))
    palette.setColor(QPalette.Button, QColor(45, 45, 45))
    palette.setColor(QPalette.ButtonText, QColor(220, 220, 220))
    palette.setColor(QPalette.BrightText, QColor(255, 50, 50))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(128, 128, 128))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(128, 128, 128))
    app.setPalette(palette)

    app.setStyleSheet("""
        QGroupBox {
            border: 1px solid #555;
            border-radius: 4px;
            margin-top: 8px;
            padding-top: 12px;
            font-weight: bold;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 4px;
        }
        QLineEdit {
            padding: 4px 8px;
            border: 1px solid #555;
            border-radius: 3px;
            background: #252525;
        }
        QProgressBar {
            border: 1px solid #555;
            border-radius: 3px;
            text-align: center;
            height: 22px;
        }
        QProgressBar::chunk {
            background-color: #2a82da;
            border-radius: 2px;
        }
        QPlainTextEdit {
            border: 1px solid #555;
            border-radius: 3px;
            background: #1a1a1a;
        }
    """)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
