from __future__ import annotations

import os
import time
from typing import Dict, Optional

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

try:
    from .uploader import ScanJob, Uploader
except ImportError:  # pragma: no cover - fallback for running as script
    from uploader import ScanJob, Uploader

try:
    from .ws_client import WSClient
except ImportError:  # pragma: no cover - fallback for running as script
    from ws_client import WSClient


class AppWindow(QMainWindow):
    def __init__(self, uploader: Optional[Uploader] = None, ws_client: Optional[WSClient] = None) -> None:
        super().__init__()
        self.uploader = uploader or Uploader()
        self.ws_client = ws_client or WSClient()

        self.setWindowTitle("Sentinel MalScan")
        self.resize(1200, 720)
        self._icons_dir = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "resources", "icons")
        )
        self._logo_path = os.path.join(self._icons_dir, "Sentinel.png")

        self.mode_buttons: list[QPushButton] = []
        self._system_scanning = False
        self._pending_system_job: Optional[ScanJob] = None
        self._loading_timer = QTimer(self)
        self._loading_timer.timeout.connect(self._update_loading_animation)
        self._loading_label = ""
        self._loading_phase = 0

        self._set_window_icon()
        self._build_ui()
        self._apply_styles()
        self.ws_client.register_callback(self._handle_ws_message)
        self._switch_mode(0)

    def _build_ui(self) -> None:
        container = QWidget()
        outer_layout = QVBoxLayout(container)
        outer_layout.setSpacing(16)
        outer_layout.setContentsMargins(18, 18, 18, 18)

        self.top_bar = self._build_top_bar()
        outer_layout.addWidget(self.top_bar)

        content_panel = QWidget()
        content_layout = QHBoxLayout(content_panel)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(18)

        self.mode_stack = QStackedWidget()
        self.mode_stack.addWidget(self._build_file_tab())
        self.mode_stack.addWidget(self._build_folder_tab())
        self.mode_stack.addWidget(self._build_system_tab())
        content_layout.addWidget(self.mode_stack, stretch=5)

        self.result_box = self._build_result_box()
        content_layout.addWidget(self.result_box, stretch=4)

        outer_layout.addWidget(content_panel, stretch=1)

        self.log_box = self._build_log_box()
        outer_layout.addWidget(self.log_box)

        container.setLayout(outer_layout)
        self.setCentralWidget(container)

    def _build_top_bar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("TopBar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(14)

        self.mode_buttons = []

        self.logo_label = QLabel()
        self.logo_label.setObjectName("LogoImage")
        self.logo_label.setFixedSize(44, 44)
        self.logo_label.setAlignment(Qt.AlignCenter)
        logo_pix = self._load_logo_pixmap(size=44)
        if logo_pix:
            self.logo_label.setPixmap(logo_pix)
        else:
            self.logo_label.setText("Sentinel")
            self.logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.logo_label)

        self.logo_title = QLabel("Sentinel MalScan")
        self.logo_title.setObjectName("LogoTitle")
        layout.addWidget(self.logo_title)

        layout.addStretch()

        self.file_mode_btn = self._create_mode_button("Quét tệp", 0)
        self.folder_mode_btn = self._create_mode_button("Quét thư mục", 1)
        self.system_mode_btn = self._create_mode_button("Quét hệ thống", 2)
        layout.addWidget(self.file_mode_btn)
        layout.addWidget(self.folder_mode_btn)
        layout.addWidget(self.system_mode_btn)

        return bar

    def _create_mode_button(self, text: str, index: int) -> QPushButton:
        button = QPushButton(text)
        button.setCheckable(True)
        button.setObjectName("ModeButton")
        button.clicked.connect(lambda _: self._switch_mode(index))
        self.mode_buttons.append(button)
        return button

    def _switch_mode(self, index: int) -> None:
        if hasattr(self, "mode_stack"):
            self.mode_stack.setCurrentIndex(index)
        for i, button in enumerate(getattr(self, "mode_buttons", [])):
            button.blockSignals(True)
            button.setChecked(i == index)
            button.blockSignals(False)

    def _load_logo_pixmap(self, size: int = 40) -> Optional[QPixmap]:
        if not os.path.exists(self._logo_path):
            return None
        pixmap = QPixmap(self._logo_path)
        if pixmap.isNull():
            return None
        return pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)

    def _set_window_icon(self) -> None:
        pixmap = self._load_logo_pixmap(size=128)
        if pixmap:
            self.setWindowIcon(QIcon(pixmap))

    def _build_file_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)

        intro = QLabel("Chế độ quét tệp giúp bạn tải lên và phân tích từng tệp cụ thể.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.file_mode_tabs = QTabWidget()
        self.file_mode_tabs.setObjectName("FileModeTabs")

        file_tab = QWidget()
        file_layout = QVBoxLayout(file_tab)
        file_layout.setSpacing(14)
        file_layout.setContentsMargins(0, 0, 0, 0)

        file_box = QGroupBox("Quét tệp trực tiếp")
        file_box.setObjectName("FileBox")
        file_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        file_box_layout = QVBoxLayout(file_box)
        file_box_layout.setSpacing(14)
        file_box_layout.setContentsMargins(20, 20, 20, 24)

        file_path_row = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Chưa chọn tệp nào")
        self.file_path_input.setReadOnly(True)

        self.file_browse_btn = QPushButton("Chọn tệp…")
        self.file_browse_btn.clicked.connect(self._choose_file)

        file_path_row.addWidget(self.file_path_input, stretch=1)
        file_path_row.addWidget(self.file_browse_btn)
        file_box_layout.addLayout(file_path_row)

        options_column = QVBoxLayout()
        options_column.setSpacing(10)
        self.file_opt_yara = QCheckBox("Áp dụng bộ quy tắc YARA")
        self.file_opt_capa = QCheckBox("Phân tích chức năng với capa")
        self.file_opt_strings = QCheckBox("Trích xuất chuỗi với FLOSS")
        self.file_opt_pestudio = QCheckBox("Phân tích tĩnh với PEStudio")
        options_column.addWidget(self.file_opt_yara)
        options_column.addWidget(self.file_opt_capa)
        options_column.addWidget(self.file_opt_strings)
        options_column.addWidget(self.file_opt_pestudio)
        file_box_layout.addLayout(options_column)
        file_box_layout.addStretch(1)

        file_layout.addWidget(file_box)

        hash_tab = QWidget()
        hash_layout = QVBoxLayout(hash_tab)
        hash_layout.setSpacing(14)
        hash_layout.setContentsMargins(0, 0, 0, 0)

        hash_box = QGroupBox("Quét bằng mã băm")
        hash_box.setObjectName("HashBox")
        hash_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        hash_box_layout = QVBoxLayout(hash_box)
        hash_box_layout.setSpacing(14)
        hash_box_layout.setContentsMargins(20, 20, 20, 24)

        hash_desc = QLabel("Nhập SHA256 hoặc MD5 để truy vấn nhanh trong cơ sở dữ liệu mẫu.")
        hash_desc.setWordWrap(True)
        hash_box_layout.addWidget(hash_desc)

        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Ví dụ: 44d88612fea8a8f36de82e1278abb02f")
        hash_box_layout.addWidget(self.hash_input)

        hash_options_grid = QGridLayout()
        hash_options_grid.setHorizontalSpacing(24)
        hash_options_grid.setVerticalSpacing(8)
        self.hash_opt_yara = QCheckBox("Áp dụng bộ quy tắc YARA")
        self.hash_opt_capa = QCheckBox("Phân tích chức năng với capa")
        self.hash_opt_strings = QCheckBox("Trích xuất chuỗi với FLOSS")
        self.hash_opt_pestudio = QCheckBox("Phân tích tĩnh với PEStudio")
        hash_options_grid.addWidget(self.hash_opt_yara, 0, 0)
        hash_options_grid.addWidget(self.hash_opt_capa, 0, 1)
        hash_options_grid.addWidget(self.hash_opt_strings, 1, 0)
        hash_options_grid.addWidget(self.hash_opt_pestudio, 1, 1)
        hash_box_layout.addLayout(hash_options_grid)

        hash_box_layout.addStretch(1)

        hash_layout.addWidget(hash_box)

        self.file_mode_tabs.addTab(file_tab, "File scan")
        self.file_mode_tabs.addTab(hash_tab, "Hash scan")

        layout.addWidget(self.file_mode_tabs, stretch=1)
        layout.addStretch(1)

        action_row = QHBoxLayout()
        action_row.addStretch(1)
        self.file_scan_btn = QPushButton("Bắt đầu quét")
        self.file_scan_btn.clicked.connect(self._start_file_scan)
        action_row.addWidget(self.file_scan_btn)
        layout.addLayout(action_row)
        self.file_mode_tabs.currentChanged.connect(self._on_file_mode_changed)
        self._on_file_mode_changed(self.file_mode_tabs.currentIndex())
        return tab

    def _build_folder_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)

        intro = QLabel("Chế độ quét thư mục giúp rà soát một thư mục hoặc ổ đĩa cụ thể.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        path_row = QHBoxLayout()
        self.folder_root_input = QLineEdit()
        self.folder_root_input.setPlaceholderText("Chọn thư mục hoặc ổ đĩa bắt đầu quét")
        self.folder_root_input.setReadOnly(True)
        browse_btn = QPushButton("Chọn thư mục…")
        browse_btn.clicked.connect(self._choose_folder)
        path_row.addWidget(self.folder_root_input)
        path_row.addWidget(browse_btn)
        layout.addLayout(path_row)

        options_box = QGroupBox("Tùy chọn quét")
        options_box.setObjectName("FolderBox")
        options_layout = QVBoxLayout(options_box)
        options_layout.setContentsMargins(20, 16, 20, 18)
        options_layout.setSpacing(10)
        self.folder_opt_quick = QCheckBox("Quét nhanh (bỏ qua tệp lớn hơn 100MB)")
        self.folder_opt_hidden = QCheckBox("Bao gồm tệp ẩn")
        self.folder_opt_hash = QCheckBox("Tính hash SHA256")

        options_layout.addWidget(self.folder_opt_quick)
        options_layout.addWidget(self.folder_opt_hidden)
        options_layout.addWidget(self.folder_opt_hash)
        options_layout.addStretch(1)
        layout.addWidget(options_box, stretch=1)

        action_row = QHBoxLayout()
        self.folder_scan_btn = QPushButton("Quét thư mục")
        self.folder_scan_btn.clicked.connect(self._start_folder_scan)
        action_row.addStretch()
        action_row.addWidget(self.folder_scan_btn)
        layout.addLayout(action_row)

        layout.addStretch()
        return tab

    def _build_system_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(24)
        layout.setContentsMargins(40, 40, 40, 40)

        description = QLabel(
            "Chế độ quét hệ thống sẽ rà soát toàn bộ máy tính và phát hiện các tệp khả nghi."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignCenter)
        layout.addWidget(description, alignment=Qt.AlignCenter)

        self.system_scan_btn = QPushButton("Quét toàn hệ thống")
        self.system_scan_btn.setObjectName("SystemScanButton")
        self.system_scan_btn.setFixedSize(320, 120)
        self.system_scan_btn.clicked.connect(self._start_system_scan)
        layout.addWidget(self.system_scan_btn, alignment=Qt.AlignCenter)

        self.system_progress = QProgressBar()
        self.system_progress.setObjectName("SystemProgress")
        self.system_progress.setRange(0, 0)
        self.system_progress.setVisible(False)
        self.system_progress.setFixedWidth(360)
        layout.addWidget(self.system_progress, alignment=Qt.AlignCenter)

        self.system_status_label = QLabel("Hệ thống đang an toàn.")
        self.system_status_label.setObjectName("SystemStatus")
        self.system_status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.system_status_label, alignment=Qt.AlignCenter)

        layout.addStretch()
        return tab

    def _build_result_box(self) -> QGroupBox:
        box = QGroupBox("Kết quả quét")
        box.setObjectName("ResultBox")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(16, 12, 16, 16)
        layout.setSpacing(12)

        self.result_output = QPlainTextEdit()
        self.result_output.setReadOnly(True)
        self.result_output.setPlaceholderText("Kết quả mới nhất sẽ hiển thị tại đây…")
        layout.addWidget(self.result_output)
        return box

    def _build_log_box(self) -> QGroupBox:
        box = QGroupBox("Nhật ký & lịch sử quét")
        box.setObjectName("LogBox")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(16, 12, 16, 16)
        layout.setSpacing(8)

        self.activity_log = QPlainTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setPlaceholderText("Sự kiện và lịch sử quét sẽ xuất hiện tại đây…")
        self.activity_log.setFixedHeight(160)
        layout.addWidget(self.activity_log)
        return box

    def _on_file_mode_changed(self, index: int) -> None:
        if index == 0:
            self.file_scan_btn.setText("Bắt đầu quét")
            if hasattr(self, "file_path_input"):
                self.file_path_input.setFocus()
        else:
            self.file_scan_btn.setText("Quét hash")
            if hasattr(self, "hash_input"):
                self.hash_input.setFocus()

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QWidget {
                background-color: #1e1f2e;
                color: #f1f2f8;
                font-family: "Segoe UI", "Tahoma", sans-serif;
                font-size: 11pt;
            }
            #TopBar {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                             stop:0 #1c1d2b, stop:1 #252741);
                border: 1px solid #2f314b;
                border-radius: 14px;
                padding: 6px 12px;
            }
            #TopBar QLabel {
                color: #dfe2fb;
            }
            #LogoTitle {
                font-size: 15pt;
                font-weight: 600;
                letter-spacing: 0.6px;
            }
            #LogoImage {
                border: 1px solid #2d2f46;
                border-radius: 12px;
                background: #131424;
            }
            QGroupBox {
                border: none;
                border-radius: 20px;
                margin-top: 18px;
                background: transparent;
            }
            #FileBox,
            #HashBox,
            #FolderBox {
                background: #232437;
                border-radius: 20px;
                border: none;
            }
            #FileModeTabs::pane {
                border: 1px solid #2f314b;
                border-radius: 16px;
                padding: 12px;
                background: #1e1f30;
            }
            #FileModeTabs QTabBar::tab {
                background: transparent;
                color: #c7cbf5;
                padding: 10px 24px;
                border: 1px solid transparent;
                margin-right: 6px;
                border-radius: 18px;
                font-weight: 500;
            }
            #FileModeTabs QTabBar::tab:hover {
                border-color: #4f58d6;
            }
            #FileModeTabs QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                             stop:0 #5560ff, stop:1 #3c46c5);
                color: white;
                border: none;
            }
            #ResultBox {
                background: #1b1c2c;
                border: 1px solid #343553;
                border-radius: 16px;
            }
            #LogBox {
                background: #191a29;
                border: 1px solid #343553;
                border-radius: 16px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 18px;
                padding: 0 10px 10px 10px;
                color: #8fa2ff;
                font-weight: bold;
                font-size: 12pt;
            }
            QLabel {
                color: #c8cae2;
            }
            QLineEdit {
                background: #1b1c29;
                color: #f1f2fa;
                border: 1px solid #3e4164;
                border-radius: 8px;
                padding: 10px 12px;
                font-size: 11.5pt;
            }
            QLineEdit:disabled {
                color: #7f80a0;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                             stop:0 #4b5fe0, stop:1 #3849b5);
                border: none;
                border-radius: 8px;
                color: white;
                padding: 10px 20px;
                font-weight: 600;
                letter-spacing: 0.3px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                             stop:0 #6374ff, stop:1 #4b5fe0);
            }
            QPushButton:pressed {
                background: #2e3aa4;
            }
            QPushButton#ModeButton {
                background: transparent;
                border: 1px solid #3a3b5a;
                border-radius: 18px;
                color: #c8cae2;
                padding: 8px 24px;
                font-weight: 500;
            }
            QPushButton#ModeButton:hover {
                border-color: #5560ff;
                color: #f1f2ff;
            }
            QPushButton#ModeButton:checked {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                             stop:0 #5560ff, stop:1 #3c46c5);
                border: none;
                color: white;
            }
            QPushButton#ModeButton:pressed {
                background: #313bb1;
            }
            QPushButton#SystemScanButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                             stop:0 #5c69ff, stop:1 #4250d4);
                font-size: 14pt;
                font-weight: 600;
                letter-spacing: 0.6px;
            }
            QPushButton#SystemScanButton:disabled {
                background: #2d2e4e;
                color: #9799bf;
            }
            QCheckBox {
                padding: 6px 0;
                font-size: 11.5pt;
            }
            QPlainTextEdit {
                background: #10111d;
                border: 1px solid #343553;
                border-radius: 8px;
                padding: 10px;
                color: #e7e8f8;
            }
            QProgressBar {
                background: #141523;
                border: 1px solid #343553;
                border-radius: 8px;
                height: 18px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                             stop:0 #4b5fe0, stop:1 #7183ff);
                border-radius: 8px;
            }
            #SystemStatus {
                color: #8fa2ff;
                font-size: 11.5pt;
            }
            QScrollBar:vertical {
                background: #141523;
                width: 12px;
                margin: 12px 0 12px 0;
                border: 1px solid #141523;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: #3c3f60;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background: #4b5fe0;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0;
            }
            """
        )

    def _choose_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Chọn tệp để quét")
        if file_path:
            self.file_path_input.setText(file_path)

    def _choose_folder(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Chọn thư mục để quét")
        if directory:
            self.folder_root_input.setText(directory)

    def _start_file_scan(self) -> None:
        if hasattr(self, "file_mode_tabs") and self.file_mode_tabs.currentIndex() == 1:
            self._start_hash_scan(self.hash_input.text())
            return

        value = self.file_path_input.text().strip()
        if not value:
            self._warn("Vui lòng chọn tệp trước khi quét.")
            return

        options = {}
        if self.file_opt_yara.isChecked():
            options["yara"] = "true"
        if self.file_opt_capa.isChecked():
            options["capa"] = "true"
        if self.file_opt_strings.isChecked():
            options["floss"] = "true"
        if self.file_opt_pestudio.isChecked():
            options["pestudio"] = "true"

        job = self.uploader.upload_file(value, options)
        filename = os.path.basename(value)
        self._start_loading_animation(f"Đang quét tệp {filename}")
        self._append_activity(f"[{job.job_id}] Khởi chạy quét tệp: {filename}")
        if options:
            self._append_activity(f"Tùy chọn: {self._format_option_labels(options)}")
        QTimer.singleShot(450, lambda j=job: self._show_result(j))

    def _start_folder_scan(self) -> None:
        root_path = self.folder_root_input.text().strip()
        if not root_path:
            self._warn("Vui lòng chọn thư mục hoặc ổ đĩa trước khi quét.")
            return

        options: Dict[str, str] = {}
        if self.folder_opt_quick.isChecked():
            options["quick"] = "true"
        if self.folder_opt_hidden.isChecked():
            options["include_hidden"] = "true"
        if self.folder_opt_hash.isChecked():
            options["hash"] = "true"

        job = self.uploader.schedule_directory_scan(root_path, options)
        folder_label = os.path.basename(root_path.rstrip(os.sep)) or root_path
        self._start_loading_animation(f"Đang quét thư mục {folder_label}")
        self._append_activity(f"[{job.job_id}] Khởi chạy quét thư mục: {root_path}")
        if options:
            self._append_activity(f"Tùy chọn: {self._format_option_labels(options)}")
        QTimer.singleShot(450, lambda j=job: self._show_result(j))

    def _start_hash_scan(self, hash_value: Optional[str] = None) -> None:
        value = (hash_value or "").strip()
        if not value and hasattr(self, "hash_input"):
            value = self.hash_input.text().strip()
        if not value:
            self._warn("Vui lòng nhập giá trị hash trước khi quét.")
            return

        options: Dict[str, str] = {}
        if getattr(self, "hash_opt_yara", None) and self.hash_opt_yara.isChecked():
            options["yara"] = "true"
        if getattr(self, "hash_opt_capa", None) and self.hash_opt_capa.isChecked():
            options["capa"] = "true"
        if getattr(self, "hash_opt_strings", None) and self.hash_opt_strings.isChecked():
            options["floss"] = "true"
        if getattr(self, "hash_opt_pestudio", None) and self.hash_opt_pestudio.isChecked():
            options["pestudio"] = "true"

        job = self.uploader.scan_by_hash(value, options)
        display_hash = value if len(value) <= 18 else f"{value[:8]}…{value[-6:]}"
        self._start_loading_animation(f"Đang tra cứu hash {display_hash}")
        self._append_activity(f"[{job.job_id}] Quét theo hash: {value}")
        if options:
            self._append_activity(f"Tùy chọn: {self._format_option_labels(options)}")
        QTimer.singleShot(450, lambda j=job: self._show_result(j))
        if hasattr(self, "hash_input"):
            self.hash_input.clear()

    def _start_system_scan(self) -> None:
        if self._system_scanning:
            return

        self._system_scanning = True
        self.system_scan_btn.setEnabled(False)
        self.system_scan_btn.setText("Đang quét…")
        self.system_progress.setVisible(True)
        self.system_status_label.setText("Đang quét toàn bộ hệ thống…")

        job = self.uploader.schedule_system_scan("toàn bộ hệ thống", {"scope": "full"})
        self._pending_system_job = job
        self._append_activity(f"[{job.job_id}] Khởi chạy quét hệ thống toàn diện.")
        if job.options:
            self._append_activity(f"Tùy chọn: {self._format_option_labels(job.options)}")
        self._start_loading_animation(f"Đang quét hệ thống ({job.job_id})")

        QTimer.singleShot(2600, self._finish_system_scan)

    def _finish_system_scan(self) -> None:
        if not self._pending_system_job:
            self._system_scanning = False
            return

        job = self._pending_system_job
        verdict = "Không phát hiện mối đe dọa ở cấp độ hệ thống."
        completed = self.uploader.finalize_job(job, verdict=verdict)

        self._pending_system_job = None
        self._system_scanning = False
        self.system_progress.setVisible(False)
        self.system_scan_btn.setEnabled(True)
        self.system_scan_btn.setText("Quét toàn hệ thống")
        self.system_status_label.setText("Quét hệ thống hoàn tất. Không phát hiện bất thường.")

        self._append_activity(f"[{completed.job_id}] Đã hoàn tất quét hệ thống.")
        self._show_result(completed)

    def _append_activity(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.activity_log.appendPlainText(f"[{timestamp}] {message}")
        self._scroll_plain_text(self.activity_log)

    def _start_loading_animation(self, label: str) -> None:
        self._stop_loading_animation()
        self._loading_label = label
        self._loading_phase = 0
        self._loading_timer.start(220)
        self.result_output.setPlainText(f"{self._loading_label} ·")

    def _update_loading_animation(self) -> None:
        if not self._loading_label:
            return
        self._loading_phase = (self._loading_phase + 1) % 4
        dots = "." * (self._loading_phase or 1)
        self.result_output.setPlainText(f"{self._loading_label} {dots}")

    def _stop_loading_animation(self) -> None:
        self._loading_label = ""
        self._loading_phase = 0
        if self._loading_timer.isActive():
            self._loading_timer.stop()

    def _show_result(self, job: ScanJob) -> None:
        self._stop_loading_animation()
        timestamp = time.strftime("%H:%M:%S")
        header = f"[{timestamp}] {job.job_id} • {job.mode.upper()} • {job.target}"
        content = job.result or "Chưa có kết quả cho job này."
        self.result_output.setPlainText(f"{header}\n{content}")
        self._scroll_plain_text(self.result_output)

    @staticmethod
    def _scroll_plain_text(widget: QPlainTextEdit) -> None:
        widget.verticalScrollBar().setValue(widget.verticalScrollBar().maximum())

    @staticmethod
    def _format_option_labels(options: Dict[str, str]) -> str:
        labels = {
            "yara": "YARA",
            "capa": "capa",
            "floss": "FLOSS",
            "pestudio": "PEStudio",
            "quick": "Quét nhanh",
            "include_hidden": "Bao gồm tệp ẩn",
            "hash": "Hash SHA256",
            "scope": "Phạm vi toàn hệ thống",
        }
        formatted = []
        for key, value in options.items():
            value_str = str(value).strip().lower()
            if value_str in {"false", "0", "no", "off"}:
                continue
            label = labels.get(key, key)
            if value_str not in {"true", "1", "yes", "on"} and value_str:
                label = f"{label}={value}"
            formatted.append(label)
        return ", ".join(formatted) if formatted else "mặc định"

    def _handle_ws_message(self, message: str) -> None:
        self._append_activity(f"[Realtime] {message}")

    def _warn(self, text: str) -> None:
        QMessageBox.warning(self, "Thiếu thông tin", text)
