from __future__ import annotations

import os
import sys

from PyQt5.QtWidgets import QApplication


def _resolve_imports():
    if __package__:
        return

    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.append(current_dir)

    parent_dir = os.path.dirname(current_dir)
    if parent_dir not in sys.path:
        sys.path.append(parent_dir)


def main() -> int:
    _resolve_imports()

    if __package__:
        from .app_window import AppWindow
        from .uploader import Uploader
        from .ws_client import WSClient
    else:
        from app_window import AppWindow
        from uploader import Uploader
        from ws_client import WSClient

    app = QApplication(sys.argv)
    window = AppWindow(uploader=Uploader(), ws_client=WSClient())
    app.setWindowIcon(window.windowIcon())
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
