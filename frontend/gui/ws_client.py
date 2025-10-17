"""
Minimal websocket client placeholder.

The real implementation should manage an asynchronous websocket connection
to the backend for streaming job updates. The GUI expects this object to
expose connect/disconnect hooks and a way to register callbacks.
"""

from __future__ import annotations

from typing import Callable, List, Optional


class WSClient:
    def __init__(self) -> None:
        self._callbacks: List[Callable[[str], None]] = []
        self._connected = False

    def connect(self, url: str) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    def register_callback(self, callback: Callable[[str], None]) -> None:
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def emit_fake_message(self, message: str) -> None:
        """
        Convenience helper so the GUI can simulate websocket activity while
        the real backend is not available.
        """

        for callback in self._callbacks:
            callback(message)
