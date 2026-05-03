import asyncio
import threading


class PauseController:
    def __init__(self):
        self._reasons = set()
        self._lock = threading.Lock()
        self._loop = None
        self._async_event = asyncio.Event()
        self._async_event.set()

    def bind_loop(self, loop=None):
        if loop is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
        self._loop = loop

    def is_paused(self) -> bool:
        with self._lock:
            return bool(self._reasons)

    def is_paused_by(self, reason: str) -> bool:
        if not reason:
            return False
        with self._lock:
            return reason in self._reasons

    def pause(self, reason: str | None = None) -> None:
        key = reason or "manual"
        with self._lock:
            self._reasons.add(key)
        self._set_async_event(False)

    def resume(self, reason: str | None = None) -> None:
        with self._lock:
            if reason:
                self._reasons.discard(reason)
            else:
                self._reasons.clear()
            should_run = not self._reasons
        self._set_async_event(should_run)

    async def wait_if_paused(self) -> None:
        if self.is_paused():
            await self._async_event.wait()

    def _set_async_event(self, running: bool) -> None:
        if self._loop and self._loop.is_running():
            if running:
                self._loop.call_soon_threadsafe(self._async_event.set)
            else:
                self._loop.call_soon_threadsafe(self._async_event.clear)
        else:
            if running:
                self._async_event.set()
            else:
                self._async_event.clear()
