"""
ConsentManager — decouples consent prompts from background threads.

The TCP router runs in a background thread. Python's input() cannot be
safely called from two threads at once — the CLI's input() and the router's
input() fight over stdin, causing the first keypress to be consumed by the
wrong caller.

Fix: the background thread queues the consent request and blocks on a
response queue. The main CLI loop detects the pending request, prints the
prompt itself (from the main thread), reads the response, and unblocks the
background thread.
"""
import threading
import queue


class ConsentManager:

    def __init__(self):
        self._pending  = queue.Queue()   # (peer_name, filename, filesize)
        self._response = queue.Queue()   # bool: True=accepted, False=denied
        self._event    = threading.Event()

    def request(self, peer_name: str, filename: str, filesize: int) -> bool:
        """
        Called from a background thread.
        Submits the consent request and blocks until the main thread responds.
        """
        self._pending.put((peer_name, filename, filesize))
        self._event.set()
        return self._response.get()   # blocks until CLI loop calls respond()

    def is_pending(self) -> bool:
        return self._event.is_set()

    def pop_pending(self):
        """Called from the main thread to retrieve the queued request."""
        item = self._pending.get_nowait()
        self._event.clear()
        return item   # (peer_name, filename, filesize)

    def respond(self, accepted: bool):
        """Called from the main thread after the user answers."""
        self._response.put(accepted)
