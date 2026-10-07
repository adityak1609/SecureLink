"""Bounded TCP service used by the bank and independent audit witness."""
import collections
import socket
import threading
import time

from .settings import MAX_CONNECTIONS, MAX_ATTEMPTS_PER_MINUTE


class TCPService:
    def __init__(self, host='127.0.0.1', port=0, max_connections=MAX_CONNECTIONS,
                 attempts_per_minute=MAX_ATTEMPTS_PER_MINUTE):
        self.listener = socket.socket()
        self.listener.bind((host, port))
        self.listener.listen(max_connections)
        self.listener.settimeout(.2)
        self.address = self.listener.getsockname()
        self.slots = threading.BoundedSemaphore(max_connections)
        self.attempts = collections.OrderedDict()
        self.rate_limit = attempts_per_minute
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.connections = set()
        self.workers = set()
        self.rejected = 0
        self.failures = 0

    def handle(self, conn, addr):
        raise NotImplementedError

    def serve_forever(self):
        while not self.stopping.is_set():
            try:
                conn, addr = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            now = time.monotonic()
            attempts = self.attempts.setdefault(addr[0], collections.deque())
            while attempts and now - attempts[0] > 60:
                attempts.popleft()
            allowed = len(attempts) < self.rate_limit
            if allowed:
                attempts.append(now)
            self.attempts.move_to_end(addr[0])
            if len(self.attempts) > 1024:
                self.attempts.popitem(last=False)
            if not allowed or not self.slots.acquire(blocking=False):
                self.rejected += 1
                conn.close()
                continue
            worker = threading.Thread(target=self._worker, args=(conn, addr), daemon=True)
            with self.lock:
                self.connections.add(conn)
                self.workers.add(worker)
            worker.start()

    def _worker(self, conn, addr):
        try:
            self.handle(conn, addr)
        except Exception:
            # No secrets or untrusted payloads in console errors.
            self.failures += 1
        finally:
            conn.close()
            with self.lock:
                self.connections.discard(conn)
                self.workers.discard(threading.current_thread())
            self.slots.release()

    def start(self):
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.stopping.set()
        self.listener.close()
        with self.lock:
            connections, workers = list(self.connections), list(self.workers)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        for worker in workers:
            worker.join(timeout=6)
        if hasattr(self, 'thread'):
            self.thread.join(timeout=1)

    def __enter__(self):
        return self.start()

    def __exit__(self, *args):
        self.stop()
