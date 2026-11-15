"""Native single-process resource guards. Not a distributed/multi-worker quota."""
import threading
import time
from fastapi import HTTPException
from backend.app.core.config import settings

_ip_request_history = {}
_LOCK = threading.Lock()
PUBLIC_SLOTS = threading.BoundedSemaphore(settings.VERIFY_CONCURRENCY)

def check_rate_limit(client_ip):
    now = time.monotonic()
    cutoff = now - 60
    with _LOCK:
        for ip in list(_ip_request_history):
            _ip_request_history[ip] = [t for t in _ip_request_history[ip] if t > cutoff]
            if not _ip_request_history[ip]:
                del _ip_request_history[ip]
        if client_ip not in _ip_request_history and len(_ip_request_history) >= settings.VERIFY_MAX_TRACKED_IPS:
            raise HTTPException(503, "Rate limiter capacity reached", headers={"Retry-After":"60"})
        history = _ip_request_history.setdefault(client_ip, [])
        if len(history) >= settings.VERIFY_RATE_PER_MINUTE:
            raise HTTPException(429, "Quá nhiều yêu cầu xác minh", headers={"Retry-After":"60"})
        history.append(now)

class Admission:
    """A worker keeps its permit if the HTTP request disconnects while it runs."""
    def __init__(self, semaphore):
        self.semaphore = semaphore
        self.lock = threading.Lock()
        self.started = False
        self.released = False
    def start_job(self):
        with self.lock:
            if self.released:
                raise HTTPException(503, "Verification request cancelled")
            self.started = True
    def finish_job(self):
        with self.lock:
            self._release()
    def close_request(self):
        with self.lock:
            if not self.started:
                self._release()
    def _release(self):
        if not self.released:
            self.released = True
            self.semaphore.release()
