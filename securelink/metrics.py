"""Operation timings from the actual cryptographic calls, not estimated values."""
from contextlib import contextmanager
import time


class CryptoMetrics:
    def __init__(self):
        self.values = {}

    @contextmanager
    def measure(self, operation, size=0):
        start = time.perf_counter_ns()
        failed = False
        try:
            yield
        except BaseException:
            failed = True
            raise
        finally:
            value = self.values.setdefault(operation, {'calls':0, 'nanoseconds':0, 'bytes':0, 'failures':0})
            value['calls'] += 1
            value['nanoseconds'] += max(0, time.perf_counter_ns() - start)
            value['bytes'] += size
            value['failures'] += int(failed)

    def snapshot(self):
        return {name:{**value,'milliseconds':value['nanoseconds']/1_000_000} for name,value in self.values.items()}
