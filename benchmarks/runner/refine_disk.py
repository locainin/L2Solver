"""Sample owned disk and open temporary files during an existing process run."""

import os
import stat
import time
from pathlib import Path


class DiskObserver:
    def __init__(self, root, temporary, stop_at, interval=0.25):
        self.root = Path(root).resolve()
        self.temporary = Path(temporary).resolve()
        self.temporary.relative_to(self.root)
        if stop_at <= 0 or interval <= 0:
            raise ValueError("disk limit and sample interval must be positive")
        self.stop_at, self.interval, self.next_sample = stop_at, interval, None
        self.samples = self.errors = 0
        self.named = self.allocated = self.temp_logical = self.temp_allocated = self.temp_files = 0
        self.stopped = False

    def sample(self, pids, force=False):
        now = time.monotonic()
        if not force and self.next_sample is not None and now < self.next_sample:
            return
        self.next_sample = now + self.interval
        named, temporary = {}, {}
        try:
            def fail(error):
                raise error
            for directory, _subdirs, files in os.walk(self.root, onerror=fail, followlinks=False):
                for name in files:
                    try:
                        info = os.stat(Path(directory) / name, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISREG(info.st_mode):
                        named[(info.st_dev, info.st_ino)] = (info.st_size, info.st_blocks * 512)
            for pid in pids:
                try:
                    descriptors = list((Path("/proc") / str(pid) / "fd").iterdir())
                except FileNotFoundError:
                    continue
                for descriptor in descriptors:
                    try:
                        target = os.readlink(descriptor)
                        if not target.startswith(str(self.temporary) + os.sep):
                            continue
                        info = descriptor.stat()
                    except FileNotFoundError:
                        continue
                    if stat.S_ISREG(info.st_mode):
                        temporary[(info.st_dev, info.st_ino)] = (info.st_size, info.st_blocks * 512)
        except OSError:
            self.errors += 1
            raise
        all_owned = dict(named)
        all_owned.update(temporary)
        self.samples += 1
        self.named = max(self.named, sum(size for size, _ in named.values()))
        self.allocated = max(self.allocated, sum(size for _, size in all_owned.values()))
        self.temp_logical = max(self.temp_logical, sum(size for size, _ in temporary.values()))
        self.temp_allocated = max(self.temp_allocated, sum(size for _, size in temporary.values()))
        self.temp_files = max(self.temp_files, len(temporary))
        if self.allocated >= self.stop_at:
            self.stopped = True
            raise ValueError("owned disk stop threshold reached")

    def result(self):
        return {"samples": self.samples, "sampling_interval_seconds": self.interval,
                "peak_named_logical_bytes": self.named, "peak_owned_allocated_bytes": self.allocated,
                "peak_temporary_logical_bytes": self.temp_logical,
                "peak_temporary_allocated_bytes": self.temp_allocated,
                "peak_temporary_open_files": self.temp_files, "sampling_errors": self.errors,
                "disk_stop_requested": self.stopped, "peaks_are_lower_bounds": True,
                "scope": "owned files plus open files under private temporary directory"}
