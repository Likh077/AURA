# integrity_monitor.py
import os
import time
import json
import hashlib
import threading

class FileIntegrityMonitor:
    """
    Reliable File Integrity Monitor:
    - baseline file stored as JSON (path_norm -> sha256)
    - periodic background scanning
    - detects added / modified / removed files
    - supports a force_scan() to trigger immediate detection (useful for testing)
    - emits structured events via an alert_queue (if provided)
    """

    def __init__(self, baseline_path="integrity_baseline.json",
                 watch_dirs=None, interval=60, alert_queue=None, max_files=None):
        self.baseline_path = baseline_path
        self.watch_dirs = watch_dirs or [r"C:\Users\LIKHITH\OneDrive\Desktop\AURA-COPY"]
        self.interval = interval
        self.alert_queue = alert_queue
        self.running = False
        self.lock = threading.Lock()
        # limit how many files to index for speed (None = no limit)
        self.max_files = max_files

        # internal baseline representation uses normcase() for Windows compatibility
        self.baseline = {}
        if os.path.exists(self.baseline_path):
            self._load_baseline()
        else:
            print("[INTEGRITY] Baseline not found; create baseline by calling create_baseline() or start_monitoring().")

    # ----------------------
    # hashing helpers
    # ----------------------
    def _hash_file(self, path):
        try:
            with open(path, "rb") as f:
                h = hashlib.sha256()
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    # ----------------------
    # baseline creation / load / save
    # ----------------------
    def create_baseline(self):
        """
        Create and save a baseline snapshot for all watch_dirs.
        This may take time on first run. Progress printed to console.
        """
        print("[INTEGRITY] Creating baseline...")
        snapshot = {}
        count = 0
        for base in self.watch_dirs:
            if not os.path.exists(base):
                print(f"[INTEGRITY] Watch directory missing: {base}  (skipping)")
                continue
            for root, _, files in os.walk(base):
                for name in files:
                    path = os.path.join(root, name)
                    norm = os.path.normcase(os.path.abspath(path))
                    file_hash = self._hash_file(path)
                    if file_hash:
                        snapshot[norm] = file_hash
                    count += 1
                    if self.max_files and count >= self.max_files:
                        print(f"[INTEGRITY] Reached max_files ({self.max_files}) while indexing baseline.")
                        break
                if self.max_files and count >= self.max_files:
                    break
            if self.max_files and count >= self.max_files:
                break

        try:
            with open(self.baseline_path, "w") as f:
                json.dump(snapshot, f, indent=2)
            self.baseline = snapshot
            print(f"[INTEGRITY] Baseline created ({len(snapshot)} files tracked).")
        except Exception as e:
            print(f"[INTEGRITY] Failed to save baseline: {e}")

    def _load_baseline(self):
        try:
            with open(self.baseline_path, "r") as f:
                data = json.load(f)
            # ensure keys are normalized for comparison
            self.baseline = {os.path.normcase(k): v for k, v in data.items()}
            print(f"[INTEGRITY] Baseline loaded ({len(self.baseline)} files).")
        except Exception as e:
            print(f"[INTEGRITY] Failed to load baseline: {e}")
            self.baseline = {}

    def _save_baseline(self):
        try:
            with open(self.baseline_path, "w") as f:
                json.dump(self.baseline, f, indent=2)
        except Exception as e:
            print(f"[INTEGRITY] Failed to save baseline: {e}")

    # ----------------------
    # scanning & detection
    # ----------------------
    def _scan_current(self):
        """Return snapshot dict of current files: {norm_path: sha256}"""
        snapshot = {}
        count = 0
        for base in self.watch_dirs:
            if not os.path.exists(base):
                continue
            for root, _, files in os.walk(base):
                for name in files:
                    path = os.path.join(root, name)
                    norm = os.path.normcase(os.path.abspath(path))
                    h = self._hash_file(path)
                    if h:
                        snapshot[norm] = h
                    count += 1
                    if self.max_files and count >= self.max_files:
                        return snapshot
        return snapshot

    def detect_drift(self):
        """
        Compare current snapshot with baseline.
        Returns dict: {modified:[], added:[], removed:[]}
        Also pushes events into alert_queue if provided.
        """
        with self.lock:
            current = self._scan_current()

            modified = []
            removed = []
            added = []

            # check for modified / removed
            for path, old_hash in self.baseline.items():
                new_hash = current.get(path)
                if new_hash is None:
                    removed.append(path)
                elif new_hash != old_hash:
                    modified.append(path)

            # check for new files
            for path in current.keys():
                if path not in self.baseline:
                    added.append(path)

            # if any changes, push structured event(s)
            if modified or removed or added:
                event = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "modified": modified,
                    "added": added,
                    "removed": removed,
                    "total_changes": len(modified) + len(added) + len(removed)
                }
                print(f"[INTEGRITY] Drift detected: modified={len(modified)} added={len(added)} removed={len(removed)}")
                # push event(s) to queue
                if self.alert_queue:
                    try:
                        self.alert_queue.put(event)
                    except Exception:
                        pass
                # update baseline for modified/added/removed? (we do not auto-update baseline)
                # (We keep baseline unchanged — admin should rebuild baseline if changes are expected)
                return event
            else:
                print("[INTEGRITY] No drift detected.")
                return None

    # ----------------------
    # background monitoring
    # ----------------------
    def start_monitoring(self, initial_delay=2):
        """Start background thread that runs detect_drift() every self.interval seconds."""
        if self.running:
            return
        if not self.baseline:
            print("[INTEGRITY] No baseline loaded — creating one now.")
            self.create_baseline()

        self.running = True

        def _loop():
            # small initial delay to let system stabilize
            time.sleep(initial_delay)
            while self.running:
                try:
                    self.detect_drift()
                except Exception as e:
                    print(f"[INTEGRITY] Error during detect_drift: {e}")
                time.sleep(self.interval)

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        print(f"[INTEGRITY] Background monitor started (interval={self.interval}s).")

    def stop_monitoring(self):
        self.running = False
        print("[INTEGRITY] Monitoring stopped.")

    # ----------------------
    # utility: force scan
    # ----------------------
    def force_scan(self):
        """Run detect_drift() once synchronously and return event or None."""
        return self.detect_drift()
