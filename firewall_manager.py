# firewall_manager.py
import platform
import subprocess
import json
import os
import ipaddress

class FirewallManager:
    """
    Firewall manager for AURA Cyber Threat Radar
    - Auto-blocks malicious IPs dynamically.
    - Persists blocked IPs.
    - Prevents duplicate rules.
    - Works safely on Windows (using netsh).
    """

    def __init__(self, record_file="blocked_ips.json"):
        self.os = platform.system().lower()
        self.record_file = record_file
        self.blocked_ips = set()
        self._load_blocked_ips()

    # -------------------------------
    # File persistence helpers
    # -------------------------------
    def _load_blocked_ips(self):
        if os.path.exists(self.record_file):
            try:
                with open(self.record_file, "r") as f:
                    self.blocked_ips = set(json.load(f))
                print(f"[FIREWALL] Loaded {len(self.blocked_ips)} previously blocked IPs.")
            except Exception:
                self.blocked_ips = set()

    def _save_blocked_ips(self):
        try:
            with open(self.record_file, "w") as f:
                json.dump(sorted(list(self.blocked_ips)), f, indent=2)
        except Exception as e:
            print(f"[FIREWALL] Failed to save record: {e}")

    # -------------------------------
    # Private helper
    # -------------------------------
    def _is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return True

    # -------------------------------
    # Main methods
    # -------------------------------
    def block_ip(self, ip):
        """Add a firewall rule to block a malicious IP address."""
        if self._is_private_ip(ip):
            return

        if ip in self.blocked_ips:
            return  # already blocked

        try:
            if "windows" in self.os:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=AURA_Block_{ip}", "dir=in", f"remoteip={ip}", "action=block"
                ], capture_output=True, check=False)
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=AURA_Block_{ip}", "dir=out", f"remoteip={ip}", "action=block"
                ], capture_output=True, check=False)
            else:
                print(f"[FIREWALL] Non-Windows OS detected, skipping actual block for {ip}.")

            self.blocked_ips.add(ip)
            self._save_blocked_ips()
            print(f"[FIREWALL] Blocked IP: {ip}")
        except Exception as e:
            print(f"[FIREWALL] Failed to block {ip}: {e}")

    def unblock_ip(self, ip):
        """Remove a firewall block rule for a given IP."""
        if ip not in self.blocked_ips:
            return

        try:
            if "windows" in self.os:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=AURA_Block_{ip}"
                ], capture_output=True, check=False)
            else:
                print(f"[FIREWALL] Non-Windows OS detected, skipping unblock for {ip}.")

            self.blocked_ips.remove(ip)
            self._save_blocked_ips()
            print(f"[FIREWALL] Unblocked IP: {ip}")
        except Exception as e:
            print(f"[FIREWALL] Failed to unblock {ip}: {e}")

    def list_blocked_ips(self):
        """Return the current list of blocked IPs."""
        return sorted(list(self.blocked_ips))
