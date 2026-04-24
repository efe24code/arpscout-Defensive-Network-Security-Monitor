import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Optional imports for advanced features
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False  # Optional: Linux/macOS only (Windows needs compilation)

try:
    from scapy.all import ARP, Ether, sniff, sendp, conf
    SCAPY_AVAILABLE = True
    # Scapy config: avoid verbose output
    conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False  # Optional dependency

try:
    import sqlite3
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False


# ──────────────────────────── Logging Setup ──────────────────────────────
LOG_DIR = Path.home() / ".arpscout" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / f"arpscout_{datetime.now():%Y%m%d_%H%M%S}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("arpscout")

# ──────────────────────────── Constants ──────────────────────────────────
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
# Strict IPv4 regex (0-255 per octet)
IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
KNOWN_DEVICES_FILE = Path.home() / ".arpscout" / "known_devices.json"

# ──────────────────────────── Notification Module ──────────────────────────
class Notifier:
    """Cross-platform desktop notifications."""

    @staticmethod
    def available() -> bool:
        if _is_windows():
            try:
                from win10toast import ToastNotifier
                return True
            except ImportError:
                return False
        elif _is_linux():
            return os.system("which notify-send >/dev/null 2>&1") == 0
        elif _is_macos():
            return os.system("which osascript >/dev/null 2>&1") == 0
        return False

    @staticmethod
    def send(title: str, message: str, duration: int = 5) -> None:
        try:
            if _is_windows():
                try:
                    from win10toast import ToastNotifier
                    toaster = ToastNotifier()
                    toaster.show_toast(title, message, duration=duration, threaded=True)
                except ImportError:
                    log.debug("win10toast not installed – skipping notification")
            elif _is_linux():
                os.system(f'notify-send "{title}" "{message}" --expire-time={duration*1000}')
            elif _is_macos():
                script = f'display notification "{message}" with title "{title}"'
                os.system(f'osascript -e \'{script}\'')
        except Exception as e:
            log.debug("Notification failed: %s", e)


# ──────────────────────────── Data Classes ───────────────────────────────
@dataclass(frozen=True)
class WifiNetwork:
    ssid: str
    bssid: str | None = None
    channel: int | None = None
    signal_dbm: int | None = None
    authentication: str | None = None
    encryption: str | None = None

    def is_open(self) -> bool:
        auth = (self.authentication or "").lower()
        enc = (self.encryption or "").lower()
        return any(x in auth for x in ("open", "none")) or "none" in enc

    def is_wep(self) -> bool:
        auth = (self.authentication or "").lower()
        enc = (self.encryption or "").lower()
        return "wep" in auth or "wep" in enc

    @property
    def risk_flags(self) -> list[str]:
        flags = []
        if self.is_open():
            flags.append("OPEN")
        if self.is_wep():
            flags.append("WEP_INSECURE")
        return flags


@dataclass
class DeviceInfo:
    mac: str
    ip: str | None = None
    vendor: str | None = None
    first_seen: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    last_seen: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    labels: list[str] = field(default_factory=list)
    signals: list[int] = field(default_factory=list)  # RSSI history dBm


# ──────────────────────────── Database Module ─────────────────────────────
if SQLITE_AVAILABLE:
    class DBOperator:
        """SQLite persistence for events, devices, and networks."""

        def __init__(self, db_path: Path | None = None) -> None:
            self.db_path = db_path or Path.home() / ".arpscout" / "arpscout.db"
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_schema()

        def _connect(self) -> sqlite3.Connection:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            return conn

        def _init_schema(self) -> None:
            if not SQLITE_AVAILABLE:
                return
            conn = self._connect()
            cur = conn.cursor()
            # Events table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    category TEXT NOT NULL,
                    message TEXT NOT NULL
                )
            """)
            # Devices table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    labels TEXT DEFAULT '[]'
                )
            """)
            # Networks table (Wi-Fi scans)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS networks (
                    bssid TEXT PRIMARY KEY,
                    ssid TEXT NOT NULL,
                    channel INTEGER,
                    signal_dbm INTEGER,
                    authentication TEXT,
                    encryption TEXT,
                    last_seen TEXT NOT NULL
                )
            """)
            # Indexes
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_last ON devices(last_seen)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_networks_last ON networks(last_seen)")
            conn.commit()
            conn.close()

        def insert_event(self, ev: Any) -> None:
            if not SQLITE_AVAILABLE:
                return
            try:
                conn = self._connect()
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO events (timestamp, level, category, message) VALUES (?, ?, ?, ?)",
                    (ev.timestamp, ev.level, ev.category, ev.message),
                )
                conn.commit()
                conn.close()
            except Exception as e:
                log.debug("DB insert_event failed: %s", e)

        def upsert_device(self, dev: Any) -> None:
            if not SQLITE_AVAILABLE:
                return
            try:
                conn = self._connect()
                cur = conn.cursor()
                cur.execute(
                    """INSERT INTO devices (mac, ip, first_seen, last_seen, labels)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(mac) DO UPDATE SET
                         ip=excluded.ip,
                         last_seen=excluded.last_seen,
                         labels=excluded.labels""",
                    (dev.mac, dev.ip, dev.first_seen, dev.last_seen, json.dumps(dev.labels)),
                )
                conn.commit()
                conn.close()
            except Exception as e:
                log.debug("DB upsert_device failed: %s", e)

        def upsert_network(self, net: Any, ts: str) -> None:
            if not SQLITE_AVAILABLE:
                return
            if not net.bssid:
                return
            try:
                conn = self._connect()
                cur = conn.cursor()
                cur.execute(
                    """INSERT INTO networks (bssid, ssid, channel, signal_dbm, authentication, encryption, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(bssid) DO UPDATE SET
                         ssid=excluded.ssid,
                         channel=excluded.channel,
                         signal_dbm=excluded.signal_dbm,
                         authentication=excluded.authentication,
                         encryption=excluded.encryption,
                         last_seen=excluded.last_seen""",
                    (net.bssid.lower(), net.ssid, net.channel, net.signal_dbm,
                     net.authentication, net.encryption, ts),
                )
                conn.commit()
                conn.close()
            except Exception as e:
                log.debug("DB upsert_network failed: %s", e)

        def get_event_count(self, hours: int = 24) -> int:
            if not SQLITE_AVAILABLE:
                return 0
            try:
                conn = self._connect()
                cur = conn.cursor()
                cur.execute(
                    "SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now', ?)",
                    (f'-{hours} hours',)
                )
                count = cur.fetchone()[0]
                conn.close()
                return count
            except Exception:
                return 0
else:
    # Dummy class when sqlite3 not available
    class DBOperator:
        def __init__(self, db_path: Path | None = None) -> None:
            pass
        def insert_event(self, ev: Any) -> None:
            pass
        def upsert_device(self, dev: Any) -> None:
            pass
        def upsert_network(self, net: Any, ts: str) -> None:
            pass
        def get_event_count(self, hours: int = 24) -> int:
            return 0


def _is_special_mac(mac: str) -> bool:
    """Return True for broadcast, multicast, or reserved MACs."""
    m = mac.lower().replace("-", ":").replace(":", ":")
    # Broadcast
    if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return True
    # IPv4 multicast (01:00:5e:00:00:00 - 01:00:5e:7f:ff:ff)
    if m.startswith("01:00:5e"):
        return True
    # IPv6 multicast (33:33:00:00:00:00 - 33:33:ff:ff:ff:ff)
    if m.startswith("33:33"):
        return True
    return False


# ──────────────────────────── Platform Helpers ───────────────────────────
def _is_windows() -> bool:
    return os.name == "nt"


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _is_macos() -> bool:
    return sys.platform == "darwin"


# ──────────────────────────── Wi-Fi Scanning ─────────────────────────────
def _run(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=15)
        out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
        return out.strip()
    except Exception as e:
        log.error("Command failed: %s – %s", cmd, e)
        return ""


# ─── Windows ──────────────────────────────────────────────────────────────
def _wifi_scan_windows() -> list[WifiNetwork]:
    text = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    if not text:
        return []

    networks: list[WifiNetwork] = []
    current: dict[str, Any] = {}

    for raw in text.splitlines():
        line = raw.strip()

        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
        if m:
            if current:
                networks.append(WifiNetwork(**current))
            current = {"ssid": m.group(1).strip()}
            continue

        if not current:
            continue

        m = re.match(r"^BSSID\s+\d+\s*:\s*([0-9A-Fa-f:-]{17})", line)
        if m:
            current["bssid"] = m.group(1).replace("-", ":").lower()

        m = re.match(r"^Channel\s*:\s*(\d+)", line)
        if m:
            current["channel"] = int(m.group(1))

        m = re.match(r"^Signal\s*:\s*(\d+)%", line)
        if m:
            # Windows netsh signal is percentage. Roughly: 100% ≈ -50dBm, 0% ≈ -100dBm
            pct = int(m.group(1))
            approx_dbm = int(-100 + (pct / 100) * 50)
            current["signal_dbm"] = approx_dbm

        m = re.match(r"^Authentication\s*:\s*(.*)$", line, re.IGNORECASE)
        if m:
            current["authentication"] = m.group(1).strip()

        m = re.match(r"^Encryption\s*:\s*(.*)$", line, re.IGNORECASE)
        if m:
            current["encryption"] = m.group(1).strip()

    if current:
        networks.append(WifiNetwork(**current))

    # Deduplicate by (SSID,BSSID) – keep first
    uniq: dict[tuple[str, str], WifiNetwork] = {}
    for n in networks:
        key = ((n.ssid or "").strip().lower(), (n.bssid or "??").lower())
        if key not in uniq:
            uniq[key] = n
    return list(uniq.values())


# ─── Linux ────────────────────────────────────────────────────────────────
def _wifi_scan_linux() -> list[WifiNetwork]:
    # Try nmcli first (NetworkManager)
    out = _run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "device", "wifi", "list"])
    if out and ":" in out:
        networks: list[WifiNetwork] = []
        for line in out.splitlines():
            if not line.strip():
                continue
            parts = line.split(":", 4)  # SSID:BSSID:CHAN:SIGNAL:SECURITY
            if len(parts) >= 5:
                ssid = parts[0] or "<hidden>"
                bssid = parts[1].lower().strip()
                try:
                    channel = int(parts[2]) if parts[2] else None
                except ValueError:
                    channel = None
                # nmcli signal is percentage (0-100)
                try:
                    pct = int(parts[3])
                    approx_dbm = int(-100 + (pct / 100) * 50)
                except ValueError:
                    approx_dbm = None
                sec = parts[4].strip()
                auth, enc = None, None
                if sec:
                    if "WPA2" in sec or "WPA3" in sec or "WPA" in sec:
                        auth = "WPA"
                        enc = "AES" if "AES" in sec else "TKIP"
                    elif "WEP" in sec:
                        auth = "WEP"
                        enc = "WEP"
                    elif "OPEN" in sec or sec == "NONE":
                        auth = "OPEN"
                        enc = "NONE"

                networks.append(WifiNetwork(
                    ssid=ssid,
                    bssid=bssid if bssid and bssid != "N/A" else None,
                    channel=channel,
                    signal_dbm=approx_dbm,
                    authentication=auth,
                    encryption=enc,
                ))
        return _dedup_wifi_networks(networks)

    # Fallback: iwlist (requires sudo)
    networks = _wifi_scan_linux_iwlist()
    return _dedup_wifi_networks(networks)


def _wifi_scan_linux_iwlist() -> list[WifiNetwork]:
    out = _run(["sudo", "iwlist", "scan", "2>/dev/null"])
    if not out:
        return []

    networks: list[WifiNetwork] = []
    cur: dict[str, Any] = {}

    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("Cell "):
            if cur:
                networks.append(WifiNetwork(**cur))
            cur = {}
            m = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", line)
            if m:
                cur["bssid"] = m.group(1).lower()
        elif line.startswith("ESSID:"):
            cur["ssid"] = line.split(':', 1)[1].strip().strip('"')
        elif line.startswith("Channel:"):
            try:
                cur["channel"] = int(line.split(':', 1)[1])
            except ValueError:
                pass
        elif line.startswith("Quality=") or line.startswith("Signal level="):
            # Try to estimate dBm from quality/level
            m = re.search(r"Quality=(\d+)/\d+|Quality level=(\d+)", line)
            if m:
                q = int(m.group(1) or m.group(2))
                # Rough approximation: 0-100 quality → -100 to -50 dBm
                cur["signal_dbm"] = int(-100 + (q / 100) * 50)
        elif "Encryption key" in line:
            if "on" in line:
                cur["encryption"] = "WPA2"  # default assumption
            else:
                cur["authentication"] = "OPEN"
                cur["encryption"] = "NONE"

    if cur:
        networks.append(WifiNetwork(**cur))

    return networks


# ─── macOS ────────────────────────────────────────────────────────────────
def _wifi_scan_macos() -> list[WifiNetwork]:
    # macOS: /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s
    airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    out = _run([airport, "-s"])
    if not out:
        return []

    networks: list[WifiNetwork] = []
    lines = out.splitlines()
    if len(lines) < 2:
        return networks

    # Header line format (varies), skip it; data has columns
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        # airport output approx: SSID BSSID RSSI CHANNEL SECURITY
        try:
            rssi = int(parts[2])
        except (IndexError, ValueError):
            rssi = None
        try:
            channel = int(parts[3])
        except (IndexError, ValueError):
            channel = None
        ssid = parts[0]
        bssid = parts[1].lower() if len(parts) > 1 else None
        sec = parts[4] if len(parts) > 4 else ""
        auth = enc = None
        if sec:
            if "WPA2" in sec or "WPA3" in sec or "WPA" in sec:
                auth = "WPA"
                enc = "AES"
            elif "WEP" in sec:
                auth = "WEP"
                enc = "WEP"
            elif sec == "NONE" or "OPEN" in sec:
                auth = "OPEN"
                enc = "NONE"
        networks.append(WifiNetwork(
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            signal_dbm=rssi,
            authentication=auth,
            encryption=enc,
        ))
    return _dedup_wifi_networks(networks)


def _dedup_wifi_networks(nets: list[WifiNetwork]) -> list[WifiNetwork]:
    uniq: dict[tuple[str, str], WifiNetwork] = {}
    for n in nets:
        bssid = (n.bssid or "??").lower()
        key = ((n.ssid or "").strip().lower(), bssid)
        if key not in uniq:
            uniq[key] = n
    return list(uniq.values())


def wifi_scan() -> list[WifiNetwork]:
    if _is_windows():
        return _wifi_scan_windows()
    elif _is_linux():
        return _wifi_scan_linux()
    elif _is_macos():
        return _wifi_scan_macos()
    else:
        log.error("Unsupported platform for Wi-Fi scan")
        return []


# ──────────────────────────── ARP Table Parsing ──────────────────────────
def _parse_arp_a(text: str) -> dict[str, str]:
    """
    Parses `arp -a` output into {ip: mac}. Works for common Windows formats.
    Skips broadcast/multicast/reserved addresses.
    """
    mapping: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("interface:") or line.lower().startswith("internet address"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 2:
            continue
        ip = parts[0].strip()
        mac_raw = parts[1].strip()
        mac = mac_raw.replace("-", ":").replace("..", ":").lower()
        if not MAC_RE.match(mac):
            continue
        # Filter special MACs
        if _is_special_mac(mac):
            continue
        # Filter special IPs
        if ip in ("255.255.255.255", "0.0.0.0"):
            continue
        mapping[ip] = mac
    return mapping


# ─── Windows ARP ──────────────────────────────────────────────────────────
def arp_snapshot_windows() -> dict[str, str]:
    """Get current ARP table from `arp -a`."""
    out = _run(["arp", "-a"])
    if not out:
        return {}
    return _parse_arp_a(out)


# ─── Linux ARP ────────────────────────────────────────────────────────────
def arp_snapshot_linux() -> dict[str, str]:
    # Read from /proc/net/arp
    arp_path = Path("/proc/net/arp")
    if not arp_path.exists():
        return {}
    mapping: dict[str, str] = {}
    try:
        with arp_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[1:]:  # skip header
            parts = re.split(r"\s+", line.strip())
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3]
                if MAC_RE.match(mac):
                    mapping[ip] = mac.lower()
    except Exception as e:
        log.debug("Failed to parse /proc/net/arp: %s", e)
    return mapping


def arp_snapshot() -> dict[str, str]:
    if _is_windows():
        return arp_snapshot_windows()
    elif _is_linux():
        return arp_snapshot_linux()
    else:
        log.error("ARP snapshot not implemented for this platform")
        return {}


# ──────────────────────────── Gateway Detection ──────────────────────────
def _default_gateway_windows() -> str | None:
    out = _run(["route", "print", "0.0.0.0"])
    if not out:
        return None
    for raw in out.splitlines():
        line = raw.strip()
        if not line or not re.match(r"^0\.0\.0\.0\s+0\.0\.0\.0\s+", line):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 3 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parts[2]):
            return parts[2]
    return None


def _default_gateway_linux() -> str | None:
    # Try ip route
    out = _run(["ip", "route", "show", "default"])
    if out:
        m = re.search(r"via\s+([0-9.]+)", out)
        if m:
            return m.group(1)
    # Fallback to netstat
    out = _run(["netstat", "-rn"])
    if out:
        for raw in out.splitlines():
            line = raw.strip()
            if line.startswith("0.0.0.0") or line.startswith("default"):
                parts = re.split(r"\s+", line)
                if len(parts) >= 2:
                    gw = parts[1] if line.startswith("0.0.0.0") else parts[1]
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", gw):
                        return gw
    return None


def default_gateway() -> str | None:
    if _is_windows():
        return _default_gateway_windows()
    elif _is_linux():
        return _default_gateway_linux()
    return None


# ──────────────────────────── Detection Logic ─────────────────────────────
@dataclass
class DetectionEvent:
    timestamp: str
    level: str  # INFO, WARN, CRITICAL
    category: str
    message: str


class DetectionEngine:
    def __init__(
        self,
        db: DBOperator | None = None,
        notifier: Notifier | None = None,
        notify_levels: tuple[str, ...] = ("CRITICAL", "WARN"),
    ) -> None:
        self._last_arp: dict[str, str] = {}
        self._gw_mac_baseline: str | None = None
        self._events: list[DetectionEvent] = []
        self._lock = threading.Lock()
        self._db = db
        self._notifier = notifier
        self._notify_levels = notify_levels

        self._known_devices: dict[str, DeviceInfo] = self._load_known_devices()
        self._ap_baseline: dict[str, WifiNetwork] = {}  # bssid -> latest network

    # ─── Known Devices ────────────────────────────────────────────────────
    @staticmethod
    def known_file() -> Path:
        return KNOWN_DEVICES_FILE

    def _load_known_devices(self) -> dict[str, DeviceInfo]:
        path = self.known_file()
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            devices: dict[str, DeviceInfo] = {}
            for mac, info in data.items():
                if MAC_RE.match(mac):
                    devices[mac] = DeviceInfo(**info)
            return devices
        except Exception as e:
            log.warning("Failed to load known devices: %s", e)
            return {}

    def _save_known_devices(self) -> None:
        path = self.known_file()
        try:
            payload = {mac: info.__dict__ for mac, info in self._known_devices.items()}
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.error("Failed to save known devices: %s", e)

    def add_known_device(self, mac: str, ip: str | None = None, label: str = "") -> None:
        key = mac.lower()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if key not in self._known_devices:
            self._known_devices[key] = DeviceInfo(
                mac=key,
                ip=ip,
                first_seen=now,
                last_seen=now,
                labels=[label] if label else [],
            )
        else:
            dev = self._known_devices[key]
            dev.last_seen = now
            if ip:
                dev.ip = ip
            if label and label not in dev.labels:
                dev.labels.append(label)
        self._save_known_devices()
        if self._db:
            self._db.upsert_device(self._known_devices[key])

    def learn_baseline_from_arp(self, arp_table: dict[str, str]) -> None:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for ip, mac in arp_table.items():
            key = mac.lower()
            if key not in self._known_devices:
                self._known_devices[key] = DeviceInfo(
                    mac=key,
                    ip=ip,
                    first_seen=now,
                    last_seen=now,
                )
                log.info("Learned new device: %s (%s)", mac, ip)
            else:
                self._known_devices[key].last_seen = now
                self._known_devices[key].ip = ip
        self._save_known_devices()
        if self._db:
            for dev in self._known_devices.values():
                self._db.upsert_device(dev)

    # ─── ARP Spoof Detection ───────────────────────────────────────────────
    def check_arp_changes(
        self,
        prev: dict[str, str],
        cur: dict[str, str],
        gateway_ip: str | None,
    ) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self._lock:
            last = self._last_arp.copy()
            gw_mac = self._gw_mac_baseline

        # 1. IP→MAC changes over time
        for ip, mac in cur.items():
            # Skip special IPs/MACs
            if ip in ("255.255.255.255", "0.0.0.0") or _is_special_mac(mac):
                continue
            old = prev.get(ip)
            if old and old != mac and not _is_special_mac(old):
                events.append(DetectionEvent(
                    timestamp=now,
                    level="WARN",
                    category="ARP_CHANGE",
                    message=f"IP {ip} MAC changed: {old} -> {mac}",
                ))

                # Check for duplicate MAC on different IPs (conflict)
                for ip2, mac2 in cur.items():
                    if ip2 != ip and mac2 == mac and not _is_special_mac(mac2) and ip2 not in ("255.255.255.255", "0.0.0.0"):
                        events.append(DetectionEvent(
                            timestamp=now,
                            level="CRITICAL",
                            category="IP_CONFLICT",
                            message=f"MAC conflict: {mac} assigned to {ip} AND {ip2} (possible spoof)",
                        ))

                # Check for duplicate MAC on different IPs (conflict)
                for ip2, mac2 in cur.items():
                    if ip2 != ip and mac2 == mac and ip2 not in ("255.255.255.255", "0.0.0.0"):
                        events.append(DetectionEvent(
                            timestamp=now,
                            level="CRITICAL",
                            category="IP_CONFLICT",
                            message=f"MAC conflict: {mac} assigned to {ip} AND {ip2} (possible spoof)",
                        ))

        # 2. Gateway MAC baseline check
        if gateway_ip and gateway_ip in cur:
            cur_gw = cur[gateway_ip]
            if gw_mac is None:
                gw_mac = cur_gw
                events.append(DetectionEvent(
                    timestamp=now,
                    level="INFO",
                    category="GATEWAY_BASELINE",
                    message=f"Gateway {gateway_ip} MAC baseline set: {gw_mac}",
                ))
            elif cur_gw != gw_mac:
                events.append(DetectionEvent(
                    timestamp=now,
                    level="CRITICAL",
                    category="GATEWAY_SPOOF",
                    message=f"Gateway MAC changed: {gw_mac} -> {cur_gw} (possible ARP spoofing)",
                ))
                gw_mac = cur_gw

        # 3. Global duplicate MAC check (any two IPs sharing same MAC in current snapshot)
        mac_to_ip: dict[str, str] = {}
        for ip, mac in cur.items():
            if mac in mac_to_ip:
                other_ip = mac_to_ip[mac]
                events.append(DetectionEvent(
                    timestamp=now,
                    level="WARN",
                    category="IP_CONFLICT",
                    message=f"MAC conflict: {mac} assigned to {other_ip} AND {ip} (possible IP spoof/conflict)",
                ))
            else:
                mac_to_ip[mac] = ip

        with self._lock:
            self._last_arp = cur.copy()
            self._gw_mac_baseline = gw_mac

        # 3. Unknown device alerts (skip special)
        for ip, mac in cur.items():
            if ip in ("255.255.255.255", "0.0.0.0") or _is_special_mac(mac):
                continue
            key = mac.lower()
            if key not in self._known_devices:
                events.append(DetectionEvent(
                    timestamp=now,
                    level="INFO",
                    category="NEW_DEVICE",
                    message=f"New/unknown device detected: {ip} -> {mac} (consider adding to baseline)",
                ))
                self.add_known_device(mac, ip)

        return events

    # ─── Wi-Fi / Evil Twin Detection ─────────────────────────────────────
    def check_wifi_networks(
        self,
        networks: list[WifiNetwork],
    ) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Build SSID -> list of BSSIDs map
        ssid_map: dict[str, list[WifiNetwork]] = {}
        for net in networks:
            ssid_key = (net.ssid or "").strip().lower()
            ssid_map.setdefault(ssid_key, []).append(net)

        # 1. Open/WEP warnings
        for net in networks:
            if net.is_open():
                events.append(DetectionEvent(
                    timestamp=now,
                    level="WARN",
                    category="OPEN_WIFI",
                    message=f"Open/unencrypted Wi-Fi: '{net.ssid}' ({net.bssid or 'unknown'})",
                ))
            if net.is_wep():
                events.append(DetectionEvent(
                    timestamp=now,
                    level="WARN",
                    category="WEP_WIFI",
                    message=f"WEP-secured Wi-Fi (insecure): '{net.ssid}' ({net.bssid or 'unknown'})",
                ))

        # 2. Evil Twin / Rogue AP detection
        for ssid_key, nets in ssid_map.items():
            if len(nets) > 1:
                # Multiple BSSIDs with same SSID
                bssids = [(n.bssid or "??", n.signal_dbm) for n in nets]
                events.append(DetectionEvent(
                    timestamp=now,
                    level="WARN",
                    category="EVIL_TWIN",
                    message=f"Multiple APs for SSID '{ssid_key}': {bssids} (possible evil twin / AP duplication)",
                ))

                # Check signal anomaly: if one AP's signal is significantly different
                # This could indicate a rogue AP with higher power
                signals = [s for _, s in bssids if s is not None]
                if len(signals) >= 2:
                    avg = sum(signals) / len(signals)
                    for bssid, sig in bssids:
                        if sig is not None and abs(sig - avg) > 15:  # >15 dBm diff
                            events.append(DetectionEvent(
                                timestamp=now,
                                level="WARN",
                                category="SIGNAL_ANOMALY",
                                message=f"BSSID {bssid} signal anomaly ({sig} dBm vs avg {avg:.0f}) – possible rogue/jammer",
                            ))

        return events

    # ─── Jammer / Deauth Detection ────────────────────────────────────────
    def check_for_jammer(
        self,
        current_aps: list[WifiNetwork],
        previous_aps: list[WifiNetwork],
    ) -> list[DetectionEvent]:
        """Heuristic: sudden disappearance of many APs + signal drop suggests jammer."""
        events: list[DetectionEvent] = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        prev_by_bssid = {n.bssid.lower(): n for n in previous_aps if n.bssid}
        cur_by_bssid = {n.bssid.lower(): n for n in current_aps if n.bssid}

        # APs that vanished between scans
        disappeared = [b for b in prev_by_bssid if b not in cur_by_bssid]
        appeared = [b for b in cur_by_bssid if b not in prev_by_bssid]

        # If many disappeared simultaneously with many new, could be deauth attack or scan error
        if len(disappeared) > 3 and len(appeared) > 3:
            events.append(DetectionEvent(
                timestamp=now,
                level="WARN",
                category="DEAUTH_POSSIBLE",
                message=f"Mass AP change: {len(disappeared)} disappeared, {len(appeared)} appeared (possible deauth/jammer attack or channel scan issue)",
            ))

        return events

    # ─── Event Recording ───────────────────────────────────────────────────
    def record_events(self, events: list[DetectionEvent]) -> None:
        for ev in events:
            log.log(
                getattr(logging, ev.level),
                "[%s] %s: %s",
                ev.category,
                ev.level,
                ev.message,
            )
            self._events.append(ev)
            if self._db:
                self._db.insert_event(ev)
            if self._notifier and ev.level in self._notify_levels:
                self._notifier.send(f"arpscout – {ev.level}", ev.message)

    def get_events(self, clear: bool = False) -> list[DetectionEvent]:
        with self._lock:
            evs = self._events.copy()
            if clear:
                self._events.clear()
        return evs

    def set_baseline_wifi(self, networks: list[WifiNetwork]) -> None:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._ap_baseline.clear()
        for n in networks:
            if n.bssid:
                self._ap_baseline[n.bssid.lower()] = n
                if self._db:
                    self._db.upsert_network(n, now)
        log.info("Wi-Fi baseline updated: %d APs", len(self._ap_baseline))

    def get_stats(self) -> dict[str, Any]:
        return {
            "known_devices": len(self._known_devices),
            "ap_baseline_count": len(self._ap_baseline),
            "recent_events": len(self._events),
            "platform": sys.platform,
        }


# ──────────────────────────── Continuous Watch ────────────────────────────
class ArpWatch:
    def __init__(
        self,
        engine: DetectionEngine,
        interval: float = 2.0,
        gateway_ip: str | None = None,
        max_events: int | None = None,
        wifi_scan_interval: int = 6,
    ) -> None:
        self.engine = engine
        self.interval = max(0.5, interval)
        self.gateway_ip = gateway_ip
        self.max_events = max_events
        self.wifi_scan_interval = max(1, wifi_scan_interval)
        self._running = False
        self._thread: threading.Thread | None = None
        self._last_networks: list[WifiNetwork] = []

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def _run(self) -> None:
        log.info("ARP+WiFi watch started. Interval=%.1fs Gateway=%s", self.interval, self.gateway_ip or "auto")
        gw = self.gateway_ip or default_gateway()
        log.info("Effective gateway: %s", gw or "none")
        events = 0
        wifi_tick = 0

        # Take initial Wi-Fi baseline
        self._last_networks = wifi_scan()
        self.engine.set_baseline_wifi(self._last_networks)

        prev_arp: dict[str, str] = {}

        try:
            while self._running:
                now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # 1. ARP snapshot & diff (every cycle)
                cur_arp = arp_snapshot()
                if cur_arp:
                    arp_events = self.engine.check_arp_changes(prev_arp, cur_arp, gw)
                    self.engine.record_events(arp_events)
                    for ev in arp_events:
                        log.log(getattr(logging, ev.level), "%s", ev.message)
                        events += 1
                    prev_arp = cur_arp
                else:
                    log.debug("No ARP entries in this cycle")

                # 2. Periodic Wi-Fi scan + detection
                wifi_tick += 1
                if wifi_tick >= self.wifi_scan_interval:
                    wifi_tick = 0
                    cur_nets = wifi_scan()
                    wifi_events = self.engine.check_wifi_networks(cur_nets)
                    if self._last_networks:
                        jammer_events = self.engine.check_for_jammer(cur_nets, self._last_networks)
                        wifi_events.extend(jammer_events)
                    self.engine.record_events(wifi_events)
                    for ev in wifi_events:
                        log.log(getattr(logging, ev.level), "%s", ev.message)
                        events += 1
                    self._last_networks = cur_nets

                if self.max_events is not None and events >= self.max_events:
                    log.info("max-events reached (%d), stopping", self.max_events)
                    break

                time.sleep(self.interval)

        except KeyboardInterrupt:
            log.info("Interrupted by user")
        finally:
            self._running = False
            log.info("Watch stopped – total events: %d", events)


# ──────────────────────────── ARP Sniffer ──────────────────────────────────
class ArpSniffer:
    """Live ARP packet sniffing for instant spoof detection (requires Scapy + Npcap/ libpcap)."""

    def __init__(
        self,
        engine: DetectionEngine,
        iface: str | None = None,
        max_packets: int | None = None,
        timeout: int | None = None,
    ) -> None:
        self.engine = engine
        self.iface = iface
        self.max_packets = max_packets
        self.timeout = timeout
        self._running = False
        self._thread: threading.Thread | None = None
        self._packet_count = 0

    def start(self) -> None:
        if self._running:
            return
        if not SCAPY_AVAILABLE:
            log.error("Scapy is not available – cannot start sniffer.")
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_sniff, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def _run_sniff(self) -> None:
        log.info("Starting ARP sniffer on interface: %s", self.iface or "auto")
        from scapy.all import sniff, ARP

        # Volatile caches for live detection (not persisted)
        live_arp: dict[str, str] = {}       # ip -> mac (from packets)
        mac_to_ip: dict[str, str] = {}       # mac -> ip (from packets)
        pkt_counts: dict[str, int] = {}      # mac -> packet count (for flood detection)
        flood_threshold = 50  # packets in 1 second considered flood

        def process_packet(pkt) -> None:
            if not self._running:
                return
            if ARP not in pkt:
                return
            arp = pkt[ARP]
            psrc = arp.psrc
            hwsrc = arp.hwsrc
            pdst = arp.pdst
            op = arp.op  # 1=who-has, 2=is-at

            if not psrc or not hwsrc:
                return

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._packet_count += 1

            # 1. Live IP->MAC conflict: same IP seen with different MAC
            if psrc in live_arp:
                old_mac = live_arp[psrc]
                if old_mac != hwsrc:
                    msg = (f"Live ARP conflict: IP {psrc} MAC changed {old_mac} -> {hwsrc} "
                           f"(op={op}, packet #{self._packet_count})")
                    ev = DetectionEvent(timestamp=now, level="WARN", category="ARP_SPOOF_LIVE", message=msg)
                    self.engine.record_events([ev])
            live_arp[psrc] = hwsrc

            # 2. MAC used for multiple IPs simultaneously
            if hwsrc in mac_to_ip:
                old_ip = mac_to_ip[hwsrc]
                if old_ip != psrc:
                    msg = (f"MAC conflict: {hwsrc} associated with multiple IPs: {old_ip} and {psrc} "
                           f"(op={op}, packet #{self._packet_count})")
                    ev = DetectionEvent(timestamp=now, level="WARN", category="MAC_CONFLICT_LIVE", message=msg)
                    self.engine.record_events([ev])
            mac_to_ip[hwsrc] = psrc

            # 3. Gratuitous ARP detection
            #  - ARP request where sender IP equals target IP
            #  - ARP reply where sender IP equals target IP
            if psrc and pdst and psrc == pdst:
                msg = f"Gratuitous ARP: {psrc} ({hwsrc}) op={op}"
                level = "INFO"
                # Gratuitous ARP can be normal but also used in attacks; mark as INFO unless frequent?
                ev = DetectionEvent(timestamp=now, level=level, category="GRATUITOUS_ARP", message=msg)
                self.engine.record_events([ev])

            # 4. ARP flood detection (per-MAC)
            pkt_counts[hwsrc] = pkt_counts.get(hwsrc, 0) + 1
            # Reset counts every second? Hard without scheduler; simple: if count > threshold -> alert and reset
            if pkt_counts[hwsrc] >= flood_threshold:
                msg = f"ARP flood from {hwsrc}: {pkt_counts[hwsrc]} packets in session"
                ev = DetectionEvent(timestamp=now, level="WARN", category="ARP_FLOOD", message=msg)
                self.engine.record_events([ev])
                pkt_counts[hwsrc] = 0  # reset to avoid spam

            # Stop condition: max_packets
            if self.max_packets and self._packet_count >= self.max_packets:
                self._running = False

        try:
            sniff(iface=self.iface, filter="arp", prn=process_packet, store=0, timeout=self.timeout if self.timeout else None)
        except Exception as e:
            log.error("ARP sniffer failed: %s", e)
        finally:
            self._running = False
            log.info("ARP sniffer stopped – total packets: %d", self._packet_count)


# ──────────────────────────── CLI Entry Point ─────────────────────────────
def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="arpscout",
        description="Defensive network monitoring: Wi-Fi, ARP spoof, MITM, jammer detection.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Global options for commands that need them
    parser.add_argument("--db", type=str, default=None, help="SQLite DB path (optional persistence)")
    parser.add_argument("--notify", action="store_true", help="Enable desktop notifications for alerts")

    # wifi-scan
    ps = sub.add_parser("wifi-scan", help="Scan and list visible Wi-Fi networks with security analysis.")

    # arp-watch
    paw = sub.add_parser("arp-watch", help="Passively watch ARP table for spoofing indicators.")
    paw.add_argument("--interval", type=float, default=2.0, help="Polling interval seconds (default: 2.0)")
    paw.add_argument("--gateway", type=str, default=None, help="Gateway IP to monitor (auto-detected if omitted)")
    paw.add_argument("--max-events", type=int, default=None, help="Stop after N events (default: unlimited)")
    paw.add_argument("--wifi-interval", type=int, default=6, help="Wi-Fi scan interval (cycles between ARP checks, default: 6)")

    # arp-sniff (live packet capture)
    psniff = sub.add_parser("arp-sniff", help="Live ARP packet sniffing for instant spoof detection (requires Scapy + Npcap).")
    psniff.add_argument("--iface", type=str, default=None, help="Network interface (default: auto)")
    psniff.add_argument("--timeout", type=int, default=0, help="Stop after N seconds (0=unlimited)")
    psniff.add_argument("--max-pkts", type=int, default=0, help="Stop after N packets (0=unlimited)")

    # learn-baseline
    plearn = sub.add_parser("learn-baseline", help="Learn current devices as known baseline.")
    plearn.add_argument("--label", type=str, default="baseline", help="Label for baseline snapshot")

    # stats
    pstat = sub.add_parser("stats", help="Show detection stats and known-device count.")

    # export
    pexp = sub.add_parser("export", help="Export events log to CSV/JSON.")
    pexp.add_argument("--file", type=str, default="arpscout_export.csv", help="Output filename")
    pexp.add_argument("--format", type=str, choices=["csv", "json", "txt"], default="csv", help="Export format")
    pexp.add_argument("--limit", type=int, default=1000, help="Max events to export")

    args = parser.parse_args(argv)

    # Initialize optional components
    db = None
    if args.db and SQLITE_AVAILABLE:
        db = DBOperator(Path(args.db))
    elif SQLITE_AVAILABLE:
        db = DBOperator()  # default path

    notifier = None
    if args.notify and Notifier.available():
        notifier = Notifier()
    elif args.notify:
        log.warning("Notifications not available on this platform (missing dependencies)")

    engine = DetectionEngine(db=db, notifier=notifier)

    if args.cmd == "wifi-scan":
        log.info("Running Wi-Fi scan…")
        nets = wifi_scan()
        if not nets:
            print("No Wi-Fi networks detected.")
            return 1
        print(f"\nVisible Wi-Fi networks ({len(nets)}):")
        print("-" * 80)
        for n in sorted(nets, key=lambda x: (x.ssid or "").lower()):
            risk = " | ".join(n.risk_flags) if n.risk_flags else "OK"
            print(f"- SSID: {n.ssid!r:30}  BSSID: {n.bssid or '??':17}  "
                  f"Ch:{str(n.channel or '-'):>3}  RSSI:{str(n.signal_dbm or '-'):>4}dBm  "
                  f"Auth:{n.authentication or '?':8} Enc:{n.encryption or '?':8}  [{risk}]")
        return 0

    if args.cmd == "arp-sniff":
        if not SCAPY_AVAILABLE:
            log.error("Scapy is not installed. Install with: pip install scapy")
            return 2
        sniffer = ArpSniffer(
            engine=engine,
            iface=args.iface,
            max_packets=args.max_pkts if args.max_pkts > 0 else None,
            timeout=args.timeout if args.timeout > 0 else None,
        )
        sniffer.start()
        try:
            while sniffer._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            sniffer.stop()
        return 0

    if args.cmd == "arp-watch":
        watch = ArpWatch(
            engine=engine,
            interval=args.interval,
            gateway_ip=args.gateway,
            max_events=args.max_events,
            wifi_scan_interval=args.wifi_interval,
        )
        watch.start()
        try:
            while watch._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            watch.stop()
        return 0

    if args.cmd == "learn-baseline":
        cur = arp_snapshot()
        if not cur:
            print("ARP table empty – cannot learn baseline.")
            return 1
        engine.learn_baseline_from_arp(cur)
        print(f"Baseline saved. {len(engine._known_devices)} devices learned.")
        return 0

    if args.cmd == "stats":
        st = engine.get_stats()
        print(json.dumps(st, indent=2))
        return 0

    if args.cmd == "export":
        events = engine.get_events(clear=False)
        if args.limit and len(events) > args.limit:
            events = events[:args.limit]
        if not events:
            print("No events to export.")
            return 1
        path = args.file
        if args.format == "csv":
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Level", "Category", "Message"])
                for ev in events:
                    writer.writerow([ev.timestamp, ev.level, ev.category, ev.message])
        elif args.format == "json":
            data = [ev.__dict__ for ev in events]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        else:  # txt
            with open(path, "w", encoding="utf-8") as f:
                for ev in events:
                    f.write(f"[{ev.timestamp}] {ev.level} [{ev.category}] {ev.message}\n")
        print(f"Exported {len(events)} events to {path}")
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
