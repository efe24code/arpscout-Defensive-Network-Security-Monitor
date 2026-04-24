import json
import os
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import arpscout

# Optional matplotlib
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Optional win10toast
try:
    from win10toast import ToastNotifier
    WIN10TOAST_AVAILABLE = True
except ImportError:
    WIN10TOAST_AVAILABLE = False


# ──────────────────────────── GUI Application ──────────────────────────────
class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("arpscout – Defensive Network Monitor")
        self.geometry("1350x800")
        self.configure(padx=8, pady=8)

        # State
        self._running = False
        self._sniffing = False
        self._watch_thread: threading.Thread | None = None
        self._sniffer_thread: threading.Thread | None = None
        self._sniffer: arpscout.ArpSniffer | None = None
        self._engine: arpscout.DetectionEngine | None = None
        self._db: arpscout.DBOperator | None = None
        self._notifier: arpscout.Notifier | None = None
        self._last_networks: list[arpscout.WifiNetwork] = []
        self._gateway_ip: str | None = None
        self._auto_refresh = tk.BooleanVar(value=True)
        self._graph_data: dict[str, list[tuple[datetime, int]]] = {}  # bssid -> [(time, rssi)]

        # Settings
        self._settings_file = Path.home() / ".arpscout" / "gui_settings.json"
        self._settings = self._load_settings()

        self._build_ui()
        self._create_menu()

        # Auto-start
        self.after(200, self._auto_start)

    # ─── Settings ──────────────────────────────────────────────────────────
    def _load_settings(self) -> dict:
        path = self._settings_file
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "interval": 2.0,
            "gateway": "",
            "auto_start": True,
            "log_limit": 5000,
            "scan_wifi_interval": 30,
            "alert_popup": True,
            "sound_alerts": False,
            "enable_db": True,
            "db_path": str(Path.home() / ".arpscout" / "arpscout.db"),
            "enable_notifications": False,
            "notify_levels": ["CRITICAL", "WARN"],
        }

    def _save_settings(self) -> None:
        self._settings.update({
            "interval": self._get_interval(),
            "gateway": self.gateway_var.get().strip(),
            "auto_start": self._auto_start_var.get(),
            "scan_wifi_interval": self._get_wifi_interval(),
            "alert_popup": self._alert_popup_var.get(),
            "sound_alerts": self._sound_alerts_var.get(),
            "enable_db": self._enable_db_var.get(),
            "db_path": self._db_path_var.get().strip(),
            "enable_notifications": self._enable_notify_var.get(),
        })
        self._settings_file.parent.mkdir(parents=True, exist_ok=True)
        with self._settings_file.open("w", encoding="utf-8") as f:
            json.dump(self._settings, f, indent=2)

    def _get_interval(self) -> float:
        try:
            return float(self.interval_var.get().strip())
        except Exception:
            return 2.0

    def _get_wifi_interval(self) -> int:
        try:
            return int(self._settings.get("scan_wifi_interval", 30))
        except Exception:
            return 30

    # ─── Menu ──────────────────────────────────────────────────────────────
    def _create_menu(self) -> None:
        menubar = tk.Menu(self)

        # File menu
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Wi-Fi Scan Now", command=self.wifi_scan)
        filem.add_command(label="ARP Snapshot", command=self.show_arp_snapshot)
        filem.add_separator()
        filem.add_command(label="Set Baseline (Learn)", command=self.set_baseline)
        filem.add_command(label="Learn from ARP", command=self.learn_baseline_arp)
        filem.add_separator()
        filem.add_command(label="Export Log…", command=self._export_log)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=filem)

        # View menu
        viewm = tk.Menu(menubar, tearoff=0)
        viewm.add_command(label="Clear Log", command=self._clear_log)
        viewm.add_command(label="Show Statistics", command=self.show_stats)
        viewm.add_command(label="List Known Devices…", command=self.show_known_devices)
        viewm.add_command(label="List Wi-Fi Networks (Baseline)", command=self.show_wifi_baseline)
        viewm.add_separator()
        viewm.add_checkbutton(label="Auto-refresh Status", variable=self._auto_refresh, onvalue=True, offvalue=False)
        if MATPLOTLIB_AVAILABLE:
            viewm.add_separator()
            viewm.add_command(label="Show Signal Graph", command=self._show_signal_graph)
        menubar.add_cascade(label="View", menu=viewm)

        # Tools menu
        toolsm = tk.Menu(menubar, tearoff=0)
        toolsm.add_command(label="Settings…", command=self._open_settings)
        toolsm.add_command(label="Reset All Data", command=self._reset_all_data)
        toolsm.add_separator()
        toolsm.add_command(label="Manually Add Device", command=self._add_device_manual)
        toolsm.add_command(label="Remove Device by MAC", command=self._remove_device)
        menubar.add_cascade(label="Tools", menu=toolsm)

        # Help menu
        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=helpm)

        self.config(menu=menubar)

    # ─── UI Layout ─────────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        # ── Top control bar ──────────────────────────────────────────────────
        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 6))

        # Gateway
        ttk.Label(top, text="Gateway IP:").pack(side="left")
        self.gateway_var = tk.StringVar(value=str(arpscout.default_gateway() or ""))
        ttk.Entry(top, textvariable=self.gateway_var, width=16).pack(side="left", padx=(0, 10))

        # Interval
        ttk.Label(top, text="ARP Interval (s):").pack(side="left")
        self.interval_var = tk.StringVar(value=str(self._settings.get("interval", 2.0)))
        ttk.Entry(top, textvariable=self.interval_var, width=6).pack(side="left", padx=(0, 10))

        # Start / Stop
        self.start_btn = ttk.Button(top, text="▶ Start Watch", command=self.start_watch)
        self.start_btn.pack(side="left", padx=(0, 4))
        self.stop_btn = ttk.Button(top, text="■ Stop", command=self.stop_watch, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 10))

        # Quick actions
        ttk.Button(top, text="Wi-Fi Scan", command=self.wifi_scan).pack(side="left", padx=(0, 4))
        ttk.Button(top, text="ARP Snapshot", command=self.show_arp_snapshot).pack(side="left", padx=(0, 4))
        ttk.Button(top, text="Set Baseline", command=self.set_baseline).pack(side="left", padx=(0, 4))
        ttk.Button(top, text="Stats", command=self.show_stats).pack(side="left", padx=(0, 4))

        # ── Main area: split pane ────────────────────────────────────────────
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, pady=(6, 0))

        # Left: Log view
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=3)

        ttk.Label(left_frame, text="Event Log:").pack(anchor="w")
        self.log = tk.Text(left_frame, wrap="word", font=("Consolas", 10), height=20)
        self.log.pack(side="left", fill="both", expand=True)
        scroll_y = ttk.Scrollbar(left_frame, orient="vertical", command=self.log.yview)
        scroll_y.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=scroll_y.set)
        scroll_x = ttk.Scrollbar(left_frame, orient="horizontal", command=self.log.xview)
        scroll_x.pack(side="bottom", fill="x")
        self.log.configure(xscrollcommand=scroll_x.set)

        # Tag configurations for colored levels
        self.log.tag_config("CRITICAL", foreground="red", font=("Consolas", 10, "bold"))
        self.log.tag_config("WARN", foreground="orange")
        self.log.tag_config("INFO", foreground="green")

        # Right: Status/Info panel
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=1)

        # Status group
        status_group = ttk.LabelFrame(right_frame, text="Status", padding=10)
        status_group.pack(fill="x", pady=(0, 8))
        self.status_lbl = ttk.Label(status_group, text="Ready")
        self.status_lbl.pack(anchor="w")
        self.gateway_status_lbl = ttk.Label(status_group, text="Gateway: (none)")
        self.gateway_status_lbl.pack(anchor="w")
        self.arp_count_lbl = ttk.Label(status_group, text="ARP entries: 0")
        self.arp_count_lbl.pack(anchor="w")
        self.wifi_count_lbl = ttk.Label(status_group, text="Wi-Fi networks: 0")
        self.wifi_count_lbl.pack(anchor="w")
        self.known_devices_lbl = ttk.Label(status_group, text="Known devices: 0")
        self.known_devices_lbl.pack(anchor="w")
        self.events_lbl = ttk.Label(status_group, text="Events (this session): 0")
        self.events_lbl.pack(anchor="w")
        self.db_status_lbl = ttk.Label(status_group, text="DB: disabled")
        self.db_status_lbl.pack(anchor="w")
        self.notify_status_lbl = ttk.Label(status_group, text="Notify: disabled")
        self.notify_status_lbl.pack(anchor="w")
        self.sniffer_status_lbl = ttk.Label(status_group, text="Sniffer: stopped")
        self.sniffer_status_lbl.pack(anchor="w")

        # Quick controls group
        ctrl_group = ttk.LabelFrame(right_frame, text="Quick Controls", padding=10)
        ctrl_group.pack(fill="x", pady=(0, 8))
        ttk.Button(ctrl_group, text="Set Baseline", command=self.set_baseline).pack(fill="x", pady=2)
        ttk.Button(ctrl_group, text="Clear Baseline", command=self.clear_baseline).pack(fill="x", pady=2)
        ttk.Button(ctrl_group, text="List Known Devices", command=self.show_known_devices).pack(fill="x", pady=2)
        ttk.Button(ctrl_group, text="Export Log…", command=self._export_log).pack(fill="x", pady=2)
        ttk.Button(ctrl_group, text="Show Stats", command=self.show_stats).pack(fill="x", pady=2)
        if MATPLOTLIB_AVAILABLE:
            ttk.Button(ctrl_group, text="Signal Graph", command=self._show_signal_graph).pack(fill="x", pady=2)
        # Sniffer controls (only if scapy available)
        if arpscout.SCAPY_AVAILABLE:
            self.start_sniff_btn = ttk.Button(ctrl_group, text="Start ARP Sniffer", command=self.start_sniffer)
            self.start_sniff_btn.pack(fill="x", pady=2)
            self.stop_sniff_btn = ttk.Button(ctrl_group, text="Stop ARP Sniffer", command=self.stop_sniffer, state="disabled")
            self.stop_sniff_btn.pack(fill="x", pady=2)
        else:
            ttk.Label(ctrl_group, text="(ARP sniffer: scapy/Npcap needed)", foreground="gray").pack(fill="x", pady=2)

        # Wi-Fi baseline group
        wifi_group = ttk.LabelFrame(right_frame, text="Wi-Fi Networks (Last Scan)", padding=10)
        wifi_group.pack(fill="both", expand=True)
        self.wifi_tree = ttk.Treeview(wifi_group, columns=("SSID", "BSSID", "Ch", "RSSI", "Sec"), show="headings", height=12)
        self.wifi_tree.heading("SSID", text="SSID")
        self.wifi_tree.heading("BSSID", text="BSSID")
        self.wifi_tree.heading("Ch", text="Ch")
        self.wifi_tree.heading("RSSI", text="RSSI")
        self.wifi_tree.heading("Sec", text="Security")
        self.wifi_tree.column("SSID", width=120)
        self.wifi_tree.column("BSSID", width=110)
        self.wifi_tree.column("Ch", width=35)
        self.wifi_tree.column("RSSI", width=50)
        self.wifi_tree.column("Sec", width=70)
        self.wifi_tree.pack(fill="both", expand=True)

        # ── Status bar ───────────────────────────────────────────────────────
        status = ttk.Frame(self, relief="sunken", padding=4)
        status.pack(fill="x", side="bottom")
        self.status_lbl_bottom = ttk.Label(status, text="Ready")
        self.status_lbl_bottom.pack(side="left")

    # ─── Auto-start ─────────────────────────────────────────────────────────
    def _auto_start(self) -> None:
        if self._settings.get("auto_start", True):
            self._init_engine()
            self.append_log("Auto: loading known devices…")
            count = len(self._engine._known_devices) if self._engine else 0
            self.append_log(f"Loaded {count} known device(s) from baseline.")
            self.append_log("Auto: performing initial Wi-Fi scan…")
            self.wifi_scan()
            self.start_watch()

    def _init_engine(self) -> None:
        """Create DB, Notifier, and DetectionEngine based on settings."""
        db = None
        if self._settings.get("enable_db", True) and arpscout.SQLITE_AVAILABLE:
            db_path = Path(self._settings.get("db_path", ""))
            if not db_path:
                db_path = Path.home() / ".arpscout" / "arpscout.db"
            self._db = arpscout.DBOperator(db_path)
            db = self._db
            self.db_status_lbl.config(text=f"DB: {db_path.name}")
        else:
            self.db_status_lbl.config(text="DB: disabled")

        notifier = None
        if self._settings.get("enable_notifications", False):
            if arpscout.Notifier.available():
                self._notifier = arpscout.Notifier()
                notifier = self._notifier
                self.notify_status_lbl.config(text="Notify: enabled")
            else:
                self.notify_status_lbl.config(text="Notify: unavailable")
                self.append_log("Notifications not available on this platform")
        else:
            self.notify_status_lbl.config(text="Notify: disabled")

        self._engine = arpscout.DetectionEngine(db=db, notifier=notifier)

    # ─── Logging ────────────────────────────────────────────────────────────
    def append_log(self, msg: str, level: str = "INFO", popup: bool = False) -> None:
        """Append colored message to log widget."""
        ts = datetime.now().strftime("%H:%M:%S")
        full = f"[{ts}] {msg}\n"
        self.log.insert("end", full, level)
        self.log.see("end")
        # Limit log size
        limit = self._settings.get("log_limit", 5000)
        lines = int(self.log.index("end-1c").split(".")[0])
        if lines > limit:
            self.log.delete("1.0", f"{lines - limit + 1}.0")
        # Popup for critical/warn if enabled
        if popup and self._settings.get("alert_popup", True) and level in ("CRITICAL", "WARN"):
            self.after(50, lambda: messagebox.showwarning(f"Alert – {level}", msg))

    def _clear_log(self) -> None:
        self.log.delete("1.0", "end")

    # ─── Wi-Fi Scan ─────────────────────────────────────────────────────────
    def wifi_scan(self) -> None:
        self.append_log("Scanning Wi-Fi networks…")
        nets = arpscout.wifi_scan()
        self._last_networks = nets
        # Update Wi-Fi tree
        for item in self.wifi_tree.get_children():
            self.wifi_tree.delete(item)
        if not nets:
            self.append_log("Wi-Fi scan: no networks detected.")
            self.wifi_count_lbl.config(text="Wi-Fi networks: 0")
            return

        self.append_log(f"Wi-Fi scan: {len(nets)} network(s) found.")
        for n in sorted(nets, key=lambda x: (x.ssid or "").lower()):
            risk = ", ".join(n.risk_flags) if n.risk_flags else "OK"
            color_tag = "WARN" if n.risk_flags else "INFO"
            self.append_log(
                f"Wi-Fi: {n.ssid!r:30} BSSID={n.bssid}  Ch={n.channel or '-'}  "
                f"RSSI={n.signal_dbm or '-'}dBm  Auth={n.authentication or '?'}  "
                f"Enc={n.encryption or '?'}  [{risk}]",
                level=color_tag,
            )
            self.wifi_tree.insert("", "end", values=(
                n.ssid[:30],
                n.bssid or "??",
                str(n.channel or "-"),
                str(n.signal_dbm or "-"),
                f"{n.authentication or '?'}/{n.encryption or '?'}"
            ))
        self.wifi_count_lbl.config(text=f"Wi-Fi networks: {len(nets)}")

        # Update graph data
        if MATPLOTLIB_AVAILABLE and self._graph_data is not None:
            now = datetime.now()
            for n in nets:
                if n.bssid and n.signal_dbm is not None:
                    self._graph_data.setdefault(n.bssid.lower(), []).append((now, n.signal_dbm))
                    # Keep last 100 points
                    self._graph_data[n.bssid.lower()] = self._graph_data[n.bssid.lower()][-100:]

    # ─── ARP Snapshot ───────────────────────────────────────────────────────
    def show_arp_snapshot(self) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        cur = arpscout.arp_snapshot()
        if not cur:
            self.append_log(f"[{now}] ARP table empty.")
            self.arp_count_lbl.config(text="ARP entries: 0")
            return

        gw_ip = self.gateway_var.get().strip() or arpscout.default_gateway() or ""
        self.append_log(f"[{now}] ARP snapshot ({len(cur)} entries):")
        if gw_ip and gw_ip in cur:
            self.append_log(f"  Gateway {gw_ip} → {cur[gw_ip]}", level="WARN")

        shown = 0
        for ip, mac in sorted(cur.items()):
            self.append_log(f"  {ip:15} → {mac}")
            shown += 1
            if shown >= 30:
                self.append_log("  … (truncated)")
                break
        self.arp_count_lbl.config(text=f"ARP entries: {len(cur)}")

    # ─── Baseline ───────────────────────────────────────────────────────────
    def set_baseline(self) -> None:
        cur = arpscout.arp_snapshot()
        if not cur:
            messagebox.showwarning("Baseline", "ARP table is empty – cannot set baseline.")
            return
        if self._engine:
            self._engine.learn_baseline_from_arp(cur)
            self.known_devices_lbl.config(text=f"Known devices: {len(self._engine._known_devices)}")
            self.append_log(f"Baseline set – {len(self._engine._known_devices)} known devices.")
            messagebox.showinfo("Baseline", f"Baseline saved with {len(self._engine._known_devices)} devices.")

    def clear_baseline(self) -> None:
        if messagebox.askyesno("Clear Baseline", "Delete all known devices?"):
            if self._engine:
                self._engine._known_devices.clear()
                self._engine._save_known_devices()
            self.known_devices_lbl.config(text="Known devices: 0")
            self.append_log("Baseline cleared.")

    def learn_baseline_arp(self) -> None:
        cur = arpscout.arp_snapshot()
        if self._engine:
            self._engine.learn_baseline_from_arp(cur)
            self.known_devices_lbl.config(text=f"Known devices: {len(self._engine._known_devices)}")
            self.append_log(f"Learned {len(cur)} devices from current ARP table.")

    # ─── Watch Control ──────────────────────────────────────────────────────
    def start_watch(self) -> None:
        if self._running:
            return
        if not self._engine:
            self._init_engine()
        interval = self._get_interval()
        gw = self.gateway_var.get().strip() or None
        self._running = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_lbl.config(text="Monitoring…")
        self.status_lbl_bottom.config(text=f"Monitoring – Interval={interval}s | Gateway={gw or 'auto'}")

        watch = arpscout.ArpWatch(
            engine=self._engine,
            interval=interval,
            gateway_ip=gw,
            wifi_scan_interval=self._get_wifi_interval(),
        )
        watch.start()

        def monitor_events() -> None:
            try:
                while self._running:
                    if self._engine:
                        events = self._engine.get_events(clear=True)
                        event_count = 0
                        for ev in events:
                            level = ev.level
                            self.append_log(ev.message, level=level if level in ("CRITICAL", "WARN") else "INFO", popup=(level=="CRITICAL"))
                            event_count += 1
                        if event_count > 0:
                            self.events_lbl.config(text=f"Events (this session): {event_count}")
                    time.sleep(0.5)
            finally:
                watch.stop()
                self.after(0, self._watch_stopped_cb)

        threading.Thread(target=monitor_events, daemon=True).start()

    def _watch_stopped_cb(self) -> None:
        self._running = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_lbl.config(text="Stopped")
        self.status_lbl_bottom.config(text="Ready")

    def stop_watch(self) -> None:
        if self._running:
            self._running = False
            self.append_log("Stopping monitor…")

    # ─── ARP Sniffer ─────────────────────────────────────────────────────────
    def start_sniffer(self) -> None:
        if self._sniffing:
            return
        if not arpscout.SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy is not installed. Install: pip install scapy\nAlso need Npcap on Windows.")
            return
        if not self._engine:
            self._init_engine()
        iface = self._settings.get("sniff_iface")  # future: read from settings
        self._sniffing = True
        self.start_sniff_btn.configure(state="disabled")
        self.stop_sniff_btn.configure(state="normal")
        self.sniffer_status_lbl.config(text="Sniffer: running")
        self.append_log("Starting ARP sniffer…")

        def worker() -> None:
            self._sniffer = arpscout.ArpSniffer(engine=self._engine, iface=iface)
            self._sniffer.start()
            try:
                while self._sniffing:
                    time.sleep(0.5)
            finally:
                self._sniffer.stop()
                self.after(0, self._sniffer_stopped_cb)

        threading.Thread(target=worker, daemon=True).start()

    def stop_sniffer(self) -> None:
        if self._sniffing:
            self._sniffing = False
            self.append_log("Stopping ARP sniffer…")

    def _sniffer_stopped_cb(self) -> None:
        self._sniffing = False
        self.start_sniff_btn.configure(state="normal")
        self.stop_sniff_btn.configure(state="disabled")
        self.sniffer_status_lbl.config(text="Sniffer: stopped")
        self.append_log("ARP sniffer stopped.")

    # ─── Stats ──────────────────────────────────────────────────────────────
    def show_stats(self) -> None:
        if not self._engine:
            messagebox.showinfo("Stats", "Engine not initialized.")
            return
        st = self._engine.get_stats()
        info = (
            f"Platform: {st['platform']}\n"
            f"Known devices: {st['known_devices']}\n"
            f"Wi-Fi AP baseline: {st['ap_baseline_count']}\n"
            f"Recent events in memory: {st['recent_events']}\n"
            f"Monitoring interval: {self._get_interval()}s\n"
            f"Wi-Fi scan interval: {self._get_wifi_interval()}s\n"
            f"Gateway: {self.gateway_var.get() or '(auto)'}\n"
            f"DB: {'enabled' if self._db else 'disabled'}\n"
            f"Notifications: {'enabled' if self._notifier else 'disabled'}"
        )
        messagebox.showinfo("Statistics", info)

    # ─── Known Devices ──────────────────────────────────────────────────────
    def show_known_devices(self) -> None:
        """Popup window with known devices table."""
        win = tk.Toplevel(self)
        win.title("Known Devices – Baseline")
        win.geometry("750x450")
        win.transient(self)

        # Toolbar
        toolbar = ttk.Frame(win, padding=5)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Add Device Manually", command=self._add_device_manual).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Remove Selected", command=lambda: self._remove_selected_device(tree)).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Export Known Devices", command=lambda: self._export_known_devices()).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Reload", command=lambda: self._reload_known_devices(tree)).pack(side="left", padx=2)

        # Treeview
        tree = ttk.Treeview(win, columns=("MAC", "Last IP", "First Seen", "Last Seen", "Labels"), show="headings")
        tree.heading("MAC", text="MAC Address")
        tree.heading("Last IP", text="Last IP")
        tree.heading("First Seen", text="First Seen")
        tree.heading("Last Seen", text="Last Seen")
        tree.heading("Labels", text="Labels")
        tree.column("MAC", width=150)
        tree.column("Last IP", width=120)
        tree.column("First Seen", width=130)
        tree.column("Last Seen", width=130)
        tree.column("Labels", width=150)
        tree.pack(fill="both", expand=True)

        # Populate
        self._populate_known_tree(tree)

    def _populate_known_tree(self, tree: ttk.Treeview) -> None:
        for item in tree.get_children():
            tree.delete(item)
        if self._engine:
            for mac, dev in self._engine._known_devices.items():
                tree.insert("", "end", values=(
                    mac.upper(),
                    dev.ip or "-",
                    dev.first_seen,
                    dev.last_seen,
                    ", ".join(dev.labels) if dev.labels else ""
                ))

    def _reload_known_devices(self, tree: ttk.Treeview) -> None:
        if self._engine:
            self._engine._known_devices = self._engine._load_known_devices()
            self._populate_known_tree(tree)
            self.known_devices_lbl.config(text=f"Known devices: {len(self._engine._known_devices)}")

    def _add_device_manual(self) -> None:
        win = tk.Toplevel(self)
        win.title("Add Known Device")
        win.geometry("350x200")
        win.transient(self)
        win.grab_set()

        ttk.Label(win, text="MAC Address (AA:BB:CC:DD:EE:FF):").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        mac_entry = ttk.Entry(win, width=20)
        mac_entry.grid(row=0, column=1, padx=10)

        ttk.Label(win, text="Label (optional):").grid(row=1, column=0, sticky="w", padx=10, pady=10)
        label_entry = ttk.Entry(win, width=20)
        label_entry.grid(row=1, column=1, padx=10)

        def add() -> None:
            mac = mac_entry.get().strip().lower()
            label = label_entry.get().strip()
            if not arpscout.MAC_RE.match(mac.replace("-", ":").replace(":", "-")):
                messagebox.showerror("Error", "Invalid MAC address format")
                return
            if self._engine:
                self._engine.add_known_device(mac, label=label)
                self.known_devices_lbl.config(text=f"Known devices: {len(self._engine._known_devices)}")
                self.append_log(f"Added known device: {mac.upper()} ({label})")
            win.destroy()

        ttk.Button(win, text="Add", command=add).grid(row=2, column=0, columnspan=2, pady=20)

    def _remove_device(self) -> None:
        self.show_known_devices()  # Uses selection in popup

    def _remove_selected_device(self, tree: ttk.Treeview) -> None:
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Remove", "Select a device first.")
            return
        values = tree.item(sel[0], "values")
        mac = values[0].lower() if values else None
        if mac and self._engine and mac.lower() in self._engine._known_devices:
            del self._engine._known_devices[mac.lower()]
            self._engine._save_known_devices()
            self._populate_known_tree(tree)
            self.known_devices_lbl.config(text=f"Known devices: {len(self._engine._known_devices)}")
            self.append_log(f"Removed device: {mac.upper()}")

    def _export_known_devices(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")],
        )
        if not path:
            return
        if not self._engine:
            return
        devices = self._engine._known_devices
        ext = Path(path).suffix.lower()
        if ext == ".csv":
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["MAC", "Last IP", "First Seen", "Last Seen", "Labels"])
                for mac, dev in devices.items():
                    writer.writerow([mac.upper(), dev.ip or "", dev.first_seen, dev.last_seen, ", ".join(dev.labels)])
        else:
            payload = {mac: dev.__dict__ for mac, dev in devices.items()}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        self.append_log(f"Exported {len(devices)} known devices to {path}")

    # ─── Wi-Fi Baseline View ────────────────────────────────────────────────
    def show_wifi_baseline(self) -> None:
        win = tk.Toplevel(self)
        win.title("Wi-Fi AP Baseline")
        win.geometry("800x400")
        win.transient(self)

        tree = ttk.Treeview(win, columns=("BSSID", "SSID", "Channel", "RSSI", "Auth", "Enc"), show="headings")
        for col, txt, w in [("BSSID", "BSSID", 130), ("SSID", "SSID", 180), ("Channel", "Ch", 50), ("RSSI", "RSSI", 60), ("Auth", "Auth", 70), ("Enc", "Enc", 70)]:
            tree.heading(col, text=txt)
            tree.column(col, width=w)
        tree.pack(fill="both", expand=True)

        if self._engine:
            for bssid, net in self._engine._ap_baseline.items():
                tree.insert("", "end", values=(
                    bssid.upper(),
                    net.ssid,
                    str(net.channel or "-"),
                    str(net.signal_dbm or "-"),
                    net.authentication or "?",
                    net.encryption or "?",
                ))

    # ─── Signal Graph ───────────────────────────────────────────────────────
    def _show_signal_graph(self) -> None:
        if not MATPLOTLIB_AVAILABLE:
            messagebox.showinfo("Graph", "matplotlib not installed.")
            return
        win = tk.Toplevel(self)
        win.title("Wi-Fi Signal Strength Over Time")
        win.geometry("900x500")
        fig, ax = plt.subplots(figsize=(8, 4))
        canvas = FigureCanvasTkAgg(fig, win)
        canvas.get_tk_widget().pack(fill="both", expand=True)

        ax.set_title("Signal Strength (dBm) by BSSID")
        ax.set_xlabel("Time")
        ax.set_ylabel("RSSI (dBm)")
        ax.grid(True, alpha=0.3)

        for bssid, points in self._graph_data.items():
            if points:
                times = [p[0] for p in points]
                rssis = [p[1] for p in points]
                ax.plot(times, rssis, marker='o', label=bssid.upper()[:12], linewidth=1.5)

        ax.legend(loc='upper left')
        fig.autofmt_xdate()
        canvas.draw()

    # ─── Export Log ─────────────────────────────────────────────────────────
    def _export_log(self) -> None:
        filetypes = [("CSV", "*.csv"), ("JSON", "*.json"), ("Text", "*.txt")]
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=filetypes)
        if not path:
            return
        try:
            if not self._engine:
                raise ValueError("Engine not initialized")
            events = self._engine.get_events(clear=False)
            ext = Path(path).suffix.lower()
            if ext == ".csv":
                self._export_csv(path, events)
            elif ext == ".json":
                self._export_json(path, events)
            else:
                self._export_txt(path, events)
            self.append_log(f"Log exported to {path}")
            messagebox.showinfo("Export", f"Log saved to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _export_csv(self, path: str, events: list) -> None:
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Level", "Category", "Message"])
            for ev in events:
                writer.writerow([ev.timestamp, ev.level, ev.category, ev.message])

    def _export_json(self, path: str, events: list) -> None:
        data = [ev.__dict__ for ev in events]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _export_txt(self, path: str, events: list) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(f"[{ev.timestamp}] {ev.level} [{ev.category}] {ev.message}\n")

    # ─── Settings Dialog ────────────────────────────────────────────────────
    def _open_settings(self) -> None:
        win = tk.Toplevel(self)
        win.title("Settings")
        win.geometry("450x380")
        win.transient(self)
        win.grab_set()

        row = 0
        ttk.Label(win, text="ARP scan interval (seconds):").grid(row=row, column=0, sticky="w", padx=10, pady=6)
        interval_entry = ttk.Entry(win, width=12)
        interval_entry.insert(0, str(self._get_interval()))
        interval_entry.grid(row=row, column=1, padx=10)
        row += 1

        ttk.Label(win, text="Wi-Fi scan interval (cycles):").grid(row=row, column=0, sticky="w", padx=10, pady=6)
        wifi_interval_entry = ttk.Entry(win, width=12)
        wifi_interval_entry.insert(0, str(self._get_wifi_interval()))
        wifi_interval_entry.grid(row=row, column=1, padx=10)
        row += 1

        ttk.Label(win, text="Default gateway IP (blank=auto):").grid(row=row, column=0, sticky="w", padx=10, pady=6)
        gw_entry = ttk.Entry(win, width=16)
        gw_entry.insert(0, self.gateway_var.get())
        gw_entry.grid(row=row, column=1, padx=10)
        row += 1

        ttk.Label(win, text="Log line limit (max lines):").grid(row=row, column=0, sticky="w", padx=10, pady=6)
        log_limit_entry = ttk.Entry(win, width=12)
        log_limit_entry.insert(0, str(self._settings.get("log_limit", 5000)))
        log_limit_entry.grid(row=row, column=1, padx=10)
        row += 1

        ttk.Label(win, text="Database path:").grid(row=row, column=0, sticky="w", padx=10, pady=6)
        self._db_path_var = tk.StringVar(value=self._settings.get("db_path", str(Path.home() / ".arpscout" / "arpscout.db")))
        db_entry = ttk.Entry(win, textvariable=self._db_path_var, width=25)
        db_entry.grid(row=row, column=1, padx=10)
        row += 1

        self._auto_start_var = tk.BooleanVar(value=self._settings.get("auto_start", True))
        ttk.Checkbutton(win, text="Auto-start monitoring on launch", variable=self._auto_start_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=6
        )
        row += 1

        self._auto_refresh_var = tk.BooleanVar(value=self._auto_refresh.get())
        ttk.Checkbutton(win, text="Auto-refresh status panel", variable=self._auto_refresh_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=6
        )
        row += 1

        self._alert_popup_var = tk.BooleanVar(value=self._settings.get("alert_popup", True))
        ttk.Checkbutton(win, text="Show popup alerts for WARN/CRITICAL", variable=self._alert_popup_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=6
        )
        row += 1

        self._enable_db_var = tk.BooleanVar(value=self._settings.get("enable_db", True))
        ttk.Checkbutton(win, text="Enable SQLite database persistence", variable=self._enable_db_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=6
        )
        row += 1

        self._enable_notify_var = tk.BooleanVar(value=self._settings.get("enable_notifications", False))
        ttk.Checkbutton(win, text="Enable desktop notifications", variable=self._enable_notify_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=6
        )
        row += 1

        self._sound_alerts_var = tk.BooleanVar(value=self._settings.get("sound_alerts", False))
        ttk.Checkbutton(win, text="Play sound on alerts (future)", variable=self._sound_alerts_var, state="disabled").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=6
        )
        row += 1

        def save_and_close() -> None:
            try:
                interval = float(interval_entry.get().strip())
                self.interval_var.set(str(interval))
                self.gateway_var.set(gw_entry.get().strip())
                try:
                    log_limit = int(log_limit_entry.get().strip())
                    self._settings["log_limit"] = max(100, log_limit)
                except ValueError:
                    pass
                self._settings["scan_wifi_interval"] = max(0, int(wifi_interval_entry.get().strip() or "0"))
                self._auto_refresh.set(self._auto_refresh_var.get())
                self._save_settings()
                # Reinit engine with new settings
                self._init_engine()
                win.destroy()
                messagebox.showinfo("Settings", "Settings saved. Engine reinitialized.")
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid value: {e}")

        ttk.Button(win, text="Save & Close", command=save_and_close).grid(row=row, column=0, columnspan=2, pady=20)

    # ─── Reset All ───────────────────────────────────────────────────────────
    def _reset_all_data(self) -> None:
        if messagebox.askyesno("Reset All", "Delete all data (known devices, logs, settings) and restart defaults?"):
            kb = arpscout.KNOWN_DEVICES_FILE
            logs_dir = arpscout.LOG_DIR
            settings = self._settings_file
            try:
                if kb.exists():
                    kb.unlink()
                if logs_dir.exists():
                    import shutil
                    shutil.rmtree(logs_dir)
                if settings.exists():
                    settings.unlink()
                if self._db and hasattr(self._db, 'db_path') and self._db.db_path.exists():
                    self._db.db_path.unlink()
                self._engine = None
                self._db = None
                self._notifier = None
                self.append_log("All data reset – restart to apply defaults.")
                messagebox.showinfo("Reset", "All data cleared. Restart application for full reset.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reset: {e}")

    # ─── About ───────────────────────────────────────────────────────────────
    def _show_about(self) -> None:
        about = (
            "arpscout – Defensive Network Monitor\n"
            "Version 2.1\n\n"
            "Detects: ARP spoof, MITM, Evil Twin, Jammer, Deauth, Open Wi-Fi, Unknown devices\n"
            "Platforms: Windows, Linux, macOS (defensive-only)\n\n"
            "Features:\n"
            "  • Cross-platform Wi-Fi scanning\n"
            "  • Real-time ARP monitoring\n"
            "  • SQLite event storage\n"
            "  • Desktop notifications\n"
            "  • Signal strength graphs\n"
            "  • Export CSV/JSON\n\n"
            "Data stored in: ~/.arpscout/\n"
            "License: MIT"
        )
        messagebox.showinfo("About arpscout", about)

    # ─── Cleanup ────────────────────────────────────────────────────────────
    def on_closing(self) -> None:
        self.stop_watch()
        time.sleep(0.2)
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()