#!/usr/bin/env python3
"""
Network Analyzer Pro - Gelismis Ag Analiz Araci
"""

import tkinter as tk
from tkinter import ttk
import threading
import subprocess
import socket
import psutil
import ipaddress
import time
import re
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.patches as mpatches
import numpy as np

# ─── Renk Paleti ─────────────────────────────────────────────────────────────
BG       = "#0a0e1a"
BG2      = "#111827"
BG3      = "#1f2937"
BG4      = "#374151"
BLUE     = "#3b82f6"
BLUE2    = "#60a5fa"
CYAN     = "#06b6d4"
GREEN    = "#10b981"
GREEN2   = "#34d399"
ORANGE   = "#f59e0b"
RED      = "#ef4444"
PURPLE   = "#8b5cf6"
PINK     = "#ec4899"
WHITE    = "#f9fafb"
GRAY     = "#9ca3af"
GRAY2    = "#6b7280"

CHART_BG   = "#0d1425"
CHART_GRID = "#1e2d45"

VENDOR_COLORS = [BLUE, CYAN, GREEN, ORANGE, PURPLE, PINK, RED, "#14b8a6",
                 "#f97316", "#a78bfa", "#fb7185", "#4ade80"]

# ─── MAC OUI Veritabani ───────────────────────────────────────────────────────
MAC_VENDORS = {
    "00:00:0C":"Cisco",        "00:01:42":"Cisco",      "00:03:6B":"Cisco",
    "00:04:9A":"Cisco",        "00:1B:D4":"Cisco",      "00:0D:BD":"Cisco",
    "00:50:56":"VMware",       "00:0C:29":"VMware",     "00:05:69":"VMware",
    "B8:27:EB":"Raspberry Pi", "DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
    "00:1B:63":"Apple",        "3C:15:C2":"Apple",      "A4:C3:F0":"Apple",
    "00:17:F2":"Apple",        "54:EE:75":"Apple",      "F8:FF:C2":"Apple",
    "AC:BC:32":"Apple",        "88:66:A5":"Apple",
    "34:F6:4B":"Samsung",      "00:12:47":"Samsung",    "44:4E:6D":"Samsung",
    "00:26:37":"Samsung",      "78:1F:DB":"Samsung",    "8C:71:F8":"Samsung",
    "00:1A:11":"Google",       "54:60:09":"Google",     "3C:5A:B4":"Google",
    "00:50:F2":"Microsoft",    "00:03:FF":"Microsoft",  "28:18:78":"Microsoft",
    "28:CF:E9":"Intel",        "00:1B:21":"Intel",      "8C:8D:28":"Intel",
    "8C:EC:4B":"Intel",        "18:66:DA":"Intel",
    "00:1E:65":"Dell",         "00:21:70":"Dell",       "14:FE:B5":"Dell",
    "18:03:73":"Dell",         "F8:DB:88":"Dell",
    "00:1A:4B":"HP",           "00:18:FE":"HP",         "3C:D9:2B":"HP",
    "B4:B5:2F":"Huawei",       "00:46:4B":"Huawei",    "00:E0:FC":"Huawei",
    "4C:1F:CC":"Huawei",       "48:FD:8E":"Huawei",
    "78:44:FD":"Asus",         "00:11:D8":"Asus",       "04:92:26":"Asus",
    "00:22:68":"Netgear",      "00:18:E7":"Netgear",   "20:4E:7F":"Netgear",
    "00:1E:E5":"TP-Link",      "14:CF:92":"TP-Link",   "50:C7:BF":"TP-Link",
    "EC:08:6B":"TP-Link",      "54:AF:97":"TP-Link",
    "00:1D:7E":"Linksys",      "00:21:29":"Linksys",
    "00:15:5D":"Hyper-V",      "52:54:00":"QEMU/KVM",  "00:16:3E":"Xen",
}

PORT_NAMES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 135:"RPC", 139:"NetBIOS", 143:"IMAP",
    443:"HTTPS", 445:"SMB", 3306:"MySQL", 3389:"RDP",
    5900:"VNC", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
}
COMMON_PORTS = list(PORT_NAMES.keys())


def lookup_vendor(mac):
    if not mac or mac == "N/A":
        return "Bilinmiyor"
    clean = mac.upper().replace("-",":")
    if clean[:8] in MAC_VENDORS:
        return MAC_VENDORS[clean[:8]]
    p6 = clean.replace(":","")[:6]
    for k, v in MAC_VENDORS.items():
        if k.replace(":","") == p6:
            return v
    return "Bilinmiyor"


# ─── Ana Pencere ──────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Analyzer Pro")
        self.geometry("1440x860")
        self.minsize(1100, 700)
        self.configure(bg=BG)

        self.scanning   = False
        self.devices    = []
        self.net_info   = {}
        self._found     = 0
        self._scan_history = []   # (timestamp, count)
        self._ping_data    = []   # ms values for histogram
        self._vendor_counts = defaultdict(int)
        self._port_counts   = defaultdict(int)

        self._setup_matplotlib()
        self._build_ui()
        self._start_clock()
        self.after(400, self._load_net_info)

    # ── Matplotlib temasi ──────────────────────────────────────────────────
    def _setup_matplotlib(self):
        plt.rcParams.update({
            "figure.facecolor":  CHART_BG,
            "axes.facecolor":    CHART_BG,
            "axes.edgecolor":    CHART_GRID,
            "axes.labelcolor":   GRAY,
            "xtick.color":       GRAY2,
            "ytick.color":       GRAY2,
            "text.color":        WHITE,
            "grid.color":        CHART_GRID,
            "grid.linestyle":    "--",
            "grid.alpha":        0.5,
            "font.family":       "Segoe UI",
            "font.size":         8,
        })

    # ── UI ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        self._build_body()
        self._build_statusbar()

    def _build_header(self):
        hdr = tk.Frame(self, bg=BG2, pady=0)
        hdr.pack(fill="x")

        # Sol - logo + baslik
        left = tk.Frame(hdr, bg=BG2)
        left.pack(side="left", padx=18, pady=10)

        # Animasyonlu nokta
        self._dot_canvas = tk.Canvas(left, width=14, height=14,
            bg=BG2, highlightthickness=0)
        self._dot_canvas.pack(side="left", padx=(0,8))
        self._dot_id = self._dot_canvas.create_oval(2,2,12,12, fill=GREEN, outline="")
        self._dot_pulse = 0
        self._animate_dot()

        tk.Label(left, text="Network Analyzer Pro",
            font=("Segoe UI", 17, "bold"), fg=WHITE, bg=BG2
        ).pack(side="left")

        tk.Label(left, text="  v2.0",
            font=("Segoe UI", 10), fg=GRAY2, bg=BG2
        ).pack(side="left")

        # Orta - canli saat
        self._clock_lbl = tk.Label(hdr, text="",
            font=("Consolas", 11), fg=CYAN, bg=BG2)
        self._clock_lbl.pack(side="left", padx=30)

        # Sag - butonlar
        right = tk.Frame(hdr, bg=BG2)
        right.pack(side="right", padx=18, pady=8)

        self.stop_btn = self._btn(right, "■  DURDUR", RED, self.stop_scan,
            state="disabled")
        self.stop_btn.pack(side="right", padx=4)

        self.scan_btn = self._btn(right, "▶  AG TARA", GREEN, self.start_scan)
        self.scan_btn.pack(side="right", padx=4)

        self._btn(right, "↻  YENILE", BLUE, self._load_net_info,
            small=True).pack(side="right", padx=4)

        # Progress bar (header altinda)
        pb_row = tk.Frame(self, bg=BG3, pady=3)
        pb_row.pack(fill="x")

        s = ttk.Style()
        s.configure("HP.Horizontal.TProgressbar",
            troughcolor=BG3, background=BLUE, borderwidth=0, thickness=4)

        self.pb = ttk.Progressbar(pb_row, style="HP.Horizontal.TProgressbar",
            mode="determinate", maximum=100)
        self.pb.pack(fill="x", padx=0, pady=0)

        self._pb_lbl = tk.Label(pb_row, text="Hazir",
            font=("Segoe UI", 8), fg=GRAY2, bg=BG3)
        self._pb_lbl.pack(side="right", padx=10)

    def _btn(self, parent, text, color, cmd, state="normal", small=False):
        sz = 9 if small else 10
        px = 12 if small else 18
        py = 5 if small else 8
        bg_map = {GREEN: "#064e3b", RED: "#450a0a", BLUE: "#1e3a5f",
                  ORANGE: "#451a03", CYAN: "#0c3040"}
        dark = bg_map.get(color, BG3)
        b = tk.Button(parent, text=text, font=("Segoe UI", sz, "bold"),
            bg=dark, fg=WHITE, activebackground=color, activeforeground=WHITE,
            relief="flat", padx=px, pady=py, cursor="hand2",
            command=cmd, state=state,
            borderwidth=0)
        b.bind("<Enter>", lambda e: b.config(bg=color))
        b.bind("<Leave>", lambda e: b.config(bg=dark) if b["state"] != "disabled" else None)
        return b

    def _build_body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        # Sol panel
        left = tk.Frame(body, bg=BG, width=300)
        left.pack(side="left", fill="y", padx=(10,5), pady=8)
        left.pack_propagate(False)
        self._build_left_panel(left)

        # Sag panel (tablo + grafikler)
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(5,10), pady=8)
        self._build_right_panel(right)

    # ── Sol Panel ─────────────────────────────────────────────────────────
    def _build_left_panel(self, parent):
        # Ag Bilgileri Karti
        self._card(parent, "AG BILGILERI", self._build_net_info_card).pack(
            fill="x", pady=(0,6))

        # Istatistik Karti
        self._card(parent, "TARAMA ISTATISTIKLERI", self._build_stats_card).pack(
            fill="x", pady=(0,6))

        # Vendor Pie Chart
        vendor_card = self._card(parent, "URETICI DAGILIMI", None)
        vendor_card.pack(fill="both", expand=True, pady=(0,6))
        self._build_vendor_chart(vendor_card)

    def _card(self, parent, title, builder):
        frame = tk.Frame(parent, bg=BG2, padx=2, pady=2)
        # Baslik
        hdr = tk.Frame(frame, bg=BG3, padx=10, pady=6)
        hdr.pack(fill="x")
        tk.Label(hdr, text=title, font=("Segoe UI", 8, "bold"),
            fg=CYAN, bg=BG3, anchor="w").pack(fill="x")
        # Icerik
        if builder:
            content = tk.Frame(frame, bg=BG2, padx=10, pady=8)
            content.pack(fill="both", expand=True)
            builder(content)
        return frame

    def _build_net_info_card(self, parent):
        self._net_labels = {}
        fields = [
            ("IP Adresim",   "ip",        BLUE2),
            ("Ag Gecidi",    "gateway",   ORANGE),
            ("Alt Ag",       "netmask",   GRAY),
            ("Arayuz",       "iface",     CYAN),
            ("Ag Araligi",   "network",   GREEN2),
            ("Host Sayisi",  "hosts",     PURPLE),
        ]
        for label, key, color in fields:
            row = tk.Frame(parent, bg=BG2)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"{label}:", font=("Segoe UI", 8),
                fg=GRAY2, bg=BG2, width=12, anchor="w").pack(side="left")
            lbl = tk.Label(row, text="—", font=("Consolas", 9, "bold"),
                fg=color, bg=BG2, anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            self._net_labels[key] = lbl

    def _build_stats_card(self, parent):
        self._stat_vals = {}
        stats = [
            ("Bulunan",      "found",   GREEN,  "0"),
            ("Ortalama Ping","avg_ms",  CYAN,   "— ms"),
            ("Acik Port",    "ports",   ORANGE, "0"),
            ("Uretici",      "vendors", PURPLE, "0"),
        ]
        for i, (label, key, color, default) in enumerate(stats):
            col = i % 2
            row_idx = i // 2
            cell = tk.Frame(parent, bg=BG3, padx=8, pady=6)
            cell.grid(row=row_idx, column=col, padx=3, pady=3, sticky="nsew")
            parent.columnconfigure(col, weight=1)

            v = tk.Label(cell, text=default, font=("Segoe UI", 18, "bold"),
                fg=color, bg=BG3)
            v.pack()
            tk.Label(cell, text=label, font=("Segoe UI", 7),
                fg=GRAY2, bg=BG3).pack()
            self._stat_vals[key] = v

    def _build_vendor_chart(self, parent):
        self._vendor_fig = Figure(figsize=(2.8, 2.8), dpi=80)
        self._vendor_ax  = self._vendor_fig.add_subplot(111)
        self._vendor_fig.patch.set_facecolor(CHART_BG)
        self._vendor_ax.set_facecolor(CHART_BG)
        self._vendor_ax.set_aspect("equal")
        self._vendor_ax.text(0.5, 0.5, "Tarama Bekleniyor",
            ha="center", va="center", color=GRAY2,
            fontsize=9, transform=self._vendor_ax.transAxes)
        self._vendor_ax.axis("off")

        canvas = FigureCanvasTkAgg(self._vendor_fig, master=parent)
        canvas.get_tk_widget().pack(fill="both", expand=True)
        self._vendor_canvas = canvas

    # ── Sag Panel ─────────────────────────────────────────────────────────
    def _build_right_panel(self, parent):
        # Ust: tablo
        tbl_frame = tk.Frame(parent, bg=BG)
        tbl_frame.pack(fill="both", expand=True)
        self._build_table(tbl_frame)

        # Alt: iki grafik yan yana
        charts_row = tk.Frame(parent, bg=BG, height=200)
        charts_row.pack(fill="x", pady=(6,0))
        charts_row.pack_propagate(False)
        self._build_bottom_charts(charts_row)

    def _build_table(self, parent):
        s = ttk.Style()
        s.configure("T.Treeview",
            background=BG2, foreground=WHITE,
            fieldbackground=BG2, rowheight=28,
            font=("Consolas", 9), borderwidth=0)
        s.configure("T.Treeview.Heading",
            background=BG3, foreground=CYAN,
            font=("Segoe UI", 9, "bold"), relief="flat", padding=5)
        s.map("T.Treeview",
            background=[("selected", BLUE)],
            foreground=[("selected", WHITE)])

        cols = ("#", "IP Adresi", "MAC Adresi", "Hostname",
                "Uretici / Marka", "Durum", "Gecikme", "Acik Portlar")

        self.tree = ttk.Treeview(parent, style="T.Treeview",
            columns=cols, show="headings", selectmode="browse")

        widths = [36, 125, 155, 200, 145, 70, 90, 280]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col, anchor="w")
            self.tree.column(col, width=w, minwidth=30, anchor="w")

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        self.tree.tag_configure("gw",  foreground=ORANGE, font=("Consolas",9,"bold"))
        self.tree.tag_configure("ok",  foreground=GREEN2)
        self.tree.tag_configure("alt", background="#151e2d")

        self.tree.bind("<Double-1>", self._show_detail)
        ctx = tk.Menu(self, tearoff=0, bg=BG3, fg=WHITE,
            activebackground=BLUE, activeforeground=WHITE)
        ctx.add_command(label="Kopyala",   command=self._copy_row)
        ctx.add_command(label="Detay Goster", command=lambda: self._show_detail(None))
        self.tree.bind("<Button-3>", lambda e: (
            self.tree.selection_set(self.tree.identify_row(e.y)),
            ctx.post(e.x_root, e.y_root)))

    def _build_bottom_charts(self, parent):
        # Sol: Ping histogram
        ping_frame = tk.Frame(parent, bg=BG2)
        ping_frame.pack(side="left", fill="both", expand=True, padx=(0,4))
        tk.Label(ping_frame, text="PING DAGILIMI (ms)",
            font=("Segoe UI", 8, "bold"), fg=CYAN, bg=BG2, pady=4
        ).pack()
        self._ping_fig = Figure(figsize=(4, 1.8), dpi=90)
        self._ping_ax  = self._ping_fig.add_subplot(111)
        self._ping_fig.patch.set_facecolor(CHART_BG)
        self._init_ping_chart()
        FigureCanvasTkAgg(self._ping_fig, master=ping_frame
            ).get_tk_widget().pack(fill="both", expand=True)

        # Sag: Port dagilimi
        port_frame = tk.Frame(parent, bg=BG2)
        port_frame.pack(side="left", fill="both", expand=True, padx=(4,0))
        tk.Label(port_frame, text="PORT DAGILIMI",
            font=("Segoe UI", 8, "bold"), fg=CYAN, bg=BG2, pady=4
        ).pack()
        self._port_fig = Figure(figsize=(4, 1.8), dpi=90)
        self._port_ax  = self._port_fig.add_subplot(111)
        self._port_fig.patch.set_facecolor(CHART_BG)
        self._init_port_chart()
        FigureCanvasTkAgg(self._port_fig, master=port_frame
            ).get_tk_widget().pack(fill="both", expand=True)

    def _init_ping_chart(self):
        ax = self._ping_ax
        ax.set_facecolor(CHART_BG)
        ax.tick_params(colors=GRAY2, labelsize=7)
        for spine in ax.spines.values():
            spine.set_edgecolor(CHART_GRID)
        ax.set_xlabel("ms", color=GRAY2, fontsize=7)
        ax.set_ylabel("Cihaz", color=GRAY2, fontsize=7)
        ax.text(0.5, 0.5, "Veri yok", ha="center", va="center",
            color=GRAY2, fontsize=9, transform=ax.transAxes)
        self._ping_fig.tight_layout(pad=0.8)

    def _init_port_chart(self):
        ax = self._port_ax
        ax.set_facecolor(CHART_BG)
        ax.tick_params(colors=GRAY2, labelsize=7)
        for spine in ax.spines.values():
            spine.set_edgecolor(CHART_GRID)
        ax.text(0.5, 0.5, "Veri yok", ha="center", va="center",
            color=GRAY2, fontsize=9, transform=ax.transAxes)
        self._port_fig.tight_layout(pad=0.8)

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=BG3, pady=3)
        bar.pack(fill="x", side="bottom")

        self._status_lbl = tk.Label(bar, text="●  Hazir — Ag bilgileri yukleniyor...",
            font=("Segoe UI", 9), fg=GREEN, bg=BG3)
        self._status_lbl.pack(side="left", padx=14)

        self._found_lbl = tk.Label(bar, text="",
            font=("Segoe UI", 9, "bold"), fg=ORANGE, bg=BG3)
        self._found_lbl.pack(side="right", padx=14)

    # ── Animasyonlar ──────────────────────────────────────────────────────
    def _animate_dot(self):
        self._dot_pulse = (self._dot_pulse + 1) % 20
        alpha = 0.4 + 0.6 * abs(math.sin(self._dot_pulse * math.pi / 20))
        r = int(16 * alpha)
        g = int(185 * alpha) if self.scanning else int(120 * alpha)
        b = int(50 * alpha)
        color = f"#{r:02x}{g:02x}{b:02x}" if self.scanning else \
                f"#{int(16*alpha):02x}{int(185*alpha):02x}{int(129*alpha):02x}"
        self._dot_canvas.itemconfig(self._dot_id, fill=color)
        self.after(60, self._animate_dot)

    def _start_clock(self):
        def tick():
            self._clock_lbl.config(
                text=datetime.now().strftime("  %d.%m.%Y   %H:%M:%S"))
            self.after(1000, tick)
        tick()

    # ── Ag Bilgisi ────────────────────────────────────────────────────────
    def _load_net_info(self):
        try:
            info = _get_network_info()
            self.net_info = info
            hosts = list(info["network"].hosts())
            self._net_labels["ip"].config(text=info["ip"])
            self._net_labels["gateway"].config(text=info["gateway"])
            self._net_labels["netmask"].config(text=info["netmask"])
            self._net_labels["iface"].config(text=info["iface"])
            self._net_labels["network"].config(text=str(info["network"]))
            self._net_labels["hosts"].config(text=f"{len(hosts)} host")
            self._set_status(f"●  Hazir — {info['ip']}  |  {len(hosts)} host taranabilir", GREEN)
        except Exception as e:
            self._set_status(f"●  HATA: {e}", RED)

    # ── Tarama ───────────────────────────────────────────────────────────
    def start_scan(self):
        if self.scanning or not self.net_info:
            return
        self.scanning = True
        self.devices.clear()
        self._found = 0
        self._ping_data.clear()
        self._vendor_counts.clear()
        self._port_counts.clear()
        self._scan_history.clear()

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.pb["value"] = 0
        self._set_status("●  Taranıyor...", ORANGE)
        self._update_stats()

        # Vendor chart sifirla
        self._vendor_ax.clear()
        self._vendor_ax.text(0.5, 0.5, "Taranıyor...",
            ha="center", va="center", color=ORANGE,
            fontsize=9, transform=self._vendor_ax.transAxes)
        self._vendor_ax.axis("off")
        self._vendor_canvas.draw()

        threading.Thread(target=self._run_scan, daemon=True).start()

    def stop_scan(self):
        self.scanning = False
        self._set_status("●  Durduruldu", RED)
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def _run_scan(self):
        try:
            hosts = list(self.net_info["network"].hosts())
            total = len(hosts)
            done  = 0

            with ThreadPoolExecutor(max_workers=60) as ex:
                fmap = {ex.submit(_scan_one, ip, self.net_info["gateway"]): ip
                        for ip in hosts}
                for fut in as_completed(fmap):
                    if not self.scanning:
                        ex.shutdown(wait=False, cancel_futures=True)
                        break
                    done += 1
                    pct  = int(done / total * 100)
                    ip_s = str(fmap[fut])
                    res  = fut.result()
                    self.after(0, lambda p=pct, ip=ip_s: self._tick(p, ip))
                    if res:
                        self._found += 1
                        self.devices.append(res)
                        self.after(0, lambda d=res, n=self._found:
                            self._add_row(d, n))
            if self.scanning:
                self.after(0, self._scan_done)
        except Exception as e:
            self.after(0, lambda: self._set_status(f"HATA: {e}", RED))
            self.after(0, self._scan_done)

    def _tick(self, pct, ip):
        self.pb["value"] = pct
        self._pb_lbl.config(text=f"%{pct}  —  {ip}")

    def _add_row(self, d, n):
        port_str = "  ".join(
            f"{p}({PORT_NAMES.get(p,'?')})" for p in d["ports"]
        ) if d["ports"] else "—"

        is_gw = (d["ip"] == self.net_info.get("gateway",""))
        tag = "gw" if is_gw else "ok"
        if n % 2 == 0:
            tag = (tag, "alt")

        self.tree.insert("", "end", values=(
            n, d["ip"], d["mac"], d["hostname"],
            d["vendor"], "Online", f"{d['ms']} ms", port_str,
        ), tags=tag)
        self.tree.yview_moveto(1)

        # Istatistik guncelle
        self._ping_data.append(d["ms"])
        self._vendor_counts[d["vendor"]] += 1
        for p in d["ports"]:
            self._port_counts[PORT_NAMES.get(p, str(p))] += 1

        self._found_lbl.config(text=f"  {n} cihaz bulundu  ")
        self._update_stats()
        self._update_vendor_chart()
        self._update_bottom_charts()

    def _scan_done(self):
        self.scanning = False
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.pb["value"] = 100
        self._pb_lbl.config(text="Tamamlandi")
        self._set_status(
            f"●  Tamamlandi — {self._found} cihaz, "
            f"{sum(self._port_counts.values())} acik port", GREEN)
        self._update_vendor_chart()
        self._update_bottom_charts()

    # ── Grafik Guncelleme ─────────────────────────────────────────────────
    def _update_stats(self):
        self._stat_vals["found"].config(text=str(self._found))
        avg = f"{sum(self._ping_data)/len(self._ping_data):.0f} ms" \
              if self._ping_data else "— ms"
        self._stat_vals["avg_ms"].config(text=avg)
        self._stat_vals["ports"].config(
            text=str(sum(self._port_counts.values())))
        self._stat_vals["vendors"].config(
            text=str(len(self._vendor_counts)))

    def _update_vendor_chart(self):
        if not self._vendor_counts:
            return
        ax = self._vendor_ax
        ax.clear()
        ax.set_facecolor(CHART_BG)

        labels = list(self._vendor_counts.keys())
        sizes  = list(self._vendor_counts.values())
        colors = VENDOR_COLORS[:len(labels)]

        wedges, texts, autotexts = ax.pie(
            sizes, labels=None, colors=colors,
            autopct=lambda p: f"{p:.0f}%" if p > 5 else "",
            startangle=90,
            wedgeprops={"linewidth": 1.5, "edgecolor": BG},
            pctdistance=0.75,
        )
        for at in autotexts:
            at.set_fontsize(7)
            at.set_color(WHITE)

        # Orta daire (donut)
        centre = plt.Circle((0,0), 0.55, fc=CHART_BG)
        ax.add_patch(centre)
        ax.text(0, 0, f"{self._found}\ncihaz",
            ha="center", va="center", color=WHITE,
            fontsize=9, fontweight="bold")

        # Legend
        patches = [mpatches.Patch(color=c, label=l)
                   for c, l in zip(colors, labels)]
        ax.legend(handles=patches, loc="lower center",
            bbox_to_anchor=(0.5, -0.12), ncol=2,
            fontsize=6.5, frameon=False,
            labelcolor=WHITE, handlelength=0.8)

        ax.set_aspect("equal")
        self._vendor_fig.tight_layout(pad=0.3)
        self._vendor_canvas.draw()

    def _update_bottom_charts(self):
        # Ping histogram
        ax = self._ping_ax
        ax.clear()
        ax.set_facecolor(CHART_BG)
        ax.tick_params(colors=GRAY2, labelsize=7)
        for sp in ax.spines.values():
            sp.set_edgecolor(CHART_GRID)

        if self._ping_data:
            bins = min(15, len(self._ping_data))
            n, edges, patches = ax.hist(self._ping_data, bins=bins,
                color=BLUE, edgecolor=BG, linewidth=0.5)
            # Renk gradyani
            mx = max(n) if max(n) > 0 else 1
            cmap = plt.cm.get_cmap("cool")
            for patch, val in zip(patches, n):
                patch.set_facecolor(cmap(val / mx))
            ax.set_xlabel("ms", color=GRAY2, fontsize=7)
            ax.set_ylabel("Cihaz", color=GRAY2, fontsize=7)
            ax.grid(True, alpha=0.3)
            avg = sum(self._ping_data)/len(self._ping_data)
            ax.axvline(avg, color=ORANGE, linestyle="--", linewidth=1,
                label=f"Ort: {avg:.0f}ms")
            ax.legend(fontsize=7, frameon=False, labelcolor=WHITE)
        else:
            ax.text(0.5, 0.5, "Veri yok", ha="center", va="center",
                color=GRAY2, fontsize=9, transform=ax.transAxes)

        self._ping_fig.tight_layout(pad=0.8)
        self._ping_fig._canvas.draw() if hasattr(self._ping_fig, "_canvas") else None
        try:
            self._ping_fig.canvas.draw()
        except:
            pass

        # Port bar chart
        ax2 = self._port_ax
        ax2.clear()
        ax2.set_facecolor(CHART_BG)
        ax2.tick_params(colors=GRAY2, labelsize=7)
        for sp in ax2.spines.values():
            sp.set_edgecolor(CHART_GRID)

        if self._port_counts:
            sorted_ports = sorted(self._port_counts.items(),
                key=lambda x: x[1], reverse=True)[:10]
            pnames = [p[0] for p in sorted_ports]
            pcnts  = [p[1] for p in sorted_ports]
            bars = ax2.barh(pnames, pcnts, color=CYAN, edgecolor=BG,
                linewidth=0.5, height=0.6)
            bar_colors = [GREEN, CYAN, BLUE, PURPLE, ORANGE,
                          PINK, RED, GREEN2, BLUE2, YELLOW if 'YELLOW' in dir() else ORANGE]
            for bar, color in zip(bars, bar_colors[:len(bars)]):
                bar.set_facecolor(color)
            ax2.set_xlabel("Cihaz Sayisi", color=GRAY2, fontsize=7)
            ax2.grid(True, alpha=0.3, axis="x")
            ax2.invert_yaxis()
        else:
            ax2.text(0.5, 0.5, "Veri yok", ha="center", va="center",
                color=GRAY2, fontsize=9, transform=ax2.transAxes)

        self._port_fig.tight_layout(pad=0.8)
        try:
            self._port_fig.canvas.draw()
        except:
            pass

    # ── Yardimci ──────────────────────────────────────────────────────────
    def _set_status(self, text, color):
        self._status_lbl.config(text=text, fg=color)

    def _copy_row(self):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        self.clipboard_clear()
        self.clipboard_append("  |  ".join(str(v) for v in vals))

    def _show_detail(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        keys = ["No", "IP Adresi", "MAC Adresi", "Hostname",
                "Uretici", "Durum", "Gecikme", "Acik Portlar"]

        win = tk.Toplevel(self)
        win.title(f"Cihaz — {vals[1]}")
        win.configure(bg=BG2)
        win.geometry("420x340")
        win.resizable(False, False)

        # Baslik
        tk.Label(win, text=f"  {vals[1]}",
            font=("Segoe UI", 14, "bold"), fg=CYAN, bg=BG2,
            pady=12).pack(fill="x")

        tk.Frame(win, bg=BG4, height=1).pack(fill="x", padx=20)

        content = tk.Frame(win, bg=BG2, padx=24, pady=12)
        content.pack(fill="both", expand=True)

        colors_map = {
            "IP Adresi": BLUE2, "MAC Adresi": ORANGE, "Hostname": GREEN2,
            "Uretici": PURPLE, "Durum": GREEN, "Gecikme": CYAN,
            "Acik Portlar": PINK,
        }

        for i, (k, v) in enumerate(zip(keys[1:], vals[1:])):
            row = tk.Frame(content, bg=BG2)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=f"{k}:", font=("Segoe UI", 9),
                fg=GRAY, bg=BG2, width=14, anchor="w").pack(side="left")
            tk.Label(row, text=str(v), font=("Consolas", 9, "bold"),
                fg=colors_map.get(k, WHITE), bg=BG2, anchor="w",
                wraplength=250, justify="left").pack(side="left", fill="x", expand=True)

        tk.Frame(win, bg=BG4, height=1).pack(fill="x", padx=20, pady=(8,0))

        tk.Button(win, text="Kapat", command=win.destroy,
            bg=BG3, fg=WHITE, relief="flat", padx=24, pady=8,
            font=("Segoe UI", 9), cursor="hand2",
            activebackground=BLUE, activeforeground=WHITE,
        ).pack(pady=10)


# ─── Network fonksiyonlari (thread-safe) ─────────────────────────────────────
def _get_network_info():
    gateway = "N/A"
    try:
        out = subprocess.run(
            ["route","print","0.0.0.0"],
            capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("0.0.0.0") and line.count("0.0.0.0") >= 2:
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        ipaddress.IPv4Address(parts[2])
                        if not parts[2].startswith("0."):
                            gateway = parts[2]
                            break
                    except:
                        pass
    except:
        pass

    best = None
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip, mask = addr.address, addr.netmask
                if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                    if mask and mask not in ("255.255.255.255","0.0.0.0"):
                        st = psutil.net_if_stats().get(iface)
                        if st and st.isup:
                            best = (iface, ip, mask)
                            break
        if best:
            break

    if not best:
        raise RuntimeError("Aktif ag arayuzu bulunamadi!")

    iface, ip, mask = best
    network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return {"iface":iface,"ip":ip,"netmask":mask,"gateway":gateway,"network":network}


def _ping(ip):
    try:
        start = time.perf_counter()
        r = subprocess.run(["ping","-n","1","-w","800",ip],
            capture_output=True, text=True, timeout=3)
        ms = round((time.perf_counter()-start)*1000, 1)
        if r.returncode != 0:
            return False, 0.0
        m = re.search(r"Average\s*=\s*(\d+)ms", r.stdout)
        return True, float(m.group(1)) if m else ms
    except:
        return False, 0.0


def _get_mac(ip):
    try:
        out = subprocess.run(["arp","-a",ip],
            capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            if ip in line:
                m = re.search(r"((?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2})", line, re.I)
                if m:
                    return m.group(1).replace("-",":").upper()
    except:
        pass
    return "N/A"


def _get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"


def _scan_ports(ip):
    open_ports = []
    for port in COMMON_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.35)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports


def _scan_one(ip, gateway):
    ip_str = str(ip)
    alive, ms = _ping(ip_str)
    if not alive:
        return None
    return {
        "ip":       ip_str,
        "mac":      _get_mac(ip_str),
        "hostname": _get_hostname(ip_str),
        "vendor":   lookup_vendor(_get_mac(ip_str)),
        "ms":       ms,
        "ports":    _scan_ports(ip_str),
    }


# ─── Baslat ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.mainloop()
