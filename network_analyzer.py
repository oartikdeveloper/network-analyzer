#!/usr/bin/env python3
"""
Network Analyzer Pro v3.0
- Ag cihaz kesfı
- Tam port tarama (1-10000 + yaygin yuksek portlar)
- SNMP v1/v2c analizi
- Multicast trafik tespiti
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
import struct
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.patches as mpatches

PYSNMP_OK = False  # Manuel BER/UDP SNMP kullaniliyor

try:
    from scapy.all import sniff, IP, UDP, TCP, Ether, ARP, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# ─── Renkler ─────────────────────────────────────────────────────────────────
BG      = "#0a0e1a"; BG2 = "#111827"; BG3 = "#1f2937"; BG4 = "#374151"
BLUE    = "#3b82f6"; BLUE2 = "#60a5fa"; CYAN = "#06b6d4"
GREEN   = "#10b981"; GREEN2 = "#34d399"
ORANGE  = "#f59e0b"; RED = "#ef4444"; PURPLE = "#8b5cf6"
PINK    = "#ec4899"; WHITE = "#f9fafb"; GRAY = "#9ca3af"; GRAY2 = "#6b7280"
CHART_BG = "#0d1425"; CHART_GRID = "#1e2d45"
VCOLS = [BLUE,CYAN,GREEN,ORANGE,PURPLE,PINK,RED,"#14b8a6","#f97316","#a78bfa"]

# ─── Port / SNMP veritabanları ────────────────────────────────────────────────
SERVICE_MAP = {
    1:"tcpmux",7:"echo",9:"discard",13:"daytime",17:"qotd",19:"chargen",
    20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",37:"time",
    53:"dns",67:"dhcp",68:"dhcp",69:"tftp",79:"finger",80:"http",
    88:"kerberos",110:"pop3",111:"rpc",119:"nntp",123:"ntp",135:"rpc",
    137:"netbios",138:"netbios",139:"netbios",143:"imap",161:"snmp",
    162:"snmp-trap",179:"bgp",194:"irc",389:"ldap",443:"https",
    445:"smb",465:"smtps",500:"ike",514:"syslog",515:"lpd",520:"rip",
    587:"smtp",631:"ipp",636:"ldaps",993:"imaps",995:"pop3s",
    1080:"socks",1194:"openvpn",1433:"mssql",1434:"mssql-mon",
    1521:"oracle",1723:"pptp",2049:"nfs",2082:"cpanel",2083:"cpanel-ssl",
    2121:"ftp-alt",2222:"ssh-alt",3000:"dev-server",3306:"mysql",
    3389:"rdp",3690:"svn",4444:"metasploit",4848:"glassfish",
    5000:"upnp",5432:"postgresql",5900:"vnc",5985:"winrm",
    5986:"winrm-ssl",6379:"redis",6443:"k8s-api",7001:"weblogic",
    8000:"http-alt",8008:"http",8080:"http-proxy",8443:"https-alt",
    8888:"jupyter",9000:"php-fpm",9090:"prometheus",9200:"elasticsearch",
    9300:"elasticsearch",10000:"webmin",11211:"memcached",
    27017:"mongodb",27018:"mongodb",50000:"db2",
}

SNMP_OIDS = {
    "sysDescr":     "1.3.6.1.2.1.1.1.0",
    "sysUpTime":    "1.3.6.1.2.1.1.3.0",
    "sysContact":   "1.3.6.1.2.1.1.4.0",
    "sysName":      "1.3.6.1.2.1.1.5.0",
    "sysLocation":  "1.3.6.1.2.1.1.6.0",
    "sysObjectID":  "1.3.6.1.2.1.1.2.0",
}
SNMP_COMMUNITIES = ["public", "private", "community", "admin", "cisco",
                    "snmp", "monitor", "manager", "guest", "read"]

MULTICAST_GROUPS = {
    "224.0.0.1":        ("All Hosts",           "RFC 1112"),
    "224.0.0.2":        ("All Routers",          "RFC 2236"),
    "224.0.0.4":        ("DVMRP Routers",        "RFC 1075"),
    "224.0.0.5":        ("OSPF Routers",         "RFC 2328"),
    "224.0.0.6":        ("OSPF DR/BDR",          "RFC 2328"),
    "224.0.0.9":        ("RIPv2",                "RFC 2453"),
    "224.0.0.10":       ("EIGRP",                "Cisco"),
    "224.0.0.13":       ("PIM Routers",          "RFC 4601"),
    "224.0.0.18":       ("VRRP",                 "RFC 3768"),
    "224.0.0.22":       ("IGMP",                 "RFC 3376"),
    "224.0.0.102":      ("HSRP",                 "Cisco"),
    "224.0.0.107":      ("PTP",                  "IEEE 1588"),
    "224.0.0.251":      ("mDNS / Bonjour",       "RFC 6762"),
    "224.0.0.252":      ("LLMNR",                "RFC 4795"),
    "224.0.1.1":        ("NTP",                  "RFC 4330"),
    "239.255.255.250":  ("SSDP / UPnP",          "UPnP Forum"),
    "239.192.0.0":      ("Organization-Local",   "RFC 2365"),
}

MAC_VENDORS = {
    "00:00:0C":"Cisco","00:50:56":"VMware","00:0C:29":"VMware",
    "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
    "00:1B:63":"Apple","3C:15:C2":"Apple","A4:C3:F0":"Apple",
    "34:F6:4B":"Samsung","44:4E:6D":"Samsung","78:1F:DB":"Samsung",
    "00:1A:11":"Google","54:60:09":"Google","00:50:F2":"Microsoft",
    "28:CF:E9":"Intel","8C:8D:28":"Intel","00:1E:65":"Dell",
    "14:FE:B5":"Dell","00:1A:4B":"HP","3C:D9:2B":"HP",
    "B4:B5:2F":"Huawei","00:E0:FC":"Huawei","78:44:FD":"Asus",
    "04:92:26":"Asus","00:22:68":"Netgear","20:4E:7F":"Netgear",
    "14:CF:92":"TP-Link","50:C7:BF":"TP-Link","EC:08:6B":"TP-Link",
    "00:15:5D":"Hyper-V","52:54:00":"QEMU/KVM",
}

SCAN_PORTS = list(range(1, 1025)) + [
    1080,1194,1433,1434,1521,1723,2049,2082,2083,2121,2222,
    3000,3306,3389,3690,4444,4848,5000,5432,5900,5985,5986,
    6379,6443,7001,8000,8008,8080,8443,8888,9000,9090,9200,
    9300,10000,11211,27017,27018,50000
]

def lookup_vendor(mac):
    if not mac or mac == "N/A": return "Bilinmiyor"
    c = mac.upper().replace("-",":")
    if c[:8] in MAC_VENDORS: return MAC_VENDORS[c[:8]]
    p = c.replace(":","")[:6]
    for k,v in MAC_VENDORS.items():
        if k.replace(":","") == p: return v
    return "Bilinmiyor"

# ─── SNMP (manuel BER) ────────────────────────────────────────────────────────
def _ber_tlv(tag, val: bytes) -> bytes:
    L = len(val)
    if L < 128:   return bytes([tag,L]) + val
    elif L < 256: return bytes([tag,0x81,L]) + val
    else:         return bytes([tag,0x82,L>>8,L&0xff]) + val

def _encode_oid(oid_str: str) -> bytes:
    p = [int(x) for x in oid_str.split(".")]
    out = [40*p[0]+p[1]]
    for n in p[2:]:
        if n == 0: out.append(0)
        else:
            b = []
            while n: b.append(n&0x7f); n>>=7
            b.reverse()
            for i in range(len(b)-1): b[i] |= 0x80
            out.extend(b)
    return bytes(out)

def _parse_snmp_response(data: bytes) -> dict:
    results = {}
    try:
        # Walk varbindList looking for OctetString / Integer values
        def find_strings(buf, depth=0):
            i = 0
            while i < len(buf)-1:
                tag = buf[i]; i+=1
                if buf[i] < 128: length=buf[i]; i+=1
                elif buf[i]==0x81: length=buf[i+1]; i+=2
                elif buf[i]==0x82: length=(buf[i+1]<<8)|buf[i+2]; i+=3
                else: break
                val = buf[i:i+length]; i+=length
                if tag == 0x04:  # OctetString
                    try: results[f"str_{len(results)}"] = val.decode("utf-8","replace").strip()
                    except: pass
                elif tag == 0x02 and length <= 4:  # Integer
                    num = int.from_bytes(val,"big")
                    results[f"int_{len(results)}"] = num
                elif tag & 0x20:  # constructed
                    find_strings(val, depth+1)
        find_strings(data)
    except: pass
    return results

def snmp_get(ip: str, community: str, oids: list, timeout=2) -> dict:
    """SNMPv2c GET - returns {name: value_str}"""
    varbinds = b""
    for oid in oids:
        ob = _encode_oid(oid)
        varbinds += _ber_tlv(0x30, _ber_tlv(0x06,ob) + _ber_tlv(0x05,b""))
    pdu = _ber_tlv(0xa0,
        _ber_tlv(0x02, b"\x00\x01") +
        _ber_tlv(0x02, b"\x00") +
        _ber_tlv(0x02, b"\x00") +
        _ber_tlv(0x30, varbinds))
    msg = _ber_tlv(0x30,
        _ber_tlv(0x02, b"\x01") +
        _ber_tlv(0x04, community.encode()) +
        pdu)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg, (ip, 161))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        parsed = _parse_snmp_response(resp)
        # Map string values back to names
        named = {}
        oid_names = list(SNMP_OIDS.keys())
        str_vals = [v for k,v in parsed.items() if isinstance(v,str) and len(v)>1]
        for i, name in enumerate(oid_names):
            if i < len(str_vals): named[name] = str_vals[i]
        return named
    except: return {}

# ─── Net helpers ─────────────────────────────────────────────────────────────
def _get_network_info():
    gateway = "N/A"
    try:
        out = subprocess.run(["route","print","0.0.0.0"],
            capture_output=True,text=True,timeout=5).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("0.0.0.0") and line.count("0.0.0.0")>=2:
                parts = line.split()
                if len(parts)>=3:
                    try:
                        ipaddress.IPv4Address(parts[2])
                        if not parts[2].startswith("0."):
                            gateway=parts[2]; break
                    except: pass
    except: pass
    best = None
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET:
                ip, mask = a.address, a.netmask
                if ip and not ip.startswith("127.") and ip!="0.0.0.0":
                    if mask and mask not in ("255.255.255.255","0.0.0.0"):
                        st = psutil.net_if_stats().get(iface)
                        if st and st.isup: best=(iface,ip,mask); break
        if best: break
    if not best: raise RuntimeError("Aktif arayuz bulunamadi!")
    iface,ip,mask = best
    network = ipaddress.IPv4Network(f"{ip}/{mask}",strict=False)
    return {"iface":iface,"ip":ip,"netmask":mask,"gateway":gateway,"network":network}

def _ping(ip):
    try:
        start = time.perf_counter()
        r = subprocess.run(["ping","-n","1","-w","800",ip],
            capture_output=True,text=True,timeout=3)
        ms = round((time.perf_counter()-start)*1000,1)
        if r.returncode!=0: return False, 0.0
        m = re.search(r"Average\s*=\s*(\d+)ms",r.stdout)
        return True, float(m.group(1)) if m else ms
    except: return False, 0.0

def _get_mac(ip):
    try:
        out = subprocess.run(["arp","-a",ip],capture_output=True,text=True,timeout=3).stdout
        for line in out.splitlines():
            if ip in line:
                m = re.search(r"((?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2})",line,re.I)
                if m: return m.group(1).replace("-",":").upper()
    except: pass
    return "N/A"

def _get_hostname(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return "N/A"

def _scan_ports_quick(ip):
    """Hizli tarama - yaygin portlar"""
    quick = [21,22,23,25,53,80,110,135,139,143,443,445,
             3306,3389,5900,8080,8443]
    open_ports = []
    for p in quick:
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(0.3); s.connect_ex((ip,p))==0 and open_ports.append(p); s.close()
        except: pass
    return open_ports

def _scan_ports_deep(ip, progress_cb=None):
    """Tam port tarama"""
    open_ports = []
    total = len(SCAN_PORTS)
    def check(port):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(0.35)
            if s.connect_ex((ip,port))==0:
                # Banner al
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(256).decode("utf-8","replace").split("\n")[0][:60]
                except: banner = ""
                open_ports.append((port, SERVICE_MAP.get(port,"unknown"), banner.strip()))
            s.close()
        except: pass
    done = [0]
    with ThreadPoolExecutor(max_workers=200) as ex:
        futs = {ex.submit(check, p): p for p in SCAN_PORTS}
        for fut in as_completed(futs):
            done[0] += 1
            if progress_cb:
                progress_cb(int(done[0]/total*100), str(futs[fut]))
    return sorted(open_ports, key=lambda x: x[0])

def _scan_one(ip, gateway):
    ip_str = str(ip)
    alive, ms = _ping(ip_str)
    if not alive: return None
    mac = _get_mac(ip_str)
    return {
        "ip": ip_str, "mac": mac,
        "hostname": _get_hostname(ip_str),
        "vendor": lookup_vendor(mac),
        "ms": ms, "ports": _scan_ports_quick(ip_str),
    }

# ─── Multicast ────────────────────────────────────────────────────────────────
def detect_multicast(local_ip, result_q: queue.Queue):
    results = {}

    # 1) netsh ile aktif uyelikler
    try:
        out = subprocess.run(
            ["netsh","interface","ip","show","joins"],
            capture_output=True, text=True, timeout=8).stdout
        for line in out.splitlines():
            m = re.search(r"(\d{3}\.\d+\.\d+\.\d+)", line)
            if m:
                addr = m.group(1)
                if addr.startswith("224.") or addr.startswith("239."):
                    info = MULTICAST_GROUPS.get(addr, ("Bilinmeyen grup","—"))
                    results[addr] = {
                        "group": addr, "name": info[0], "proto": info[1],
                        "source": "netsh (aktif uyelik)", "active": True}
    except: pass

    # 2) Bilinen gruplara ping
    for grp, (name, proto) in MULTICAST_GROUPS.items():
        if grp in results: continue
        try:
            r = subprocess.run(
                ["ping","-n","1","-w","500",grp],
                capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                results[grp] = {"group":grp,"name":name,"proto":proto,
                                "source":"ping yaniti","active":True}
            else:
                results[grp] = {"group":grp,"name":name,"proto":proto,
                                "source":"ping yok","active":False}
        except: pass

    # 3) UDP dinleyici (scapy varsa)
    if SCAPY_OK:
        try:
            pkts = sniff(timeout=4, iface=None,
                filter="ip multicast", store=True)
            for pkt in pkts:
                if IP in pkt:
                    dst = pkt[IP].dst
                    if dst.startswith("224.") or dst.startswith("239."):
                        info = MULTICAST_GROUPS.get(dst,("Bilinmeyen","—"))
                        if dst not in results:
                            results[dst] = {
                                "group":dst,"name":info[0],"proto":info[1],
                                "source":f"canli paket (src:{pkt[IP].src})",
                                "active":True}
        except: pass

    # 4) Socket ile dinle
    else:
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            sock.settimeout(0.5)
            for grp in ["224.0.0.251","239.255.255.250","224.0.0.1"]:
                try:
                    mreq = struct.pack("4s4s",
                        socket.inet_aton(grp), socket.inet_aton(local_ip))
                    sock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
                    sock.bind(("",5353 if grp=="224.0.0.251" else 1900 if "250" in grp else 0))
                    try:
                        data, addr = sock.recvfrom(1024)
                        if grp in results:
                            results[grp]["source"] = f"socket paket (src:{addr[0]})"
                            results[grp]["active"] = True
                    except socket.timeout: pass
                    sock.setsockopt(socket.IPPROTO_IP,socket.IP_DROP_MEMBERSHIP,mreq)
                except: pass
            sock.close()
        except: pass

    result_q.put(list(results.values()))


# ─── Ana Uygulama ─────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Analyzer Pro v3.0")
        self.geometry("1480x900"); self.minsize(1100,720)
        self.configure(bg=BG)

        self.scanning = False; self.devices = []; self.net_info = {}
        self._found = 0; self._ping_data = []
        self._vendor_counts = defaultdict(int)
        self._port_counts   = defaultdict(int)

        self._setup_styles()
        self._build_ui()
        self.after(400, self._load_net)

    def _setup_styles(self):
        plt.rcParams.update({
            "figure.facecolor":CHART_BG,"axes.facecolor":CHART_BG,
            "axes.edgecolor":CHART_GRID,"axes.labelcolor":GRAY,
            "xtick.color":GRAY2,"ytick.color":GRAY2,"text.color":WHITE,
            "grid.color":CHART_GRID,"grid.linestyle":"--","grid.alpha":0.5,
            "font.family":"Segoe UI","font.size":8,
        })
        s = ttk.Style(); s.theme_use("clam")
        s.configure("TV.Treeview", background=BG2,foreground=WHITE,
            fieldbackground=BG2,rowheight=27,font=("Consolas",9),borderwidth=0)
        s.configure("TV.Treeview.Heading", background=BG3,foreground=CYAN,
            font=("Segoe UI",9,"bold"),relief="flat",padding=4)
        s.map("TV.Treeview",background=[("selected",BLUE)],foreground=[("selected",WHITE)])
        s.configure("PB.Horizontal.TProgressbar",
            troughcolor=BG3,background=BLUE,borderwidth=0,thickness=5)
        s.configure("NB.TNotebook", background=BG, borderwidth=0)
        s.configure("NB.TNotebook.Tab", background=BG3,foreground=GRAY,
            font=("Segoe UI",9,"bold"),padding=[14,6])
        s.map("NB.TNotebook.Tab",
            background=[("selected",BLUE)],foreground=[("selected",WHITE)])

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        body = tk.Frame(self,bg=BG); body.pack(fill="both",expand=True)
        left = tk.Frame(body,bg=BG,width=295)
        left.pack(side="left",fill="y",padx=(10,5),pady=8)
        left.pack_propagate(False)
        self._build_left(left)
        right = tk.Frame(body,bg=BG)
        right.pack(side="left",fill="both",expand=True,padx=(5,10),pady=8)
        self._build_tabs(right)
        self._build_statusbar()

    def _build_header(self):
        hdr = tk.Frame(self,bg=BG2); hdr.pack(fill="x")
        left = tk.Frame(hdr,bg=BG2); left.pack(side="left",padx=18,pady=9)
        self._dot_cv = tk.Canvas(left,width=12,height=12,bg=BG2,highlightthickness=0)
        self._dot_cv.pack(side="left",padx=(0,8))
        self._dot = self._dot_cv.create_oval(1,1,11,11,fill=GREEN,outline="")
        self._dp = 0; self._anim_dot()
        tk.Label(left,text="Network Analyzer Pro",font=("Segoe UI",16,"bold"),
            fg=WHITE,bg=BG2).pack(side="left")
        tk.Label(left,text="  v3.0",font=("Segoe UI",9),fg=GRAY2,bg=BG2).pack(side="left")
        self._clock = tk.Label(hdr,text="",font=("Consolas",10),fg=CYAN,bg=BG2)
        self._clock.pack(side="left",padx=28); self._tick_clock()
        right = tk.Frame(hdr,bg=BG2); right.pack(side="right",padx=16,pady=8)
        self.stop_btn = self._mkbtn(right,"■ DURDUR",RED,self.stop_scan,state="disabled")
        self.stop_btn.pack(side="right",padx=3)
        self.scan_btn = self._mkbtn(right,"▶ AG TARA",GREEN,self.start_scan)
        self.scan_btn.pack(side="right",padx=3)
        pb_row = tk.Frame(self,bg=BG3,pady=2); pb_row.pack(fill="x")
        self.pb = ttk.Progressbar(pb_row,style="PB.Horizontal.TProgressbar",
            mode="determinate",maximum=100); self.pb.pack(fill="x")
        self._pblbl = tk.Label(pb_row,text="Hazir",font=("Segoe UI",8),
            fg=GRAY2,bg=BG3); self._pblbl.pack(side="right",padx=8)

    def _mkbtn(self,p,text,color,cmd,state="normal"):
        dark={GREEN:"#064e3b",RED:"#450a0a",BLUE:"#1e3a5f",
              ORANGE:"#451a03",CYAN:"#0c3040",PURPLE:"#2e1065"}.get(color,BG3)
        b = tk.Button(p,text=text,font=("Segoe UI",10,"bold"),
            bg=dark,fg=WHITE,activebackground=color,activeforeground=WHITE,
            relief="flat",padx=16,pady=7,cursor="hand2",command=cmd,state=state)
        b.bind("<Enter>",lambda e,b=b,c=color:b.config(bg=c) if b["state"]!="disabled" else None)
        b.bind("<Leave>",lambda e,b=b,d=dark:b.config(bg=d) if b["state"]!="disabled" else None)
        return b

    # ── Sol Panel ─────────────────────────────────────────────────────────────
    def _build_left(self, p):
        self._build_netcard(p)
        self._build_stats_card(p)
        self._build_vendor_chart(p)

    def _lcard(self,p,title):
        f = tk.Frame(p,bg=BG2); f.pack(fill="x",pady=(0,5))
        tk.Frame(f,bg=BG3,padx=10,pady=5).pack(fill="x")
        f.pack_slaves()[-1].pack(fill="x")
        tk.Label(f.pack_slaves()[-1],text=title,font=("Segoe UI",8,"bold"),
            fg=CYAN,bg=BG3).pack(side="left")
        body = tk.Frame(f,bg=BG2,padx=10,pady=7); body.pack(fill="x")
        return body

    def _build_netcard(self,p):
        c = self._lcard(p,"AG BILGILERI"); self._nlbls={}
        for lbl,key,col in [("IP Adresim","ip",BLUE2),("Ag Gecidi","gw",ORANGE),
            ("Alt Ag","mask",GRAY),("Arayuz","iface",CYAN),
            ("Ag Araligi","net",GREEN2),("Host Sayisi","hosts",PURPLE)]:
            row=tk.Frame(c,bg=BG2); row.pack(fill="x",pady=2)
            tk.Label(row,text=f"{lbl}:",font=("Segoe UI",8),fg=GRAY2,
                bg=BG2,width=12,anchor="w").pack(side="left")
            v=tk.Label(row,text="—",font=("Consolas",9,"bold"),fg=col,bg=BG2,anchor="w")
            v.pack(side="left",fill="x",expand=True); self._nlbls[key]=v

    def _build_stats_card(self,p):
        f=tk.Frame(p,bg=BG2); f.pack(fill="x",pady=(0,5))
        tk.Frame(f,bg=BG3,padx=10,pady=5).pack(fill="x")
        f.pack_slaves()[-1].pack(fill="x")
        tk.Label(f.pack_slaves()[-1],text="ISTATISTIKLER",
            font=("Segoe UI",8,"bold"),fg=CYAN,bg=BG3).pack(side="left")
        g=tk.Frame(f,bg=BG2,padx=8,pady=6); g.pack(fill="x"); self._svs={}
        for i,(lbl,key,col,val) in enumerate([
            ("Cihaz","found",GREEN,"0"),("Ping Ort.","avg",CYAN,"—"),
            ("Acik Port","port",ORANGE,"0"),("SNMP","snmp",PURPLE,"0")]):
            cell=tk.Frame(g,bg=BG3,padx=6,pady=5)
            cell.grid(row=i//2,column=i%2,padx=3,pady=3,sticky="nsew")
            g.columnconfigure(i%2,weight=1)
            v=tk.Label(cell,text=val,font=("Segoe UI",16,"bold"),fg=col,bg=BG3)
            v.pack(); tk.Label(cell,text=lbl,font=("Segoe UI",7),fg=GRAY2,bg=BG3).pack()
            self._svs[key]=v

    def _build_vendor_chart(self,p):
        f=tk.Frame(p,bg=BG2); f.pack(fill="both",expand=True,pady=(0,5))
        tk.Frame(f,bg=BG3,padx=10,pady=5).pack(fill="x")
        f.pack_slaves()[-1].pack(fill="x")
        tk.Label(f.pack_slaves()[-1],text="URETICI DAGILIMI",
            font=("Segoe UI",8,"bold"),fg=CYAN,bg=BG3).pack(side="left")
        self._vfig=Figure(figsize=(2.8,2.6),dpi=80)
        self._vax=self._vfig.add_subplot(111)
        self._vfig.patch.set_facecolor(CHART_BG)
        self._vax.set_facecolor(CHART_BG); self._vax.axis("off")
        self._vax.text(0.5,0.5,"Tarama bekleniyor",ha="center",va="center",
            color=GRAY2,fontsize=9,transform=self._vax.transAxes)
        vc=FigureCanvasTkAgg(self._vfig,master=f)
        vc.get_tk_widget().pack(fill="both",expand=True)
        self._vcv=vc

    # ── Tab paneli ────────────────────────────────────────────────────────────
    def _build_tabs(self,p):
        nb = ttk.Notebook(p,style="NB.TNotebook")
        nb.pack(fill="both",expand=True)

        # Tab 1: Cihazlar
        t1=tk.Frame(nb,bg=BG); nb.add(t1,text="  🖥  Cihazlar  ")
        self._build_device_tab(t1)

        # Tab 2: Port Tarama
        t2=tk.Frame(nb,bg=BG); nb.add(t2,text="  🔍  Port Tarama  ")
        self._build_port_tab(t2)

        # Tab 3: SNMP
        t3=tk.Frame(nb,bg=BG); nb.add(t3,text="  📡  SNMP Analizi  ")
        self._build_snmp_tab(t3)

        # Tab 4: Multicast
        t4=tk.Frame(nb,bg=BG); nb.add(t4,text="  📶  Multicast  ")
        self._build_multicast_tab(t4)

        self._nb = nb

    # ── Tab 1: Cihazlar ───────────────────────────────────────────────────────
    def _build_device_tab(self,p):
        cols=("#","IP Adresi","MAC Adresi","Hostname","Uretici","Durum","Gecikme","Acik Portlar")
        self.tree=ttk.Treeview(p,style="TV.Treeview",columns=cols,
            show="headings",selectmode="browse")
        for col,w in zip(cols,[36,125,150,200,140,68,88,260]):
            self.tree.heading(col,text=col,anchor="w")
            self.tree.column(col,width=w,minwidth=30,anchor="w")
        vsb=ttk.Scrollbar(p,orient="vertical",command=self.tree.yview)
        hsb=ttk.Scrollbar(p,orient="horizontal",command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set,xscrollcommand=hsb.set)
        self.tree.grid(row=0,column=0,sticky="nsew")
        vsb.grid(row=0,column=1,sticky="ns")
        hsb.grid(row=1,column=0,sticky="ew")
        p.rowconfigure(0,weight=1); p.columnconfigure(0,weight=1)
        self.tree.tag_configure("gw",foreground=ORANGE,font=("Consolas",9,"bold"))
        self.tree.tag_configure("ok",foreground=GREEN2)
        self.tree.tag_configure("alt",background="#151e2d")
        ctx=tk.Menu(self,tearoff=0,bg=BG3,fg=WHITE,
            activebackground=BLUE,activeforeground=WHITE)
        ctx.add_command(label="🔍 Tam Port Tarama",command=self._deep_scan_selected)
        ctx.add_command(label="📡 SNMP Sorgula",  command=self._snmp_scan_selected)
        ctx.add_command(label="📋 Kopyala",        command=self._copy_row)
        ctx.add_command(label="ℹ  Detay",          command=lambda:self._show_detail(None))
        self.tree.bind("<Button-3>",
            lambda e:(self.tree.selection_set(self.tree.identify_row(e.y)),
                      ctx.post(e.x_root,e.y_root)))
        self.tree.bind("<Double-1>",self._show_detail)

    # ── Tab 2: Port Tarama ────────────────────────────────────────────────────
    def _build_port_tab(self,p):
        # Kontrol satiri
        ctrl=tk.Frame(p,bg=BG2,pady=8); ctrl.pack(fill="x",padx=8)
        tk.Label(ctrl,text="Hedef IP:",font=("Segoe UI",10),
            fg=GRAY,bg=BG2).pack(side="left",padx=(8,4))
        self._port_ip=tk.StringVar()
        e=tk.Entry(ctrl,textvariable=self._port_ip,
            font=("Consolas",10),bg=BG3,fg=WHITE,
            insertbackground=WHITE,relief="flat",width=18)
        e.pack(side="left",padx=4,ipady=4)
        self._port_scan_btn=self._mkbtn(ctrl,"▶ TARA",BLUE,self._start_port_scan)
        self._port_scan_btn.pack(side="left",padx=8)
        self._port_progress=tk.Label(ctrl,text="",font=("Segoe UI",9),
            fg=ORANGE,bg=BG2); self._port_progress.pack(side="left",padx=10)
        self._port_pb=ttk.Progressbar(ctrl,style="PB.Horizontal.TProgressbar",
            mode="determinate",maximum=100,length=200)
        self._port_pb.pack(side="right",padx=12)
        # Sonuc tablosu
        cols2=("Port","Durum","Servis","Banner")
        self._port_tree=ttk.Treeview(p,style="TV.Treeview",columns=cols2,
            show="headings",selectmode="browse")
        for col,w in zip(cols2,[80,80,140,600]):
            self._port_tree.heading(col,text=col,anchor="w")
            self._port_tree.column(col,width=w,minwidth=40,anchor="w")
        vsb=ttk.Scrollbar(p,orient="vertical",command=self._port_tree.yview)
        self._port_tree.configure(yscrollcommand=vsb.set)
        self._port_tree.pack(side="left",fill="both",expand=True,padx=(8,0),pady=8)
        vsb.pack(side="left",fill="y",pady=8,padx=(0,8))
        self._port_tree.tag_configure("open",foreground=GREEN2)
        self._port_tree.tag_configure("alt",background="#151e2d")

    # ── Tab 3: SNMP ───────────────────────────────────────────────────────────
    def _build_snmp_tab(self,p):
        ctrl=tk.Frame(p,bg=BG2,pady=8); ctrl.pack(fill="x",padx=8)
        tk.Label(ctrl,text="Hedef IP:",font=("Segoe UI",10),fg=GRAY,bg=BG2).pack(side="left",padx=(8,4))
        self._snmp_ip=tk.StringVar()
        tk.Entry(ctrl,textvariable=self._snmp_ip,font=("Consolas",10),
            bg=BG3,fg=WHITE,insertbackground=WHITE,relief="flat",width=18
        ).pack(side="left",padx=4,ipady=4)
        tk.Label(ctrl,text="Community:",font=("Segoe UI",10),fg=GRAY,bg=BG2).pack(side="left",padx=(12,4))
        self._snmp_comm=tk.StringVar(value="public")
        tk.Entry(ctrl,textvariable=self._snmp_comm,font=("Consolas",10),
            bg=BG3,fg=WHITE,insertbackground=WHITE,relief="flat",width=12
        ).pack(side="left",padx=4,ipady=4)
        self._mkbtn(ctrl,"📡 TUM CIHAZLARI TARA",PURPLE,self._snmp_scan_all).pack(side="left",padx=8)
        self._mkbtn(ctrl,"▶ SORGULA",CYAN,self._snmp_scan_single).pack(side="left",padx=4)

        tbl_frame=tk.Frame(p,bg=BG); tbl_frame.pack(fill="both",expand=True,padx=8,pady=8)
        cols3=("IP","sysName","sysDescr","sysUpTime","sysLocation","sysContact","Community")
        self._snmp_tree=ttk.Treeview(tbl_frame,style="TV.Treeview",columns=cols3,
            show="headings",selectmode="browse")
        for col,w in zip(cols3,[120,130,280,100,160,140,80]):
            self._snmp_tree.heading(col,text=col,anchor="w")
            self._snmp_tree.column(col,width=w,minwidth=40,anchor="w")
        vsb=ttk.Scrollbar(tbl_frame,orient="vertical",command=self._snmp_tree.yview)
        hsb=ttk.Scrollbar(tbl_frame,orient="horizontal",command=self._snmp_tree.xview)
        self._snmp_tree.configure(yscrollcommand=vsb.set,xscrollcommand=hsb.set)
        self._snmp_tree.grid(row=0,column=0,sticky="nsew")
        vsb.grid(row=0,column=1,sticky="ns")
        hsb.grid(row=1,column=0,sticky="ew")
        tbl_frame.rowconfigure(0,weight=1); tbl_frame.columnconfigure(0,weight=1)
        self._snmp_tree.tag_configure("found",foreground=GREEN2)
        self._snmp_tree.tag_configure("noresp",foreground=GRAY2)
        self._snmp_tree.tag_configure("alt",background="#151e2d")

    # ── Tab 4: Multicast ──────────────────────────────────────────────────────
    def _build_multicast_tab(self,p):
        ctrl=tk.Frame(p,bg=BG2,pady=8); ctrl.pack(fill="x",padx=8)
        self._mc_btn=self._mkbtn(ctrl,"📶 MULTICAST TARA",ORANGE,self._start_multicast)
        self._mc_btn.pack(side="left",padx=8)
        self._mc_status=tk.Label(ctrl,text="",font=("Segoe UI",9),fg=CYAN,bg=BG2)
        self._mc_status.pack(side="left",padx=10)
        tk.Label(ctrl,text=f"Scapy: {'✓ Aktif' if SCAPY_OK else '✗ Yok (soket modu)'}",
            font=("Segoe UI",8),fg=GREEN2 if SCAPY_OK else ORANGE,bg=BG2
        ).pack(side="right",padx=16)

        # Sonuc tablosu
        cols4=("Grup IP","Grup Adi","Protokol","Kaynak","Durum")
        self._mc_tree=ttk.Treeview(p,style="TV.Treeview",columns=cols4,
            show="headings",selectmode="browse")
        for col,w in zip(cols4,[160,220,120,300,100]):
            self._mc_tree.heading(col,text=col,anchor="w")
            self._mc_tree.column(col,width=w,minwidth=60,anchor="w")
        vsb=ttk.Scrollbar(p,orient="vertical",command=self._mc_tree.yview)
        self._mc_tree.configure(yscrollcommand=vsb.set)
        self._mc_tree.pack(side="left",fill="both",expand=True,padx=(8,0),pady=8)
        vsb.pack(side="left",fill="y",pady=8,padx=(0,8))
        self._mc_tree.tag_configure("active",foreground=GREEN2)
        self._mc_tree.tag_configure("inactive",foreground=GRAY2)
        self._mc_tree.tag_configure("alt",background="#151e2d")

        # Alt grafik
        self._mc_fig=Figure(figsize=(10,1.8),dpi=80)
        self._mc_ax =self._mc_fig.add_subplot(111)
        self._mc_fig.patch.set_facecolor(CHART_BG)
        self._mc_ax.set_facecolor(CHART_BG); self._mc_ax.axis("off")
        FigureCanvasTkAgg(self._mc_fig,master=p).get_tk_widget().pack(
            fill="x",padx=8,pady=(0,8))
        self._mc_canvas=FigureCanvasTkAgg(self._mc_fig,master=p)

    def _build_statusbar(self):
        bar=tk.Frame(self,bg=BG3,pady=3); bar.pack(fill="x",side="bottom")
        self._stlbl=tk.Label(bar,text="●  Hazir",font=("Segoe UI",9),
            fg=GREEN,bg=BG3); self._stlbl.pack(side="left",padx=14)
        self._fndlbl=tk.Label(bar,text="",font=("Segoe UI",9,"bold"),
            fg=ORANGE,bg=BG3); self._fndlbl.pack(side="right",padx=14)
        tk.Label(bar,text=f"SNMP: {'pysnmp' if PYSNMP_OK else 'BER/UDP'}  |  "
            f"Scapy: {'aktif' if SCAPY_OK else 'soket modu'}",
            font=("Segoe UI",8),fg=GRAY2,bg=BG3).pack(side="right",padx=20)

    # ── Animasyon / Saat ──────────────────────────────────────────────────────
    def _anim_dot(self):
        self._dp=(self._dp+1)%20
        a=0.4+0.6*abs(math.sin(self._dp*math.pi/20))
        if self.scanning: c=f"#{int(16*a):02x}{int(185*a):02x}{int(129*a):02x}"
        else:             c=f"#{int(59*a):02x}{int(130*a):02x}{int(246*a):02x}"
        self._dot_cv.itemconfig(self._dot,fill=c)
        self.after(60,self._anim_dot)

    def _tick_clock(self):
        self._clock.config(text=datetime.now().strftime("  %d.%m.%Y   %H:%M:%S"))
        self.after(1000,self._tick_clock)

    # ── Ag keşfi ─────────────────────────────────────────────────────────────
    def _load_net(self):
        try:
            info=_get_network_info(); self.net_info=info
            hosts=list(info["network"].hosts())
            self._nlbls["ip"].config(text=info["ip"])
            self._nlbls["gw"].config(text=info["gateway"])
            self._nlbls["mask"].config(text=info["netmask"])
            self._nlbls["iface"].config(text=info["iface"])
            self._nlbls["net"].config(text=str(info["network"]))
            self._nlbls["hosts"].config(text=f"{len(hosts)} host")
            self._setstatus(f"●  Hazir — {info['ip']}  |  {len(hosts)} host",GREEN)
        except Exception as e:
            self._setstatus(f"●  HATA: {e}",RED)

    def start_scan(self):
        if self.scanning or not self.net_info: return
        self.scanning=True; self.devices.clear(); self._found=0
        self._ping_data.clear(); self._vendor_counts.clear(); self._port_counts.clear()
        for item in self.tree.get_children(): self.tree.delete(item)
        self.scan_btn.config(state="disabled"); self.stop_btn.config(state="normal")
        self.pb["value"]=0; self._setstatus("●  Taranıyor...",ORANGE)
        self._vax.clear(); self._vax.axis("off")
        self._vax.text(0.5,0.5,"Taranıyor...",ha="center",va="center",
            color=ORANGE,fontsize=9,transform=self._vax.transAxes)
        self._vcv.draw()
        threading.Thread(target=self._run_scan,daemon=True).start()

    def stop_scan(self):
        self.scanning=False; self._setstatus("●  Durduruldu",RED)
        self.scan_btn.config(state="normal"); self.stop_btn.config(state="disabled")

    def _run_scan(self):
        try:
            hosts=list(self.net_info["network"].hosts()); total=len(hosts); done=0
            with ThreadPoolExecutor(max_workers=60) as ex:
                fmap={ex.submit(_scan_one,ip,self.net_info["gateway"]):ip for ip in hosts}
                for fut in as_completed(fmap):
                    if not self.scanning:
                        ex.shutdown(wait=False,cancel_futures=True); break
                    done+=1; pct=int(done/total*100)
                    ip_s=str(fmap[fut]); res=fut.result()
                    self.after(0,lambda p=pct,ip=ip_s:self._tick(p,ip))
                    if res:
                        self._found+=1; self.devices.append(res)
                        self.after(0,lambda d=res,n=self._found:self._add_row(d,n))
            if self.scanning: self.after(0,self._scan_done)
        except Exception as e:
            self.after(0,lambda:self._setstatus(f"HATA:{e}",RED))
            self.after(0,self._scan_done)

    def _tick(self,pct,ip):
        self.pb["value"]=pct; self._pblbl.config(text=f"%{pct}  —  {ip}")

    def _add_row(self,d,n):
        ps="  ".join(f"{p}({SERVICE_MAP.get(p,'?')})" for p in d["ports"]) if d["ports"] else "—"
        is_gw=(d["ip"]==self.net_info.get("gateway",""))
        tag="gw" if is_gw else "ok"
        if n%2==0: tag=(tag,"alt")
        self.tree.insert("","end",values=(
            n,d["ip"],d["mac"],d["hostname"],d["vendor"],"Online",f"{d['ms']} ms",ps
        ),tags=tag); self.tree.yview_moveto(1)
        self._ping_data.append(d["ms"])
        self._vendor_counts[d["vendor"]]+=1
        for p in d["ports"]: self._port_counts[SERVICE_MAP.get(p,str(p))]+=1
        self._fndlbl.config(text=f"  {n} cihaz  ")
        self._update_stats(); self._update_vendor(); self._update_charts()

    def _scan_done(self):
        self.scanning=False
        self.scan_btn.config(state="normal"); self.stop_btn.config(state="disabled")
        self.pb["value"]=100; self._pblbl.config(text="Tamamlandi")
        self._setstatus(f"●  Tamamlandi — {self._found} cihaz bulundu",GREEN)
        self._update_vendor(); self._update_charts()

    # ── Port Tarama (Tab 2) ───────────────────────────────────────────────────
    def _deep_scan_selected(self):
        sel=self.tree.selection()
        if not sel: return
        ip=self.tree.item(sel[0],"values")[1]
        self._port_ip.set(ip); self._nb.select(1); self._start_port_scan()

    def _start_port_scan(self):
        ip=self._port_ip.get().strip()
        if not ip: return
        for item in self._port_tree.get_children(): self._port_tree.delete(item)
        self._port_scan_btn.config(state="disabled")
        self._port_progress.config(text=f"{ip} taranıyor...")
        self._port_pb["value"]=0
        def run():
            def cb(pct,port):
                self.after(0,lambda p=pct,pt=port:(
                    self._port_pb.__setitem__("value",p),
                    self._port_progress.config(text=f"%{p}  port:{pt}")))
            results=_scan_ports_deep(ip,progress_cb=cb)
            self.after(0,lambda r=results:self._show_port_results(ip,r))
        threading.Thread(target=run,daemon=True).start()

    def _show_port_results(self,ip,results):
        for item in self._port_tree.get_children(): self._port_tree.delete(item)
        for i,(port,svc,banner) in enumerate(results):
            tag=("open","alt") if i%2==0 else ("open",)
            self._port_tree.insert("","end",
                values=(port,"ACIK",svc,banner),tags=tag)
        self._port_scan_btn.config(state="normal")
        self._port_progress.config(
            text=f"Tamamlandi — {len(results)} acik port ({ip})")
        self._port_pb["value"]=100

    # ── SNMP (Tab 3) ──────────────────────────────────────────────────────────
    def _snmp_scan_selected(self):
        sel=self.tree.selection()
        if not sel: return
        ip=self.tree.item(sel[0],"values")[1]
        self._snmp_ip.set(ip); self._nb.select(2); self._snmp_scan_single()

    def _snmp_scan_single(self):
        ip=self._snmp_ip.get().strip()
        if not ip: return
        comm=self._snmp_comm.get().strip() or "public"
        threading.Thread(target=self._do_snmp,args=([ip],[comm]),daemon=True).start()

    def _snmp_scan_all(self):
        if not self.devices: return
        ips=[d["ip"] for d in self.devices]
        for item in self._snmp_tree.get_children(): self._snmp_tree.delete(item)
        threading.Thread(target=self._do_snmp,args=(ips,SNMP_COMMUNITIES),daemon=True).start()

    def _do_snmp(self,ips,communities):
        found=0
        for n,ip in enumerate(ips):
            self.after(0,lambda i=ip,t=n+1,tot=len(ips):
                self._setstatus(f"●  SNMP taranıyor {i} ({t}/{tot})...",PURPLE))
            result=None; used_comm=None
            for comm in communities:
                res=snmp_get(ip,comm,list(SNMP_OIDS.values()))
                if res:
                    result=res; used_comm=comm; found+=1
                    self._svs["snmp"].config(text=str(found)); break
            row=(
                ip,
                result.get("sysName","—") if result else "—",
                result.get("sysDescr","—")[:60] if result else "Yanit yok",
                result.get("sysUpTime","—") if result else "—",
                result.get("sysLocation","—") if result else "—",
                result.get("sysContact","—") if result else "—",
                used_comm or "—",
            )
            tag=("found","alt") if (result and n%2==0) else \
                ("found",) if result else \
                ("noresp","alt") if n%2==0 else ("noresp",)
            self.after(0,lambda r=row,t=tag:
                self._snmp_tree.insert("","end",values=r,tags=t))
        self.after(0,lambda:self._setstatus(
            f"●  SNMP tamamlandi — {found}/{len(ips)} cihaz yanit verdi",GREEN))

    # ── Multicast (Tab 4) ─────────────────────────────────────────────────────
    def _start_multicast(self):
        if not self.net_info: return
        self._mc_btn.config(state="disabled")
        self._mc_status.config(text="Taranıyor...")
        for item in self._mc_tree.get_children(): self._mc_tree.delete(item)
        q=queue.Queue()
        local_ip=self.net_info["ip"]
        threading.Thread(target=detect_multicast,args=(local_ip,q),daemon=True).start()
        self.after(500,lambda:self._poll_mc(q))

    def _poll_mc(self,q):
        try:
            results=q.get_nowait()
            self._show_mc_results(results)
        except queue.Empty:
            self.after(500,lambda:self._poll_mc(q))

    def _show_mc_results(self,results):
        active=[r for r in results if r["active"]]
        inactive=[r for r in results if not r["active"]]
        all_rows=active+inactive
        for i,r in enumerate(all_rows):
            tag=("active","alt") if (r["active"] and i%2==0) else \
                ("active",) if r["active"] else \
                ("inactive","alt") if i%2==0 else ("inactive",)
            self._mc_tree.insert("","end",values=(
                r["group"],r["name"],r["proto"],r["source"],
                "✓ AKTİF" if r["active"] else "✗ Sessiz",
            ),tags=tag)
        self._mc_btn.config(state="normal")
        self._mc_status.config(
            text=f"Tamamlandi — {len(active)} aktif / {len(inactive)} sessiz grup")
        self._update_mc_chart(active,inactive)

    def _update_mc_chart(self,active,inactive):
        ax=self._mc_ax; ax.clear(); ax.set_facecolor(CHART_BG)
        if not active and not inactive: return
        labels=["Aktif","Sessiz"]; sizes=[len(active),len(inactive)]
        colors=[GREEN,GRAY2]
        bars=ax.barh(labels,sizes,color=colors,height=0.5,edgecolor=BG)
        for bar,val in zip(bars,sizes):
            ax.text(bar.get_width()+0.1,bar.get_y()+bar.get_height()/2,
                str(val),va="center",color=WHITE,fontsize=9)
        ax.set_xlabel("Grup sayisi",color=GRAY2,fontsize=8)
        ax.tick_params(colors=GRAY2,labelsize=8)
        for sp in ax.spines.values(): sp.set_edgecolor(CHART_GRID)
        self._mc_fig.tight_layout(pad=0.5)
        try: self._mc_canvas.draw()
        except: pass

    # ── Grafik güncellemeleri ─────────────────────────────────────────────────
    def _update_stats(self):
        self._svs["found"].config(text=str(self._found))
        avg=f"{sum(self._ping_data)/len(self._ping_data):.0f}ms" if self._ping_data else "—"
        self._svs["avg"].config(text=avg)
        self._svs["port"].config(text=str(sum(self._port_counts.values())))

    def _update_vendor(self):
        if not self._vendor_counts: return
        ax=self._vax; ax.clear(); ax.set_facecolor(CHART_BG)
        labels=list(self._vendor_counts.keys())
        sizes =list(self._vendor_counts.values())
        colors=VCOLS[:len(labels)]
        wedges,_,auts=ax.pie(sizes,labels=None,colors=colors,
            autopct=lambda p:f"{p:.0f}%" if p>5 else "",startangle=90,
            wedgeprops={"linewidth":1.2,"edgecolor":BG},pctdistance=0.75)
        for a in auts: a.set_fontsize(7); a.set_color(WHITE)
        ax.add_patch(plt.Circle((0,0),0.55,fc=CHART_BG))
        ax.text(0,0,f"{self._found}\ncihaz",ha="center",va="center",
            color=WHITE,fontsize=9,fontweight="bold")
        patches=[mpatches.Patch(color=c,label=l) for c,l in zip(colors,labels)]
        ax.legend(handles=patches,loc="lower center",
            bbox_to_anchor=(0.5,-0.1),ncol=2,fontsize=6.5,
            frameon=False,labelcolor=WHITE,handlelength=0.8)
        ax.set_aspect("equal")
        self._vfig.tight_layout(pad=0.2); self._vcv.draw()

    def _update_charts(self):
        pass  # Genisletmek icin yer bırakıldı

    # ── Yardımcılar ───────────────────────────────────────────────────────────
    def _setstatus(self,text,color):
        self._stlbl.config(text=text,fg=color)

    def _copy_row(self):
        sel=self.tree.selection()
        if not sel: return
        self.clipboard_clear()
        self.clipboard_append("  |  ".join(str(v) for v in self.tree.item(sel[0],"values")))

    def _show_detail(self,event):
        sel=self.tree.selection()
        if not sel: return
        vals=self.tree.item(sel[0],"values")
        keys=["No","IP","MAC","Hostname","Uretici","Durum","Gecikme","Portlar"]
        colors_map={"IP":BLUE2,"MAC":ORANGE,"Hostname":GREEN2,"Uretici":PURPLE,
                    "Durum":GREEN,"Gecikme":CYAN,"Portlar":PINK}
        win=tk.Toplevel(self); win.title(f"Detay — {vals[1]}")
        win.configure(bg=BG2); win.geometry("440x360"); win.resizable(False,False)
        tk.Label(win,text=f"  {vals[1]}",font=("Segoe UI",14,"bold"),
            fg=CYAN,bg=BG2,pady=10).pack(fill="x")
        tk.Frame(win,bg=BG4,height=1).pack(fill="x",padx=20)
        c=tk.Frame(win,bg=BG2,padx=24,pady=10); c.pack(fill="both",expand=True)
        for k,v in zip(keys[1:],vals[1:]):
            row=tk.Frame(c,bg=BG2); row.pack(fill="x",pady=3)
            tk.Label(row,text=f"{k}:",font=("Segoe UI",9),fg=GRAY,
                bg=BG2,width=12,anchor="w").pack(side="left")
            tk.Label(row,text=str(v),font=("Consolas",9,"bold"),
                fg=colors_map.get(k,WHITE),bg=BG2,anchor="w",
                wraplength=260,justify="left").pack(side="left",fill="x",expand=True)
        tk.Frame(win,bg=BG4,height=1).pack(fill="x",padx=20,pady=(6,0))
        tk.Button(win,text="Kapat",command=win.destroy,
            bg=BG3,fg=WHITE,relief="flat",padx=22,pady=7,
            font=("Segoe UI",9),cursor="hand2",
            activebackground=BLUE,activeforeground=WHITE).pack(pady=8)


# ─── Giriş ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    App().mainloop()
