#!/usr/bin/env python3
"""
Arduino ESP OTA Diagnostic
--------------------------
Checks why an ESP8266 or ESP32 doesn't show up as a network port in the Arduino IDE,
or why an OTA upload fails.

Tests:
  1. Local network  - which PC interface reaches the device, same subnet?
  2. Ping           - is the device alive?
  3. TCP ports      - is the web server / other ports open?
  4. OS resolver    - can this PC resolve <hostname>.local (Bonjour/avahi)?
  5. mDNS direct    - ask the device itself (unicast to :5353) what it advertises
  6. mDNS multicast - does discovery via multicast reach this PC?
  7. Zeroconf       - browse _arduino._tcp like the IDE does (optional package)
  8. OTA handshake  - send an espota-style UDP invitation to the OTA port
  9. Passive listen - bind UDP 5353, join the mDNS group and watch whether the
                      ESP's announcements (or anyone's) actually reach this PC
 10. Callback test  - full OTA handshake incl. password; verifies the ESP can open the
                      TCP connection BACK to the PC (the step behind espota's
                      'No response from device'). Runs under the Arduino IDE's own
                      python3.exe so the firewall verdict matches the real upload
 11. Firewall check - (Windows) inbound rules for the uploader the IDE runs
                      (ESP8266: bundled python3.exe, ESP32: espota.exe), plus a
                      one-click 'add allow rule' (asks for admin rights)

Only the Python standard library is required (tkinter included).
Optional: pip install zeroconf   (enables test 7)

Run:  python main.py
"""

import base64
import glob
import hashlib
import json
import os
import platform
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
import tkinter.font as tkfont

try:
    from zeroconf import Zeroconf
    HAVE_ZEROCONF = True
except ImportError:
    HAVE_ZEROCONF = False

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
IS_WINDOWS = platform.system() == "Windows"


# --------------------------------------------------------------------------
# Minimal mDNS / DNS packet helpers (stdlib only)
# --------------------------------------------------------------------------
def dns_name(name):
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(questions):
    """questions: list of (name, qtype). Sets the QU (unicast-response) bit."""
    pkt = struct.pack("!HHHHHH", 0, 0, len(questions), 0, 0, 0)
    for name, qtype in questions:
        pkt += dns_name(name) + struct.pack("!HH", qtype, 0x8001)
    return pkt


def parse_name(data, off):
    labels, jumped, end, hops = [], False, None, 0
    while True:
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
            continue
        off += 1
        labels.append(data[off:off + length].decode("utf-8", "replace"))
        off += length
    if not jumped:
        end = off
    return ".".join(labels), end


def parse_packet(data):
    """Return list of (name, rtype, value) for A/PTR/SRV/TXT records."""
    records = []
    try:
        flags = struct.unpack("!H", data[2:4])[0]
        if not flags & 0x8000:          # not a response
            return records
        qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
        off = 12
        for _ in range(qd):
            _, off = parse_name(data, off)
            off += 4
        for _ in range(an + ns + ar):
            name, off = parse_name(data, off)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rd_off, rd = off, data[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                records.append((name, 1, socket.inet_ntoa(rd)))
            elif rtype == 12:
                records.append((name, 12, parse_name(data, rd_off)[0]))
            elif rtype == 33:
                _prio, _w, port = struct.unpack("!HHH", rd[:6])
                records.append((name, 33, (parse_name(data, rd_off + 6)[0], port)))
            elif rtype == 16:
                txt, i = [], 0
                while i < len(rd):
                    ln = rd[i]
                    txt.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                    i += 1 + ln
                records.append((name, 16, txt))
    except Exception:
        pass
    return records


def mdns_query(questions, dest, iface_ip=None, timeout=2.5):
    """Send an mDNS query, collect responses. Returns [(src_ip, records)]."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responses = []
    try:
        try:
            sock.bind((iface_ip or "", 0))
        except OSError:
            sock.bind(("", 0))
        if dest[0] == MDNS_GROUP:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            if iface_ip:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                socket.inet_aton(iface_ip))
        pkt = build_query(questions)
        sock.sendto(pkt, dest)
        t0, resent = time.time(), False
        while True:
            remaining = t0 + timeout - time.time()
            if remaining <= 0:
                break
            if not resent and time.time() - t0 > 1.0:
                sock.sendto(pkt, dest)
                resent = True
            sock.settimeout(min(0.3, remaining))
            try:
                data, addr = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except ConnectionResetError:   # Windows: ICMP port unreachable
                continue
            recs = parse_packet(data)
            if recs:
                responses.append((addr[0], recs))
    finally:
        sock.close()
    return responses


def summarize(responses):
    """Turn raw records into service entries:
       (service_type, instance, ip, port, txt_dict)"""
    ptr, srv, a, txt, srcof = {}, {}, {}, {}, {}
    for src, recs in responses:
        for name, rtype, val in recs:
            srcof[name] = src
            if rtype == 12:
                ptr.setdefault(name, set()).add(val)
                srcof[val] = src
            elif rtype == 33:
                srv[name] = val
            elif rtype == 1:
                a[name] = val
            elif rtype == 16:
                txt[name] = val
    out = []
    for svc, instances in ptr.items():
        for inst in instances:
            target, port = srv.get(inst, (None, None))
            ip = a.get(target) or srcof.get(inst) or srcof.get(target)
            kv = {}
            for item in txt.get(inst, []):
                if "=" in item:
                    k, v = item.split("=", 1)
                    kv[k] = v
            out.append((svc, inst, ip, port, kv))
    return out


# Common Espressif MAC prefixes (OUIs), not exhaustive: an ARP entry matching one is likely an ESP.
ESPRESSIF_OUIS = {
    "08:3a:f2", "08:d1:f9", "0c:b8:15", "0c:dc:7e", "10:06:1c", "10:52:1c", "14:2b:2f", "18:8b:0e",
    "18:fe:34", "1c:69:20", "1c:9d:c2", "24:0a:c4", "24:62:ab", "24:6f:28", "24:a1:60", "24:b2:de",
    "24:d7:eb", "24:dc:c3", "24:ec:4a", "2c:3a:e8", "2c:bc:bb", "2c:f4:32", "30:30:f9", "30:83:98",
    "30:ae:a4", "30:c6:f7", "34:85:18", "34:86:5d", "34:94:54", "34:ab:95", "34:b4:72", "3c:61:05",
    "3c:71:bf", "3c:84:27", "3c:e9:0e", "40:22:d8", "40:4c:ca", "40:91:51", "40:f5:20", "44:17:93",
    "48:27:e2", "48:31:b7", "48:3f:da", "48:55:19", "48:e7:29", "4c:11:ae", "4c:75:25", "4c:eb:d6",
    "50:02:91", "54:32:04", "54:43:b2", "58:bf:25", "58:cf:79", "5c:01:3b", "5c:cf:7f", "60:01:94",
    "60:55:f9", "64:b7:08", "64:e8:33", "68:67:25", "68:c6:3a", "70:03:9f", "70:04:1d", "70:b8:f6",
    "74:4d:bd", "78:21:84", "78:e3:6d", "7c:87:ce", "7c:9e:bd", "7c:df:a1", "80:64:6f", "80:7d:3a",
    "84:0d:8e", "84:cc:a8", "84:f3:eb", "84:f7:03", "84:fc:e6", "88:13:bf", "8c:4b:14", "8c:aa:b5",
    "8c:ce:4e", "90:38:0c", "94:3c:c6", "94:b5:55", "94:b9:7e", "94:e6:86", "98:cd:ac", "98:f4:ab",
    "9c:9c:1f", "a0:20:a6", "a0:76:4e", "a0:b7:65", "a4:7b:9d", "a4:cf:12", "a8:03:2a", "a8:42:e3",
    "ac:0b:fb", "ac:67:b2", "b0:a7:32", "b4:8a:0a", "b4:e6:2d", "b8:d6:1a", "b8:f0:09", "bc:dd:c2",
    "c0:49:ef", "c0:4e:30", "c4:4f:33", "c4:5b:be", "c4:de:e2", "c8:2b:96", "c8:c9:a3", "c8:f0:9e",
    "cc:50:e3", "cc:7b:5c", "cc:db:a7", "d4:8a:fc", "d4:d4:da", "d8:13:2a", "d8:3b:da", "d8:a0:1d",
    "d8:bf:c0", "dc:4f:22", "dc:54:75", "dc:da:0c", "e0:5a:1b", "e0:e2:e6", "e4:65:b8", "e4:b0:63",
    "e8:31:cd", "e8:68:e7", "e8:9f:6d", "e8:db:84", "ec:62:60", "ec:94:cb", "ec:da:3b", "ec:fa:bc",
    "f0:08:d1", "f0:9e:9e", "f4:12:fa", "f4:65:0b", "f4:cf:a2", "fc:f5:c4",
}


def read_arp_table():
    """(ip, mac) pairs from the OS neighbour cache, MACs normalised to aa:bb:cc:dd:ee:ff."""
    for cmd in (["arp", "-a"], ["ip", "neigh"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                                 creationflags=NO_WINDOW).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        pairs = []
        for line in out.splitlines():
            ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
            mac = re.search(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b", line)
            if ip and mac:
                mac = ":".join(x.zfill(2) for x in re.split("[:-]", mac.group(1))).lower()
                pairs.append((ip.group(1), mac))
        if pairs:
            return pairs
    return []


def route_ip(target):
    """Local IP address the OS would use to reach target."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


# --------------------------------------------------------------------------
# Arduino toolchain / firewall helpers
# --------------------------------------------------------------------------
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0   # hide console windows of child processes

# Runs in a *separate* interpreter, so the firewall sees the same executable the
# Arduino IDE uses (python3.exe in Arduino15). Config comes in on stdin as JSON
# (keeps the password off the command line); the result is one JSON line.
# Python 3.7 compatible. Mirrors espota.py: invitation -> AUTH -> callback.
CALLBACK_HELPER = r'''
import hashlib, json, socket, sys
cfg = json.loads(sys.stdin.read())
ip, port = cfg["ip"], int(cfg["port"])
pw, wait = cfg.get("password", ""), float(cfg.get("timeout", 10))

def out(stage, detail=""):
    print(json.dumps({"stage": stage, "detail": detail, "python": sys.executable}))
    sys.stdout.flush()
    sys.exit(0)

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.bind(("", 0))
tcp.listen(1)
lport = tcp.getsockname()[1]
md5 = hashlib.md5(b"ota-callback-test").hexdigest()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = ("0 %d 1024 %s\n" % (lport, md5)).encode()

def invite():
    udp.settimeout(2.5)
    for _ in range(3):
        udp.sendto(msg, (ip, port))
        try:
            return udp.recv(128).decode(errors="replace").strip()
        except socket.timeout:
            continue
        except ConnectionResetError:
            break
    return None

def auth(nonce, md5_password):
    # 32-char nonce: MD5 challenge (ESP8266, ESP32 before 3.3.1).
    # 64-char nonce: PBKDF2-HMAC-SHA256 challenge (ESP32 3.3.1+), as in espota.py.
    if len(nonce) == 32:
        cnonce = hashlib.md5(b"diagnostic-cnonce").hexdigest()
        passhash = hashlib.md5(pw.encode()).hexdigest()
        result = hashlib.md5(("%s:%s:%s" % (passhash, nonce, cnonce)).encode()).hexdigest()
    else:
        cnonce = hashlib.sha256(b"diagnostic-cnonce").hexdigest()
        passhash = (hashlib.md5 if md5_password else hashlib.sha256)(pw.encode()).hexdigest()
        key = hashlib.pbkdf2_hmac("sha256", passhash.encode(), (nonce + ":" + cnonce).encode(), 10000)
        result = hashlib.sha256((key.hex() + ":" + nonce + ":" + cnonce).encode()).hexdigest()
    udp.sendto(("200 %s %s\n" % (cnonce, result)).encode(), (ip, port))
    udp.settimeout(10)
    try:
        return udp.recv(128).decode(errors="replace").strip()
    except socket.timeout:
        out("auth_timeout")

reply = invite()
if reply is None:
    out("no_reply")
if reply.startswith("AUTH"):
    if not pw:
        out("need_password")
    nonce = reply.split()[1]
    answer = auth(nonce, md5_password=False)
    if answer != "OK" and len(nonce) == 64:
        # Devices that stored an MD5 password hash: espota retries with a fresh invitation
        reply = invite()
        if reply is None or not reply.startswith("AUTH"):
            out("auth_failed", answer)
        answer = auth(reply.split()[1], md5_password=True)
    if answer != "OK":
        out("auth_failed", answer)
elif not reply.startswith("OK"):
    out("unexpected", reply)
tcp.settimeout(wait)
try:
    conn, addr = tcp.accept()
    conn.close()
except socket.timeout:
    out("callback_timeout", "port %d" % lport)
out("callback_ok", addr[0])
'''


def arduino15_dir():
    if IS_WINDOWS:
        return os.path.join(os.environ.get("LOCALAPPDATA", ""), "Arduino15")
    if platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Arduino15")
    return os.path.expanduser("~/.arduino15")


# Board families. Each Arduino core has its own OTA port, uploader and mDNS setup.
CORES = {
    "esp8266": {"label": "ESP8266", "ota_port": 8266,
                "mdns_fix": 'ArduinoOTA.begin(false) + MDNS.addService("arduino", "tcp", 8266)'},
    "esp32": {"label": "ESP32", "ota_port": 3232,
              "mdns_fix": "ArduinoOTA.setMdnsEnabled(false) + MDNS.enableArduino(3232, true)"},
}


def find_ide_pythons(core):
    """Python interpreters bundled with a core (the ESP8266 IDE runs espota.py with these)."""
    pattern = os.path.join(arduino15_dir(), "packages", core, "tools", "python3", "*")
    names = ["python3.exe", "python.exe"] if IS_WINDOWS else ["python3", os.path.join("bin", "python3")]
    found = []
    for folder in sorted(glob.glob(pattern), reverse=True):
        for n in names:
            f = os.path.join(folder, n)
            if os.path.isfile(f):
                found.append(f)
                break
    return found


def find_espota(core):
    """espota uploaders shipped with a core, newest first. On Windows the ESP32 core runs espota.exe."""
    base = os.path.join(arduino15_dir(), "packages", core)
    found = []
    for name in (["espota.exe", "espota.py"] if IS_WINDOWS else ["espota.py"]):
        for pattern in (os.path.join(base, "hardware", core, "*", "tools", name),
                        os.path.join(base, "tools", "*", "*", name)):
            found += sorted(glob.glob(pattern), reverse=True)
    return found


def run_ps(script, timeout=40):
    """Run PowerShell (Windows). Returns CompletedProcess or None."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        return subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=timeout, creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None


FW_QUERY = r"""
$ErrorActionPreference='SilentlyContinue'
$rules=@(Get-NetFirewallApplicationFilter | Where-Object { $_.Program -ieq '__EXE__' } | ForEach-Object { $r = $_ | Get-NetFirewallRule; [pscustomobject]@{Name=$r.DisplayName;Enabled=[string]$r.Enabled;Direction=[string]$r.Direction;Action=[string]$r.Action;Profile=[string]$r.Profile} })
$profiles=@(Get-NetConnectionProfile | ForEach-Object { [pscustomobject]@{Name=$_.Name;Category=[string]$_.NetworkCategory} })
[pscustomobject]@{Rules=$rules;Profiles=$profiles} | ConvertTo-Json -Depth 4 -Compress
"""


def analyze_firewall(rules, profiles):
    """Pure function: (state, detail, [(log_line, tag)]) for the inbound rules of one program."""
    cat_map = {"public": "public", "private": "private",
               "domainauthenticated": "domain", "domain": "domain"}
    cats = {cat_map.get(str(x.get("Category", "")).lower(), "") for x in profiles} - {""}
    lines = []
    for x in profiles:
        lines.append((f"Active network '{x.get('Name')}' is profile: {x.get('Category')}", "info"))
    if "public" in cats:
        lines.append(("Tip: 'Public' networks are the strictest; set your home Wi-Fi/Ethernet to Private "
                      "in Windows network settings.", "info"))

    def covers(rule):
        prof = str(rule.get("Profile", "")).lower()
        if "any" in prof or "all" in prof or not cats:
            return True
        return any(c in prof for c in cats)

    def is_(rule, field, value):
        return str(rule.get(field, "")).lower() == value

    for r in rules:
        lines.append((f"  rule '{r.get('Name')}': {r.get('Direction')}, {r.get('Action')}, "
                      f"enabled={r.get('Enabled')}, profiles={r.get('Profile')}", "info"))
    enabled_in = [r for r in rules if is_(r, "Direction", "inbound") and is_(r, "Enabled", "true")]
    blocks = [r for r in enabled_in if is_(r, "Action", "block") and covers(r)]
    allows = [r for r in enabled_in if is_(r, "Action", "allow") and covers(r)]
    if blocks:
        names = ", ".join(str(r.get("Name")) for r in blocks)
        lines.append(("An enabled BLOCK rule overrides every allow rule. Delete or disable it "
                      "(wf.msc > Inbound Rules), then add an allow rule.", "fail"))
        return "fail", f"Inbound BLOCK rule active: {names}", lines
    if allows:
        return "ok", "Inbound allow rule covers the active network profile", lines
    if any(is_(r, "Action", "allow") for r in enabled_in):
        lines.append((f"An allow rule exists but not for the active profile ({', '.join(sorted(cats))}). "
                      "Add a rule for 'Any' profile.", "fail"))
        return "fail", "Allow rule exists, but not for the active network profile", lines
    lines.append(("No inbound rule for this program. Windows blocks unsolicited inbound connections "
                  "(or prompts once, and a dismissed prompt often becomes a Block rule). "
                  "Use 'Add firewall rule...'. If you are not admin, existing rules may be unreadable.", "warn"))
    return "warn", "No inbound rule for this program -> ESP callback will be blocked", lines


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
# Grayscale palette. Status is carried by luminance and glyph shape, never hue:
# the louder the problem, the brighter it gets, and a failure inverts its row.
C = {
    "bg": "#161616",      # window
    "panel": "#1E1E1E",   # sidebar, tables, log
    "field": "#282828",   # inputs, secondary buttons
    "raised": "#323232",  # hover
    "line": "#343434",    # borders, dividers
    "dim": "#6E6E6E",     # skipped
    "muted": "#8E8E8E",   # hints
    "text": "#D2D2D2",    # body
    "bright": "#F4F4F4",  # emphasis, primary button
}


class App(tk.Tk):
    TESTS = [
        ("local", "Local network / subnet"),
        ("ping", "Ping (ICMP)"),
        ("tcp", "TCP ports"),
        ("firewall", "Windows firewall rules (uploader)"),
        ("resolve", "<hostname>.local via OS resolver"),
        ("mdns_direct", "mDNS direct to device (unicast)"),
        ("mdns_multi", "mDNS multicast discovery"),
        ("zeroconf", "Zeroconf browse (_arduino._tcp)"),
        ("ota", "OTA UDP handshake"),
        ("callback", "OTA reverse TCP callback (ESP -> PC)"),
        ("mdns_listen", "mDNS passive listen (announcements)"),
    ]
    STATES = {
        "ok": ("✓  OK", "ok"), "fail": ("✕  Fail", "fail"),
        "warn": ("▲  Warn", "warn"), "skip": ("–  Skipped", "skip"),
        "run": ("…  Running", "run"), "idle": ("", "idle"),
    }
    SIDEBAR_W = 330
    EMPTY_SUMMARY = "Enter the device IP, or use Find devices below."

    def __init__(self):
        super().__init__()
        self.title("Arduino ESP OTA Diagnostic")
        self.geometry("1220x900")
        self.minsize(1040, 880)
        self.configure(bg=C["bg"])
        self.q = queue.Queue()
        self.results = {}
        self.shown = {}
        self.busy = False
        self.found = set()
        self.buttons = []
        self.labels = dict(self.TESTS)
        self._init_theme()
        self._build_ui()
        self._dark_titlebar()
        self.bind("<Control-Return>", lambda e: self.run_all())
        self.bind("<F5>", lambda e: self.run_all())
        self.after(100, self._pump)
        self.log(f"Zeroconf package: {'available' if HAVE_ZEROCONF else 'not installed (pip install zeroconf)'}", "info")

    # ---------------- theme ----------------
    def _init_theme(self):
        fams = set(tkfont.families(self))
        pick = lambda *names: next((n for n in names if n in fams), names[-1])
        ui = pick("Segoe UI Variable Text", "Segoe UI", "Inter", "Helvetica Neue", "DejaVu Sans", "Helvetica")
        display = pick("Segoe UI Variable Display", ui)
        mono = pick("Cascadia Mono", "Consolas", "JetBrains Mono", "DejaVu Sans Mono", "Courier")
        self.f = {
            "small": (ui, 9), "body": (ui, 10), "strong": (ui, 10, "bold"),
            "section": (ui, 11, "bold"), "hero": (display, 24),
            "mono": (mono, 10), "mono_b": (mono, 10, "bold"),
        }

        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=C["bg"], foreground=C["text"], font=self.f["body"],
                    bordercolor=C["line"], lightcolor=C["bg"], darkcolor=C["bg"],
                    troughcolor=C["panel"], focuscolor=C["muted"], fieldbackground=C["field"],
                    selectbackground="#3C3C3C", selectforeground=C["bright"], insertcolor=C["bright"])
        s.configure("TFrame", background=C["bg"])
        s.configure("Side.TFrame", background=C["panel"])

        for prefix, bg in (("", C["bg"]), ("Side", C["panel"])):
            s.configure(f"{prefix}Section.TLabel", background=bg, foreground=C["bright"], font=self.f["section"])
            s.configure(f"{prefix}Field.TLabel", background=bg, foreground=C["text"], font=self.f["small"])
            s.configure(f"{prefix}Hint.TLabel", background=bg, foreground=C["muted"], font=self.f["small"])

        # Buttons: one light primary, flat gray secondaries, text-only ghosts
        s.configure("TButton", background=C["field"], foreground=C["text"], bordercolor=C["line"],
                    lightcolor=C["field"], darkcolor=C["field"], padding=(12, 6), relief="flat", width=-4,
                    focusthickness=1, focuscolor=C["muted"])
        s.map("TButton",
              background=[("disabled", "#1F1F1F"), ("pressed", "#3A3A3A"), ("active", C["raised"])],
              lightcolor=[("disabled", "#1F1F1F"), ("pressed", "#3A3A3A"), ("active", C["raised"])],
              darkcolor=[("disabled", "#1F1F1F"), ("pressed", "#3A3A3A"), ("active", C["raised"])],
              foreground=[("disabled", C["dim"]), ("active", C["bright"])],
              bordercolor=[("focus", C["muted"])])
        s.configure("Primary.TButton", background=C["bright"], foreground="#161616", font=self.f["strong"],
                    lightcolor=C["bright"], darkcolor=C["bright"], bordercolor=C["bright"],
                    padding=(16, 6), focuscolor="#161616")
        s.map("Primary.TButton",
              background=[("disabled", C["field"]), ("pressed", "#D8D8D8"), ("active", "#FFFFFF")],
              lightcolor=[("disabled", C["field"]), ("pressed", "#D8D8D8"), ("active", "#FFFFFF")],
              darkcolor=[("disabled", C["field"]), ("pressed", "#D8D8D8"), ("active", "#FFFFFF")],
              bordercolor=[("disabled", C["field"])],
              foreground=[("disabled", C["dim"]), ("active", "#161616")])
        for prefix, bg in (("", C["bg"]), ("Side", C["panel"])):
            s.configure(f"{prefix}Ghost.TButton", background=bg, foreground=C["muted"], font=self.f["small"],
                        bordercolor=bg, lightcolor=bg, darkcolor=bg, padding=(8, 4))
            s.map(f"{prefix}Ghost.TButton",
                  background=[("pressed", C["raised"]), ("active", C["field"])],
                  lightcolor=[("pressed", C["raised"]), ("active", C["field"])],
                  darkcolor=[("pressed", C["raised"]), ("active", C["field"])],
                  bordercolor=[("focus", C["muted"])],
                  foreground=[("active", C["bright"])])

        s.configure("Side.TCheckbutton", background=C["panel"], foreground=C["text"],
                    indicatorbackground=C["field"], indicatorforeground=C["bright"],
                    upperbordercolor=C["line"], lowerbordercolor=C["line"],
                    indicatormargin=(0, 0, 8, 0), focuscolor=C["muted"])
        s.map("Side.TCheckbutton",
              background=[("active", C["panel"])], foreground=[("active", C["bright"])],
              indicatorbackground=[("pressed", C["raised"]), ("active", C["raised"])])

        s.configure("Small.TButton", font=self.f["small"], padding=(10, 3))

        s.configure("Seg.Toolbutton", background=C["field"], foreground=C["muted"], font=self.f["small"],
                    bordercolor=C["line"], lightcolor=C["field"], darkcolor=C["field"],
                    padding=(10, 3), focuscolor=C["muted"])
        s.map("Seg.Toolbutton",
              background=[("selected", C["bright"]), ("active", C["raised"])],
              lightcolor=[("selected", C["bright"]), ("active", C["raised"])],
              darkcolor=[("selected", C["bright"]), ("active", C["raised"])],
              foreground=[("selected", "#161616"), ("active", C["bright"])])

        s.configure("TCombobox", fieldbackground=C["field"], background=C["field"], foreground=C["text"],
                    arrowcolor=C["text"], bordercolor=C["line"], lightcolor=C["field"], darkcolor=C["field"],
                    selectbackground=C["field"], selectforeground=C["text"], padding=(6, 5))
        s.map("TCombobox",
              fieldbackground=[("readonly", C["field"])], background=[("active", C["raised"])],
              bordercolor=[("focus", C["muted"])], arrowcolor=[("active", C["bright"])])
        self.option_add("*TCombobox*Listbox.background", C["field"])
        self.option_add("*TCombobox*Listbox.foreground", C["text"])
        self.option_add("*TCombobox*Listbox.selectBackground", "#3C3C3C")
        self.option_add("*TCombobox*Listbox.selectForeground", C["bright"])
        self.option_add("*TCombobox*Listbox.font", self.f["small"])

        s.configure("Vertical.TScrollbar", background="#3A3A3A", troughcolor=C["panel"],
                    bordercolor=C["panel"], lightcolor="#3A3A3A", darkcolor="#3A3A3A",
                    arrowcolor=C["muted"], gripcount=0)
        s.map("Vertical.TScrollbar", background=[("active", "#4A4A4A")])

        s.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["text"],
                    bordercolor=C["line"], lightcolor=C["panel"], darkcolor=C["panel"],
                    rowheight=28, font=self.f["body"])
        s.map("Treeview", background=[("selected", "#3A3A3A")], foreground=[("selected", C["bright"])])
        s.configure("Treeview.Heading", background=C["panel"], foreground=C["muted"], font=self.f["small"],
                    bordercolor=C["line"], lightcolor=C["panel"], darkcolor=C["panel"],
                    relief="flat", padding=(0, 6))
        s.map("Treeview.Heading", background=[("active", C["panel"])], foreground=[("active", C["text"])])

    def _dark_titlebar(self):
        if not IS_WINDOWS:
            return
        try:
            import ctypes
            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            on = ctypes.c_int(1)
            for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (current, then pre-20H1)
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(on), ctypes.sizeof(on)) == 0:
                    break
        except Exception:
            pass

    # ---------------- UI ----------------
    def _box(self, parent, var, show="", suffix=None, width=10):
        """Flat input with a focus ring drawn by its frame."""
        box = tk.Frame(parent, bg=C["field"], highlightthickness=1,
                       highlightbackground=C["line"], highlightcolor=C["line"])
        e = tk.Entry(box, textvariable=var, show=show, width=width, font=self.f["body"],
                     bg=C["field"], fg=C["bright"], insertbackground=C["bright"],
                     selectbackground="#4A4A4A", selectforeground=C["bright"],
                     relief="flat", bd=0, highlightthickness=0)
        e.pack(side="left", fill="x", expand=True, padx=(9, 0 if suffix else 9), pady=6)
        if suffix:
            tk.Label(box, text=suffix, bg=C["field"], fg=C["muted"], font=self.f["body"]
                     ).pack(side="right", padx=(2, 9))
        e.bind("<FocusIn>", lambda _: box.configure(highlightbackground=C["muted"]))
        e.bind("<FocusOut>", lambda _: box.configure(highlightbackground=C["line"]))
        e.bind("<Return>", lambda _: self.run_all())
        return box

    def _field(self, parent, label, var, **kw):
        wrap = ttk.Frame(parent, style="Side.TFrame")
        ttk.Label(wrap, text=label, style="SideField.TLabel").pack(anchor="w", pady=(0, 4))
        self._box(wrap, var, **kw).pack(fill="x")
        return wrap

    def _divider(self, parent):
        tk.Frame(parent, bg=C["line"], height=1).pack(fill="x", pady=16)

    def _build_ui(self):
        self.ip_var = tk.StringVar(value="192.168.1.13")
        self.host_var = tk.StringVar(value="")
        self.core_var = tk.StringVar(value="esp8266")
        self.port_var = tk.StringVar(value="8266")
        self.ports_var = tk.StringVar(value="80, 8266")
        self.probe_var = tk.BooleanVar(value=True)
        self.listen_var = tk.StringVar(value="30")
        self.pw_var = tk.StringVar(value="")
        self.pyexe_var = tk.StringVar(value="")
        self.summary_var = tk.StringVar(value=self.EMPTY_SUMMARY)
        self.py_map = {}
        wrap_w = self.SIDEBAR_W - 48

        # ---- sidebar: what to test ----
        side = ttk.Frame(self, style="Side.TFrame", width=self.SIDEBAR_W, padding=(24, 22, 24, 18))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        top = ttk.Frame(side, style="Side.TFrame")
        top.pack(fill="x")
        ttk.Label(top, text="Device IP address", style="SideField.TLabel").pack(side="left", anchor="s")
        for key in reversed(list(CORES)):
            ttk.Radiobutton(top, text=CORES[key]["label"], value=key, variable=self.core_var,
                            style="Seg.Toolbutton", command=self._core_changed).pack(side="right")
        ip = tk.Entry(side, textvariable=self.ip_var, font=self.f["hero"], width=14,
                      bg=C["panel"], fg=C["bright"], insertbackground=C["bright"],
                      selectbackground="#4A4A4A", selectforeground=C["bright"],
                      relief="flat", bd=0, highlightthickness=0)
        ip.pack(fill="x", pady=(2, 0))
        rule = tk.Frame(side, bg=C["line"], height=1)
        rule.pack(fill="x", pady=(2, 14))
        ip.bind("<FocusIn>", lambda _: rule.configure(bg=C["bright"]))
        ip.bind("<FocusOut>", lambda _: rule.configure(bg=C["line"]))
        ip.bind("<Return>", lambda _: self.run_all())

        self._field(side, "Hostname (optional)", self.host_var, suffix=".local").pack(fill="x", pady=(0, 12))
        ports = ttk.Frame(side, style="Side.TFrame")
        ports.pack(fill="x")
        ports.columnconfigure(1, weight=1)
        self._field(ports, "OTA UDP port", self.port_var, width=6).grid(row=0, column=0, sticky="we", padx=(0, 10))
        self._field(ports, "TCP ports to check", self.ports_var).grid(row=0, column=1, sticky="we")

        self._divider(side)
        ttk.Label(side, text="Upload test", style="SideSection.TLabel").pack(anchor="w", pady=(0, 10))
        self._field(side, "OTA password", self.pw_var, show="•").pack(fill="x", pady=(0, 12))
        ttk.Label(side, text="Uploader program", style="SideField.TLabel").pack(anchor="w", pady=(0, 4))
        self.py_combo = ttk.Combobox(side, textvariable=self.pyexe_var, state="readonly", font=self.f["small"])
        self.py_combo.pack(fill="x")
        ttk.Label(side, text="What the Arduino IDE uploads with. The firewall check targets it.",
                  style="SideHint.TLabel", wraplength=wrap_w, justify="left").pack(anchor="w", pady=(4, 10))
        ttk.Checkbutton(side, variable=self.probe_var, text="Allow OTA probes",
                        style="Side.TCheckbutton").pack(anchor="w")
        ttk.Label(side, text="Probes fire onStart on the device, then time out.",
                  style="SideHint.TLabel", wraplength=wrap_w, justify="left").pack(anchor="w", pady=(2, 12))
        b = ttk.Button(side, text="Add firewall rule…", command=self.add_fw_rule)
        b.pack(fill="x")
        self.buttons.append(b)
        copies = ttk.Frame(side, style="Side.TFrame")
        copies.pack(fill="x", pady=(6, 0))
        ttk.Button(copies, text="Copy netsh", style="SideGhost.TButton", width=0,
                   command=self.copy_netsh).pack(side="left")
        ttk.Button(copies, text="Copy espota", style="SideGhost.TButton", width=0,
                   command=self.copy_espota).pack(side="left", padx=(4, 0))
        self._refresh_uploaders()

        self._divider(side)
        ttk.Label(side, text="Passive listen", style="SideSection.TLabel").pack(anchor="w")
        ttk.Label(side, text="Reboot the ESP while listening to catch its boot announcement.",
                  style="SideHint.TLabel", wraplength=wrap_w, justify="left").pack(anchor="w", pady=(2, 10))
        self._field(side, "Duration in seconds", self.listen_var, width=6).pack(anchor="w")

        # ---- main: run and read ----
        main = ttk.Frame(self, padding=(26, 22, 26, 20))
        main.pack(side="left", fill="both", expand=True)

        bar = ttk.Frame(main)
        bar.pack(fill="x")
        # "ota" is filled in by the callback test; "mdns_listen" is long, so both are separate buttons
        self.all_keys = [k for k, _ in self.TESTS if k not in ("mdns_listen", "ota")]
        b = ttk.Button(bar, text="Run all checks", style="Primary.TButton", command=self.run_all)
        b.pack(side="left")
        self.buttons.append(b)
        ttk.Label(bar, text="Ctrl+Enter", style="Hint.TLabel").pack(side="left", padx=(10, 22))
        for label, keys in (
            ("Network", ["local", "ping", "tcp", "firewall"]),
            ("mDNS", ["resolve", "mdns_direct", "mdns_multi", "zeroconf"]),
            ("OTA probe", ["ota"]),
            ("Callback test", ["callback"]),
            ("Passive listen", ["mdns_listen"]),
        ):
            b = ttk.Button(bar, text=label, command=lambda k=keys: self.start(k))
            b.pack(side="left", padx=(0, 6))
            self.buttons.append(b)

        # Results table: status first so the eye runs down one edge
        head = ttk.Frame(main)
        head.pack(fill="x", pady=(24, 8))
        ttk.Label(head, text="Checks", style="Section.TLabel").pack(side="left")
        ttk.Label(head, textvariable=self.summary_var, style="Hint.TLabel").pack(side="right")
        self.tree = ttk.Treeview(main, columns=("status", "check", "detail"), show="headings",
                                 height=len(self.TESTS), selectmode="browse")
        for col, text, w, stretch in (("status", "Result", 110, False), ("check", "Check", 320, False),
                                      ("detail", "Details", 360, True)):
            self.tree.heading(col, text="  " + text, anchor="w")
            self.tree.column(col, width=w, minwidth=w if not stretch else 120, stretch=stretch, anchor="w")
        self.tree.tag_configure("idle", foreground=C["text"])
        self.tree.tag_configure("ok", foreground="#BDBDBD")
        self.tree.tag_configure("warn", foreground=C["bright"], background="#303030")
        self.tree.tag_configure("fail", foreground="#161616", background="#E6E6E6")
        self.tree.tag_configure("run", foreground=C["bright"], background="#262626")
        self.tree.tag_configure("skip", foreground=C["dim"])
        for key, label in self.TESTS:
            self.tree.insert("", "end", iid=key, values=("", "  " + label, ""), tags=("idle",))
        self.tree.pack(fill="x")

        # Discovered services
        head = ttk.Frame(main)
        head.pack(fill="x", pady=(22, 8))
        ttk.Label(head, text="Discovered services", style="Section.TLabel").pack(side="left")
        b = ttk.Button(head, text="Find devices", style="Small.TButton", command=self.find_devices)
        b.pack(side="right")
        self.buttons.append(b)
        ttk.Label(head, text="Double-click a row to use its IP", style="Hint.TLabel").pack(side="right", padx=(0, 12))
        self.found_tree = ttk.Treeview(
            main, columns=("source", "service", "addr", "port", "info"),
            show="headings", height=4)
        for col, w in (("source", 90), ("service", 150), ("addr", 190),
                       ("port", 60), ("info", 320)):
            self.found_tree.heading(col, text="  " + col.capitalize(), anchor="w")
            self.found_tree.column(col, width=w, stretch=(col == "info"), anchor="w")
        self.found_tree.pack(fill="x")
        self.found_tree.bind("<Double-1>", self._use_found)
        self.found_tree.bind("<Return>", self._use_found)

        # Log
        head = ttk.Frame(main)
        head.pack(fill="x", pady=(22, 6))
        ttk.Label(head, text="Log", style="Section.TLabel").pack(side="left")
        ttk.Button(head, text="Copy log", style="Ghost.TButton", command=self.copy_log).pack(side="right")
        ttk.Button(head, text="Clear", style="Ghost.TButton", command=self.clear).pack(side="right", padx=(0, 4))
        logwrap = tk.Frame(main, bg=C["panel"], highlightthickness=1, highlightbackground=C["line"])
        logwrap.pack(fill="both", expand=True)
        self.logbox = tk.Text(logwrap, height=8, wrap="word", font=self.f["mono"],
                              bg=C["panel"], fg=C["text"], insertbackground=C["bright"],
                              selectbackground="#3C3C3C", selectforeground=C["bright"],
                              relief="flat", bd=0, highlightthickness=0, padx=14, pady=10,
                              spacing1=1, spacing3=1)
        sb = ttk.Scrollbar(logwrap, orient="vertical", command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.logbox.pack(side="left", fill="both", expand=True)
        self.logbox.tag_configure("info", foreground="#9A9A9A")
        self.logbox.tag_configure("ok", foreground=C["text"])
        self.logbox.tag_configure("warn", foreground=C["bright"])
        self.logbox.tag_configure("fail", foreground=C["bright"], background="#333333", font=self.f["mono_b"])
        self.logbox.tag_configure("head", foreground=C["bright"], font=self.f["strong"], spacing1=10, spacing3=4)
        self.logbox.configure(state="disabled")

    # ---------------- thread-safe messaging ----------------
    def log(self, text, tag="info"):
        self.q.put(("log", text, tag))

    def set_status(self, key, state, detail=""):
        self.results[key] = state
        self.q.put(("status", key, state, detail))

    def add_found(self, source, service, addr, port, info):
        row = (source, service, addr or "?", port or "", info)
        if row in self.found:
            return
        self.found.add(row)
        self.q.put(("found", row))

    def _update_summary(self):
        n = lambda s: sum(1 for v in self.shown.values() if v == s)
        ok, fail, warn = n("ok"), n("fail"), n("warn")
        parts = []
        if ok:
            parts.append(f"{ok} passed")
        if fail:
            parts.append(f"{fail} failed")
        if warn:
            parts.append(f"{warn} warning{'s' if warn > 1 else ''}")
        self.summary_var.set(", ".join(parts) if parts else self.EMPTY_SUMMARY)

    def _pump(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "log":
                    self.logbox.configure(state="normal")
                    self.logbox.insert("end", msg[1] + "\n", msg[2])
                    self.logbox.see("end")
                    self.logbox.configure(state="disabled")
                elif msg[0] == "status":
                    _, key, state, detail = msg
                    if not self.tree.exists(key):
                        continue
                    text, tag = self.STATES[state]
                    label = self.labels[key]
                    self.tree.item(key, values=("  " + text, "  " + label, "  " + detail if detail else ""),
                                   tags=(tag,))
                    self.shown[key] = state
                    if state == "run":
                        self.summary_var.set(f"Running: {label}")
                elif msg[0] == "found":
                    self.found_tree.insert("", "end", values=tuple(f"  {v}" for v in msg[1]))
                elif msg[0] == "discovered":
                    self._discovered(*msg[1:])
                elif msg[0] == "done":
                    self.busy = False
                    self._update_summary()
                    for b in self.buttons:
                        b.state(["!disabled"])
        except queue.Empty:
            pass
        self.after(100, self._pump)

    # ---------------- device discovery (when the IP is unknown) ----------------
    def find_devices(self):
        if self.busy:
            return
        self.busy = True
        for b in self.buttons:
            b.state(["disabled"])
        self.found_tree.delete(*self.found_tree.get_children())
        self.found.clear()
        self.summary_var.set("Looking for devices…")
        threading.Thread(target=self._discover, daemon=True).start()

    def _discover(self):
        """mDNS first (what the IDE uses), then an ARP sweep for Espressif MACs. Never touches the OTA port."""
        hits = {}                                   # ip -> hostname ("" if unknown)
        iface = route_ip("8.8.8.8") or route_ip(MDNS_GROUP)
        self.log(f"=== Looking for devices from {iface or 'the default interface'} "
                 f"at {time.strftime('%H:%M:%S')} ===", "head")
        try:
            resp = mdns_query([("_arduino._tcp.local", 12)], (MDNS_GROUP, MDNS_PORT), iface, timeout=3.0)
            for svc, inst, ip, port, kv in summarize(resp):
                if svc.startswith("_arduino._tcp") and ip:
                    host = inst.split(".")[0]
                    self.add_found("mDNS", "_arduino._tcp", ip, port, f"{host} {kv.get('board', '')}".strip())
                    hits.setdefault(ip, host)
            self.log(f"mDNS: {len(hits)} device(s) advertise _arduino._tcp.", "ok" if hits else "info")

            prefix = iface.rsplit(".", 1)[0] if iface else None
            if prefix:
                # An empty UDP packet to each address makes the OS resolve its MAC into the ARP table
                self.log(f"ARP sweep of {prefix}.1-254 for Espressif network adapters...", "info")
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                for i in range(1, 255):
                    try:
                        sock.sendto(b"", (f"{prefix}.{i}", 9))
                    except OSError:
                        pass
                sock.close()
                time.sleep(2.5)
                arp = 0
                for ip, mac in read_arp_table():
                    if ip.startswith(prefix + ".") and mac[:8] in ESPRESSIF_OUIS:
                        self.add_found("ARP", "Espressif device", ip, "", mac)
                        hits.setdefault(ip, "")
                        arp += 1
                self.log(f"ARP: {arp} Espressif device(s) on {prefix}.x.", "ok" if arp else "info")
        except Exception as e:
            self.log(f"Discovery error: {e!r}", "fail")
        self.q.put(("discovered", hits, iface))
        self.q.put(("done",))

    def _discovered(self, hits, iface):
        if len(hits) == 1:
            ip, host = next(iter(hits.items()))
            self._use_device(ip, host)
        elif hits:
            self.log(f"Found {len(hits)} devices. Double-click one in Discovered services to use it.", "ok")
        else:
            self.log("No ESP found. Check it is powered and on the same network as this PC "
                     f"({iface or 'no route found'}). A device on another subnet, or one that is not "
                     "connected to Wi-Fi at all, can't be found; read its IP from the serial monitor "
                     "or your router's client list.", "warn")

    def _use_found(self, _event=None):
        sel = self.found_tree.selection()
        if not sel:
            return
        source, _svc, addr, _port, info = (str(v).strip() for v in self.found_tree.item(sel[0], "values"))
        if addr in ("", "?"):
            return
        host = info.split()[0].split(".")[0] if info and source != "ARP" else ""
        self._use_device(addr, host)

    def _use_device(self, ip, host=""):
        self.ip_var.set(ip)
        if host:
            self.host_var.set(host)
        self.log(f"Using {ip}{f' ({host}.local)' if host else ''}. Run all checks to test it.", "ok")

    # ---------------- actions ----------------
    def run_all(self):
        self.start(self.all_keys)

    def clear(self):
        self.logbox.configure(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.configure(state="disabled")
        for key, label in self.TESTS:
            self.tree.item(key, values=("", "  " + label, ""), tags=("idle",))
        self.found_tree.delete(*self.found_tree.get_children())
        self.found.clear()
        self.results.clear()
        self.shown.clear()
        self._update_summary()

    def copy_log(self):
        self.clipboard_clear()
        self.clipboard_append(self.logbox.get("1.0", "end"))

    def copy_espota(self):
        ip = self.ip_var.get().strip()
        port = self.port_var.get().strip()
        esp = find_espota(self.core_var.get())
        tool = esp[0] if esp else "espota.py"
        auth = " --auth=YOUR_PASSWORD" if self.pw_var.get() else ""
        run = f'"{tool}"' if tool.endswith(".exe") else f'"{self.selected_runner()}" "{tool}"'
        cmd = f'{run} -i {ip} -p {port}{auth} -f your_sketch.ino.bin'
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self.log(f"Copied: {cmd}", "info")

    def params(self):
        ip = self.ip_var.get().strip()
        try:
            socket.inet_aton(ip)
            if ip.count(".") != 3:
                raise OSError
        except OSError:
            messagebox.showerror("Invalid IP", "Enter a valid IPv4 address.")
            return None
        try:
            ota_port = int(self.port_var.get())
            ports = [int(p) for p in re.split(r"[,\s]+", self.ports_var.get().strip()) if p]
            listen = max(5, min(600, int(self.listen_var.get())))
        except ValueError:
            messagebox.showerror("Invalid port", "Ports must be numbers.")
            return None
        host = self.host_var.get().strip()
        if host.lower().endswith(".local"):
            host = host[:-6]
        return {"ip": ip, "host": host, "ota_port": ota_port, "ports": ports,
                "listen": listen, "iface": route_ip(ip),
                "password": self.pw_var.get(), "core": CORES[self.core_var.get()],
                "pyexe": self.selected_uploader(), "runner": self.selected_runner()}

    def start(self, keys):
        if self.busy:
            return
        p = self.params()
        if not p:
            return
        self.busy = True
        for b in self.buttons:
            b.state(["disabled"])
        for k in keys:
            self.set_status(k, "idle")
        if "callback" in keys and "ota" not in keys:
            self.set_status("ota", "idle")
        self.found_tree.delete(*self.found_tree.get_children())
        self.found.clear()
        threading.Thread(target=self._worker, args=(keys, p), daemon=True).start()

    def _worker(self, keys, p):
        funcs = {
            "local": self.t_local, "ping": self.t_ping, "tcp": self.t_tcp,
            "resolve": self.t_resolve, "mdns_direct": self.t_mdns_direct,
            "mdns_multi": self.t_mdns_multi, "zeroconf": self.t_zeroconf,
            "ota": self.t_ota, "mdns_listen": self.t_mdns_listen,
            "firewall": self.t_firewall, "callback": self.t_callback, "fw_add": self.t_fw_add,
        }
        self.log(f"=== Testing {p['ip']} (OTA port {p['ota_port']}) at {time.strftime('%H:%M:%S')} ===", "head")
        for k in keys:
            self.set_status(k, "run")
            try:
                funcs[k](p)
            except Exception as e:
                self.set_status(k, "fail", f"error: {e}")
                self.log(f"[{k}] unexpected error: {e!r}", "fail")
        if len(keys) > 1:
            self.diagnose(p)
        self.q.put(("done",))

    # ---------------- tests ----------------
    def t_local(self, p):
        iface = p["iface"]
        if not iface:
            self.set_status("local", "fail", "No route to that IP from this PC")
            self.log("No local interface can route to the device IP.", "fail")
            return
        same = iface.rsplit(".", 1)[0] == p["ip"].rsplit(".", 1)[0]
        self.log(f"PC would use interface {iface} to reach {p['ip']}", "info")
        if same:
            self.set_status("local", "ok", f"PC {iface} is on the same /24 subnet")
        else:
            self.set_status("local", "warn", f"PC {iface} is NOT on the same /24 (VPN / other network?)")
            self.log("Different subnet: mDNS multicast does not cross routers/VPNs.", "warn")

    def t_ping(self, p):
        if IS_WINDOWS:
            cmd = ["ping", "-n", "3", "-w", "1500", p["ip"]]
            flags = 0x08000000  # CREATE_NO_WINDOW
        else:
            cmd = ["ping", "-c", "3", "-W", "2", p["ip"]]
            flags = 0
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                               creationflags=flags)
        except FileNotFoundError:
            self.set_status("ping", "skip", "ping command not found")
            return
        out = r.stdout + r.stderr
        alive = r.returncode == 0 and "ttl=" in out.lower()
        m = re.search(r"(?:Average = |avg[^=]*= ?[\d.]+/)(\d+(?:\.\d+)?)", out)
        if alive:
            self.set_status("ping", "ok", f"Replies received{' (avg ' + m.group(1) + ' ms)' if m else ''}")
            self.log("Ping OK.", "ok")
        else:
            self.set_status("ping", "fail", "No replies (ICMP may also just be blocked)")
            self.log("Ping failed.", "fail")

    def t_tcp(self, p):
        open_ports = []
        for port in p["ports"]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            res = s.connect_ex((p["ip"], port))
            s.close()
            if res == 0:
                open_ports.append(port)
                self.log(f"TCP {port}: open", "ok")
            else:
                note = "  (normal: ArduinoOTA listens on UDP, not TCP)" if port == p["ota_port"] else ""
                self.log(f"TCP {port}: closed/filtered{note}", "info")
        if open_ports:
            self.set_status("tcp", "ok", "Open: " + ", ".join(map(str, open_ports)))
        else:
            self.set_status("tcp", "warn", "No listed TCP ports open (OK if you only use OTA)")

    def t_resolve(self, p):
        if not p["host"]:
            self.set_status("resolve", "skip", "Enter a hostname to test")
            return
        name = p["host"] + ".local"
        self.log(f"Resolving {name} through the OS resolver...", "info")
        try:
            infos = socket.getaddrinfo(name, None, socket.AF_INET)
            addr = infos[0][4][0]
        except socket.gaierror as e:
            self.set_status("resolve", "fail", f"Cannot resolve {name} (install Bonjour on Windows)")
            self.log(f"Resolver failed: {e}", "fail")
            return
        if addr == p["ip"]:
            self.set_status("resolve", "ok", f"{name} -> {addr}")
            self.log(f"{name} -> {addr}", "ok")
        else:
            self.set_status("resolve", "warn", f"{name} -> {addr} (expected {p['ip']})")
            self.log(f"{name} resolved to a different address: {addr}", "warn")

    def _questions(self, p):
        q = [("_arduino._tcp.local", 12), ("_http._tcp.local", 12)]
        if p["host"]:
            q.append((p["host"] + ".local", 1))
        return q

    def t_mdns_direct(self, p):
        self.log(f"Sending mDNS query directly to {p['ip']}:{MDNS_PORT} ...", "info")
        resp = mdns_query(self._questions(p), (p["ip"], MDNS_PORT), p["iface"], timeout=2.5)
        resp = [(s, r) for s, r in resp if s == p["ip"]]
        if not resp:
            self.set_status("mdns_direct", "fail", "Device did not answer mDNS queries")
            self.log("No mDNS answer from the device. Its responder may not be running, "
                     "or the _arduino service isn't registered.", "fail")
            return
        services = summarize(resp)
        has_arduino = False
        for svc, inst, ip, port, kv in services:
            self.log(f"  {svc}  ->  {inst}  {ip}:{port}  {kv or ''}", "info")
            self.add_found("direct", svc, ip, port, f"{inst} {kv or ''}".strip())
            if svc.startswith("_arduino._tcp"):
                has_arduino = True
        for _, recs in resp:
            for name, rtype, val in recs:
                if rtype == 1:
                    self.log(f"  A record: {name} = {val}", "info")
        if has_arduino:
            self.set_status("mdns_direct", "ok", "Device advertises _arduino._tcp (OTA service)")
            self.log("Device advertises the OTA service correctly.", "ok")
        else:
            self.set_status("mdns_direct", "warn", "Device answers mDNS but has NO _arduino._tcp service")
            self.log("The device runs mDNS but does not advertise _arduino._tcp. The IDE will never "
                     f"list it. Fix: {p['core']['mdns_fix']}.", "warn")

    def t_mdns_multi(self, p):
        self.log(f"Sending mDNS multicast query via {p['iface'] or 'default interface'} ...", "info")
        resp = mdns_query(self._questions(p), (MDNS_GROUP, MDNS_PORT), p["iface"], timeout=3.5)
        if not resp:
            self.set_status("mdns_multi", "fail", "No mDNS responses from anyone (multicast blocked?)")
            self.log("Nobody answered the multicast query. Check firewall (UDP 5353), VPN, "
                     "multiple adapters, router IGMP snooping / AP isolation.", "fail")
            return
        sources = sorted({s for s, _ in resp})
        self.log("Responders: " + ", ".join(sources), "info")
        for svc, inst, ip, port, kv in summarize(resp):
            self.add_found("multicast", svc, ip, port, f"{inst} {kv or ''}".strip())
        if p["ip"] in sources:
            self.set_status("mdns_multi", "ok", f"{p['ip']} answered ({len(sources)} responder(s) total)")
            self.log("Device answered the multicast query.", "ok")
        else:
            self.set_status("mdns_multi", "warn", f"Others answered, but not {p['ip']}")
            self.log("Multicast works on this network, but your device didn't answer.", "warn")

    def t_zeroconf(self, p):
        if not HAVE_ZEROCONF:
            self.set_status("zeroconf", "skip", "pip install zeroconf to enable")
            return
        seen = []

        class Listener:
            def add_service(self, zc, type_, name):
                seen.append((type_, name))

            def update_service(self, *a):
                pass

            def remove_service(self, *a):
                pass

        from zeroconf import ServiceBrowser
        zc = Zeroconf()
        try:
            browser = ServiceBrowser(zc, ["_arduino._tcp.local.", "_http._tcp.local."], Listener())
            time.sleep(4)
            browser.cancel()
            arduino_hits = 0
            target_hit = False
            for type_, name in seen:
                info = zc.get_service_info(type_, name, timeout=2000)
                if not info:
                    continue
                addrs = info.parsed_addresses()
                props = {k.decode(errors="replace"): (v.decode(errors="replace") if v else "")
                         for k, v in info.properties.items()}
                self.log(f"  {type_} {name} {addrs}:{info.port} {props}", "info")
                self.add_found("zeroconf", type_.rstrip("."), ", ".join(addrs), info.port,
                               f"{name} {props}")
                if type_.startswith("_arduino"):
                    arduino_hits += 1
                    if p["ip"] in addrs:
                        target_hit = True
        finally:
            zc.close()
        if target_hit:
            self.set_status("zeroconf", "ok", "Found your device as _arduino._tcp")
        elif arduino_hits:
            self.set_status("zeroconf", "warn", f"{arduino_hits} Arduino device(s) found, not {p['ip']}")
        else:
            self.set_status("zeroconf", "fail", "No _arduino._tcp services discovered")

    def t_ota(self, p):
        if not self.probe_var.get():
            self.set_status("ota", "skip", "Probe disabled")
            return
        ip, port = p["ip"], p["ota_port"]
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("", 0))
        tcp.listen(1)
        lport = tcp.getsockname()[1]
        md5 = hashlib.md5(b"ota-diagnostic").hexdigest()
        msg = f"0 {lport} 1024 {md5}\n".encode()   # espota: FLASH command
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(2.5)
        reply = None
        try:
            for attempt in range(1, 4):
                self.log(f"OTA invitation -> {ip}:{port} (attempt {attempt}/3)", "info")
                try:
                    udp.sendto(msg, (ip, port))
                    data, _ = udp.recvfrom(1024)
                    reply = data.decode(errors="replace").strip()
                    break
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    self.log("ICMP port unreachable: nothing listening on that UDP port.", "warn")
                    break
            if reply is None:
                self.set_status("ota", "fail", f"No response on UDP {port}: OTA not running in this firmware")
                self.log("No OTA reply. Causes: OTA_ENABLED=0, ArduinoOTA.begin() not reached, "
                         "handle() not running, custom setPort(), or firmware hung.", "fail")
            elif reply.startswith("AUTH"):
                self.set_status("ota", "ok", "OTA is running (password protected)")
                self.log(f"Reply: '{reply[:20]}...' - OTA is up and asks for a password.", "ok")
            elif reply.startswith("OK"):
                self.set_status("ota", "ok", "OTA is running (no password)")
                self.log("Reply: OK - OTA is up. Aborting handshake (device will time out).", "ok")
                self.log("Note: onStart fired on the device; if 'otaInProgress' isn't reset in "
                         "onError, reboot it or your loop() stays stuck.", "warn")
                tcp.settimeout(2)
                try:
                    conn, _ = tcp.accept()
                    conn.close()
                except socket.timeout:
                    pass
            else:
                self.set_status("ota", "warn", f"Unexpected reply: {reply[:40]}")
                self.log(f"Unexpected reply: {reply!r}", "warn")
        finally:
            udp.close()
            tcp.close()

    def t_mdns_listen(self, p):
        secs, iface, esp_ip = p["listen"], p["iface"], p["ip"]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            try:
                sock.bind(("", MDNS_PORT))
            except OSError as e:
                self.set_status("mdns_listen", "fail", f"Cannot bind UDP 5353: {e}")
                self.log("Another program holds UDP 5353 exclusively (or permission denied).", "fail")
                return
            mreq = struct.pack("4s4s", socket.inet_aton(MDNS_GROUP), socket.inet_aton(iface or "0.0.0.0"))
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except OSError as e:
                self.set_status("mdns_listen", "fail", f"Cannot join multicast group: {e}")
                return
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            if iface:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface))

            # One standard (multicast-response) query from port 5353 to provoke a reply.
            query = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + dns_name("_arduino._tcp.local") \
                + struct.pack("!HH", 12, 1)
            try:
                sock.sendto(query, (MDNS_GROUP, MDNS_PORT))
                self.log(f"Joined {MDNS_GROUP} on {iface or 'default'}; sent one _arduino._tcp query. "
                         f"Listening {secs}s - reboot the ESP now.", "info")
            except OSError as e:
                self.log(f"Could not send query ({e}); listening only.", "warn")

            types = {1: "A", 12: "PTR", 16: "TXT", 33: "SRV"}
            stats, esp_pkts, esp_resp = {}, 0, 0
            end, shown = time.time() + secs, None
            while time.time() < end:
                left = int(end - time.time())
                if left != shown:
                    shown = left
                    self.set_status("mdns_listen", "run", f"Listening... {left}s left (reboot the ESP now)")
                sock.settimeout(0.5)
                try:
                    data, addr = sock.recvfrom(9000)
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    continue
                src = addr[0]
                is_resp = len(data) >= 4 and bool(data[2] & 0x80)
                counts = stats.setdefault(src, [0, 0])
                counts[0 if is_resp else 1] += 1
                if src == esp_ip:
                    esp_pkts += 1
                    ts = time.strftime("%H:%M:%S")
                    if is_resp:
                        esp_resp += 1
                        recs = parse_packet(data)
                        kinds = ", ".join(sorted({types.get(t, str(t)) for _, t, _ in recs})) or "no records"
                        self.log(f"  [{ts}] ESP announcement/response ({kinds})", "ok")
                        for svc, inst, ip, port, kv in summarize([(src, recs)]):
                            self.add_found("listen", svc, ip, port, inst)
                    else:
                        self.log(f"  [{ts}] ESP sent an mDNS query", "ok")
        finally:
            sock.close()

        local = stats.pop(iface, None) if iface else None
        others = {k: v for k, v in stats.items() if k != esp_ip}
        self.log("Packets seen (responses/queries):", "info")
        if esp_ip in stats:
            self.log(f"  {esp_ip} (ESP): {stats[esp_ip][0]}/{stats[esp_ip][1]}", "info")
        for k, v in others.items():
            self.log(f"  {k}: {v[0]}/{v[1]}", "info")
        if local:
            self.log(f"  {iface} (this PC): {local[0]}/{local[1]}", "info")
        if not stats and not local:
            self.log("  (nothing)", "info")

        if esp_pkts:
            self.set_status("mdns_listen", "ok", f"ESP multicast reaches this PC ({esp_pkts} packets)")
            self.log("The ESP's multicast traffic arrives. The network and firewall are fine; the IDE should "
                     "find the device after a reboot/announcement. If the earlier multicast test failed, "
                     "the ESP just ignores unicast-flagged queries.", "ok")
        elif others:
            self.set_status("mdns_listen", "warn", f"Other hosts heard ({len(others)}), but NOT the ESP")
            self.log("Multicast reaches this PC from other devices, but nothing from the ESP. Likely the ESP "
                     "is missing/not sending multicast (Wi-Fi sleep: WiFi.setSleepMode(WIFI_NONE_SLEEP); "
                     "call MDNS.announce() periodically) or the router blocks multicast between Wi-Fi and "
                     "your PC's port (IGMP snooping / AP isolation).", "warn")
        else:
            self.set_status("mdns_listen", "fail", "No mDNS traffic from any other host reached this PC")
            self.log("Nothing arrived from anyone. Either the PC blocks it (firewall UDP 5353 inbound for "
                     "the IDE/mdns-discovery, network profile set to Public, VPN/virtual adapters) or the "
                     "router drops multicast. Try turning the PC firewall off briefly as a test.", "fail")

    # ---------------- board / uploader selection / firewall ----------------
    def _core_changed(self):
        """Swap the OTA port defaults (unless edited) and the uploader list for the new board."""
        new = self.core_var.get()
        old_port = next(str(c["ota_port"]) for k, c in CORES.items() if k != new)
        new_port = str(CORES[new]["ota_port"])
        if self.port_var.get().strip() == old_port:
            self.port_var.set(new_port)
        ports = [x for x in re.split(r"[,\s]+", self.ports_var.get().strip()) if x]
        self.ports_var.set(", ".join(new_port if x == old_port else x for x in ports))
        self._refresh_uploaders()

    def _refresh_uploaders(self):
        core = self.core_var.get()
        ide = find_ide_pythons(core)
        esp = find_espota(core)
        self.py_map = {}
        for path in ide:
            self.py_map["Arduino IDE Python: " + path] = path
        for path in esp:
            if path.endswith(".exe"):
                self.py_map["espota.exe: " + path] = path
        self.py_map["This tool's Python: " + sys.executable] = sys.executable
        labels = list(self.py_map)
        self.py_combo["values"] = labels
        self.pyexe_var.set(labels[0])
        name = CORES[core]["label"]
        self.log(f"{name} core, Arduino IDE Python: " + (ide[0] if ide else "none bundled"), "info")
        self.log(f"{name} core, espota: " + (esp[0] if esp else "not found (is the core installed?)"), "info")

    def selected_uploader(self):
        """The program the firewall check and rule target."""
        return self.py_map.get(self.pyexe_var.get(), sys.executable)

    def selected_runner(self):
        """A Python to run the callback test in: the uploader itself when it is a Python."""
        exe = self.selected_uploader()
        return exe if os.path.basename(exe).lower().startswith("python") else sys.executable

    def _netsh_args(self, exe):
        return ('advfirewall firewall add rule name="Arduino ESP OTA upload" dir=in action=allow '
                f'program="{exe}" protocol=TCP profile=any')

    def copy_netsh(self):
        cmd = "netsh " + self._netsh_args(self.selected_uploader())
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self.log(f"Copied (run in an Administrator Command Prompt):\n  {cmd}", "info")

    def add_fw_rule(self):
        if not IS_WINDOWS:
            messagebox.showinfo("Windows only", "Firewall rules are created on Windows only.")
            return
        exe = self.selected_uploader()
        if not messagebox.askyesno(
                "Add firewall rule",
                f"Create an inbound Windows Firewall rule allowing TCP for:\n\n{exe}\n\n"
                "Windows will ask for administrator permission. Continue?"):
            return
        self.start(["fw_add"])

    def t_fw_add(self, p):
        exe = p["pyexe"]
        self.log(f"Requesting administrator rights to allow inbound TCP for:\n  {exe}", "info")
        script = ("Start-Process -FilePath netsh -Verb RunAs -Wait -ArgumentList '"
                  + self._netsh_args(exe).replace("'", "''") + "'")
        r = run_ps(script, 180)
        if r is None or r.returncode != 0:
            self.log("Elevation was cancelled or failed. Use 'Copy netsh command' and run it from an "
                     "Administrator Command Prompt.", "fail")
            return
        self.log("Rule submitted. Verifying...", "info")
        self.results.pop("firewall", None)
        self.t_firewall(p)
        self.log("Now run 'Callback test' again.", "info")

    def t_firewall(self, p):
        if not IS_WINDOWS:
            self.set_status("firewall", "skip", "Windows only")
            return
        exe = p["pyexe"]
        self.set_status("firewall", "run")
        r = run_ps(FW_QUERY.replace("__EXE__", exe.replace("'", "''")))
        if r is None or r.returncode != 0 or not r.stdout.strip():
            self.set_status("firewall", "warn", "Could not query the firewall via PowerShell")
            if r is not None and r.stderr.strip():
                self.log(r.stderr.strip()[:300], "warn")
            return
        try:
            data = json.loads(r.stdout.strip().splitlines()[-1])
        except ValueError:
            self.set_status("firewall", "warn", "Unreadable PowerShell output")
            return
        rules = data.get("Rules") or []
        profiles = data.get("Profiles") or []
        rules = [rules] if isinstance(rules, dict) else rules
        profiles = [profiles] if isinstance(profiles, dict) else profiles
        self.log(f"Firewall rules for: {exe}", "info")
        state, detail, lines = analyze_firewall(rules, profiles)
        for text, tag in lines:
            self.log(text, tag)
        self.set_status("firewall", state, detail)

    # ---------------- reverse TCP callback (the espota 'No response from device' step) ----------------
    def t_callback(self, p):
        if not self.probe_var.get():
            self.set_status("callback", "skip", "Probes disabled")
            return
        exe = p["runner"]
        name = os.path.basename(exe)
        cfg = json.dumps({"ip": p["ip"], "port": p["ota_port"], "password": p["password"], "timeout": 10})
        self.log(f"Callback test running under: {exe}", "info")
        if exe != p["pyexe"]:
            self.log(f"The real upload runs {os.path.basename(p['pyexe'])}, so the firewall verdict here can "
                     "differ. The firewall check covers that program.", "info")
        self.log("Invitation -> authentication -> waiting up to 10 s for the ESP to connect back (TCP)...", "info")
        try:
            r = subprocess.run([exe, "-c", CALLBACK_HELPER], input=cfg, capture_output=True,
                               text=True, timeout=60, creationflags=NO_WINDOW)
        except (OSError, subprocess.TimeoutExpired) as e:
            self.set_status("callback", "fail", f"Could not run {name}: {e}")
            return
        lines = [ln for ln in r.stdout.splitlines() if ln.startswith("{")]
        if not lines:
            self.set_status("callback", "fail", "Helper produced no result")
            self.log((r.stderr or r.stdout or "no output").strip()[:400], "fail")
            return
        res = json.loads(lines[-1])
        stage, detail = res.get("stage"), res.get("detail", "")

        if stage == "callback_ok":
            self.set_status("ota", "ok", "OTA responds and authentication succeeded")
            self.set_status("callback", "ok", f"ESP connected back to {name} ({detail})")
            self.log("The ESP opened the TCP connection back to this PC: espota uploads will work.", "ok")
            self.log("Note: onStart fired on the device and it will now time out. Reboot it if "
                     "otaInProgress stays set.", "warn")
        elif stage == "callback_timeout":
            self.set_status("ota", "ok", "OTA responds and authentication succeeded")
            self.set_status("callback", "fail", f"ESP could NOT connect back to {name} ({detail})")
            self.log("Authentication passed, but the ESP's TCP connection back to this PC never arrived. "
                     "That is exactly what makes espota print 'No response from device'.", "fail")
            self.log(f"Most likely the Windows firewall blocks inbound TCP to {exe}. Use 'Add firewall "
                     "rule...' (or 'Copy netsh command'). Also rule out router AP/client isolation by "
                     "putting the PC on Wi-Fi, and disable VPN/virtual adapters.", "fail")
        elif stage == "need_password":
            self.set_status("ota", "ok", "OTA running (password protected)")
            self.set_status("callback", "skip", "Enter the OTA password to run this test")
            self.log("The device requires a password; type it in the OTA password field.", "warn")
        elif stage == "auth_failed":
            self.set_status("ota", "ok", "OTA running (password protected)")
            self.set_status("callback", "fail", f"Wrong OTA password (device said: {detail})")
        elif stage == "auth_timeout":
            self.set_status("callback", "fail", "No answer to the authentication message")
        elif stage == "no_reply":
            self.set_status("ota", "fail", "No response on the OTA UDP port")
            self.set_status("callback", "fail", "No reply to the OTA invitation")
            self.log("No OTA reply. Causes: OTA_ENABLED=0, ArduinoOTA.begin() not reached, handle() "
                     "not running, custom setPort(), or firmware hung.", "fail")
        else:
            self.set_status("callback", "warn", f"Unexpected reply: {detail[:40]}")

    # ---------------- summary ----------------
    def diagnose(self, p):
        r = self.results
        g = lambda k: r.get(k, "skip")
        self.log("", "info")
        self.log("=== Diagnosis ===", "head")
        reachable = g("ping") == "ok" or g("tcp") == "ok"
        if g("local") == "warn":
            self.log("• PC and device are on different subnets: discovery won't work across them. "
                     "Disconnect VPN / use the same network.", "warn")
        if not reachable and g("ota") != "ok":
            self.log(f"• {p['ip']} isn't reachable. Check the IP, that the ESP is powered and on Wi-Fi, "
                     "and that the router has no client/AP isolation.", "fail")
        elif g("ota") == "fail":
            self.log("• Device is reachable but nothing answers on the OTA UDP port. The running firmware "
                     "isn't serving OTA (check OTA_ENABLED, ArduinoOTA.begin() after Wi-Fi is up, "
                     "ArduinoOTA.handle() in loop). Flash once via USB.", "fail")
        elif g("ota") == "ok":
            if g("callback") == "fail":
                self.log("• The ESP answers OTA invitations but cannot connect BACK to this PC over TCP. "
                         "That is what makes espota say 'No response from device'.", "fail")
                if g("firewall") in ("warn", "fail"):
                    self.log("• The firewall check found a problem for the uploader: fix it with 'Add firewall "
                             "rule...' and re-run the callback test.", "fail")
                else:
                    self.log("• Firewall rules look fine, so suspect a third-party firewall/antivirus, a VPN or "
                             "virtual adapter, or router AP/client isolation (try the PC on Wi-Fi).", "warn")
            elif g("callback") == "ok":
                self.log("• Full OTA handshake incl. the TCP callback works: uploads by IP will succeed "
                         "(use 'Copy espota command').", "ok")
            else:
                self.log("• OTA answers on UDP. An upload additionally needs the ESP to connect back over TCP: "
                         "enter the OTA password and run the callback test.", "info")
            if g("mdns_direct") in ("fail", "warn"):
                self.log("• The device doesn't advertise _arduino._tcp. If you also call MDNS.begin(), use "
                         f"{p['core']['mdns_fix']}.", "warn")
            elif g("mdns_multi") == "fail":
                self.log("• Device advertises correctly, but multicast replies don't reach this PC. Allow "
                         "UDP 5353 for Arduino IDE / mdns-discovery in the firewall, disable VPN or extra "
                         "adapters, and check router IGMP snooping / AP isolation.", "warn")
                self.log("• Next step: press 'Passive listen' and reboot the ESP to see whether its "
                         "announcements reach this PC.", "info")
            elif g("resolve") == "fail":
                self.log("• The OS can't resolve .local names. Install Bonjour (Windows) or avahi (Linux).", "warn")
            else:
                self.log("• Discovery looks healthy. If the IDE still hides the port: restart the IDE, "
                         "allow it through the firewall, and re-select the board/port.", "info")
        elif g("ota") == "skip" and reachable:
            self.log("• Device reachable. Enable the OTA probe to test the OTA service itself.", "info")
        self.log("", "info")


if __name__ == "__main__":
    App().mainloop()
