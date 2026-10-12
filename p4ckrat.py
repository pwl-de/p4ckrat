#!/usr/bin/env python3
r"""p4ckrat - full-auto recon & loot grabber (by p4cket). See README.md."""
import os
import re
import sys
import json
import time
import shutil
import socket
import ftplib
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
DNS_WORDLIST     = SECLISTS/"Discovery"/"DNS"/"subdomains-top1million-5000.txt"
USER_WORDLIST    = SECLISTS/"Usernames"/"top-usernames-shortlist.txt"
PASS_WORDLIST    = SECLISTS/"Passwords"/"Common-Credentials"/"10-million-password-list-top-100.txt"

DOMAIN         = ""
RATE           = 5000
THREADS        = 80
CONCURRENCY    = 4
GOBUSTER_DEPTH = 2
GOBUSTER_BUDGET = 12
GOBUSTER_EXT   = "php,txt"

ENABLE_GOBUSTER  = True
ENABLE_DIRSEARCH = True
ENABLE_VHOST     = True
ENABLE_HOSTS     = True
DO_WEBFUZZ       = True

T_FULLSCAN = 480
T_SVCSCAN  = 360
T_GOBUSTER = 420
T_DIRSRCH  = 420
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

def info(s, t=None): emit(col("c","[*] ")+_pfx(t)+s)
def ok(s,   t=None): emit(col("G","[+] ")+_pfx(t)+col("w",s))
def warn(s, t=None): emit(col("Y","[!] ")+_pfx(t)+s)
def err(s,  t=None): emit(col("r","[-] ")+_pfx(t)+s)
def raw(line, t=None): emit("    "+_pfx(t)+col("d",line))

def finding(cat, text, t=None):
    if _FINDF:
        with _LOCK:
            try: _FINDF.write(f"[{_ts()}] {cat:<6} {text}\n"); _FINDF.flush()
            except Exception: pass
    emit(col("G","[+] ")+col(_tagcolor(t) if t else "G", cat.lower()+": ")+col("w",text))

def head(s):
    emit()
    emit(col("b",s.lower()))

BANNER = r"""
          _____          __                   __
______   /  |  |   ____ |  | ______________ _/  |_
\____ \ /   |  |__/ ___\|  |/ /\_  __ \__  \\   __\
|  |_> >    ^   /\  \___|    <  |  | \// __ \|  |
|   __/\____   |  \___  >__|_ \ |__|  (____  /__|
|__|        |__|      \/     \/            \/"""
def banner(ip, name):
    emit(col("G", col("b", BANNER)))
    emit(col("d","   full-auto recon & loot grabber - by p4cket - github.com/pwl-de"))
    emit(col("d",f"   target {ip}   name {name}   started {_ts()}"))
    emit(col("d",f"   wordlist {WORDLIST.name}   lists {SECLISTS}"))
    emit()

def have(tool): return shutil.which(tool) is not None

def run(cmd, outfile=None, timeout=T_GENERIC):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        out = (p.stdout or "") + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        rc = 124
    except FileNotFoundError:
        return (127, "")
    if outfile: Path(outfile).write_text(out, errors="replace")
    return (rc, out)

def run_live(cmd, t=None, outfile=None, timeout=T_GENERIC, filt=None, echo=True):
    """Stream stdout live (tagged) + tee to file. filt(line)->bool filtert Ausgabe."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, errors="replace", bufsize=1)
    except FileNotFoundError:
        warn(f"not installed: {cmd[0]}", t); return (127, "")
    killer = threading.Timer(timeout, p.kill); killer.start()
    buf = []
    try:
        for line in p.stdout:
            buf.append(line)
            ln = line.rstrip("\n")
            if ln and echo and (filt is None or filt(ln)):
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

def scan_creds(root, report):
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
    if hits:
        Path(report).write_text("\n".join(hits))
        warn(f"{len(hits)} moegliche Credential-Treffer -> {report}")
        for h in hits[:20]: emit("   "+col("Y",h))
        if len(hits) > 20: emit(f"   {col('d','... +'+str(len(hits)-20)+' weitere')}")
    return hits

def portscan(ip, out):
    head("PORT-SCAN")
    gfile = out/"scans"/"all-ports.gnmap"
    info("full port scan (all 65535 ports)", "nmap")
    run_live(["nmap","-p-","--min-rate",str(RATE),"-T4","-Pn","-n","-v",
              "-oG",str(gfile),"-oN",str(out/"scans"/"all-ports.txt"), ip],
             t="nmap", timeout=T_FULLSCAN,
             filt=lambda l: "Discovered open port" in l or "Completed" in l or "scan report" in l)
    ports = sorted({m.group(1) for m in re.finditer(r"(\d+)/open",
                    gfile.read_text(errors="replace"))} if gfile.exists() else set(), key=int)
    if not ports:
        warn("no open tcp ports, trying udp top-50", "nmap")
        run_live(["nmap","-sU","--top-ports","50","-Pn","-n","-oN",
                  str(out/"scans"/"udp.txt"), ip], t="nmap", timeout=T_SVCSCAN)
        return {}, ""
    ok("Offene Ports: "+col("G",", ".join(ports)), "nmap")
    info("service scan on open ports", "nmap")
    _, svc = run_live(["nmap","-p",",".join(ports),"-sCV","-Pn","-n","-oN",
                       str(out/"scans"/"services.txt"), ip], t="nmap", timeout=T_SVCSCAN,
                      filt=lambda l: bool(re.match(r"\d+/tcp", l)) or "|" in l)
    svcmap = {}
    for line in svc.splitlines():
        m = re.match(r"\s*(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if m: svcmap[m.group(1)] = (m.group(2), m.group(3))
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
    dest = out/"files"/"ftp"; dest.mkdir(parents=True, exist_ok=True)
    try:
        ftp = ftplib.FTP(); ftp.connect(ip, 21, timeout=15)
        ftp.login("anonymous","anonymous@")
        finding("FTP", "anonymous login allowed", "ftp")
        ok("anonymous login ok, downloading all files", "ftp")
    except Exception as e:
        warn(f"no anon ftp: {e}", "ftp"); return
    n = [0]
    def pull(path=""):
        try: items = ftp.nlst(path)
        except Exception: return
        for it in items:
            if it in (".",".."): continue
            name = it if (not path or it.startswith(path)) else f"{path.rstrip('/')}/{it}"
            try:
                ftp.cwd("/"+name.strip("/")); pull(name)
            except ftplib.error_perm:
                local = dest/name.lstrip("/"); local.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with open(local,"wb") as fh: ftp.retrbinary("RETR "+name, fh.write)
                    n[0]+=1; raw("get "+name, "ftp")
                except Exception: pass
    try: pull()
    finally:
        try: ftp.quit()
        except Exception: pass
    ok(f"{n[0]} file(s) -> {dest}", "ftp")

def smb_anon(ip, out):
    info("enumerate SMB (139/445)", "smb")
    dest = out/"files"/"smb"; dest.mkdir(parents=True, exist_ok=True)
    if have("smbmap"):
        run_live(["smbmap","-H",ip], t="smb", outfile=out/"scans"/"smbmap.txt",
                 timeout=T_GENERIC, filt=lambda l: "READ" in l or "Disk" in l or "ANONYMOUS" in l)
    if not have("smbclient"):
        warn("smbclient missing, skipping share grab", "smb"); return
    _, listing = run(["smbclient","-N","-L",f"//{ip}/"], timeout=T_GENERIC)
    shares = [s for s in re.findall(r"^\s*(\S+)\s+Disk", listing, re.M)
              if s.upper() not in ("ADMIN$","IPC$","C$","PRINT$")]
    if not shares:
        warn("no readable shares", "smb"); return
    finding("SMB", "readable shares: "+", ".join(shares), "smb")
    for sh in shares:
        sdir = dest/sh; sdir.mkdir(parents=True, exist_ok=True)
        info(f"grabbing share '{sh}'", "smb")
        run(["smbclient","-N",f"//{ip}/{sh}","-c",
             f"recurse ON; prompt OFF; lcd {sdir}; mget *"], timeout=T_GENERIC)
    ok(f"SMB-Files -> {dest}", "smb")

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

def gobuster_recursive(base, wd, tag, budget):
    if not (ENABLE_GOBUSTER and have("gobuster") and WORDLIST.exists()):
        if not have("gobuster"): warn("gobuster missing", tag)
        return
    seen = set(); queue = [(base.rstrip("/")+"/", 0)]
    while queue and budget[0] > 0:
        url, depth = queue.pop(0)
        if url in seen: continue
        seen.add(url); budget[0] -= 1
        wl = WORDLIST if depth == 0 else RECURSE_WORDLIST
        outf = wd/("gobuster_"+re.sub(r"\W+","_",url).strip("_")+".txt")
        info(f"gobuster d{depth} {url}  ({wl.name})", tag)
        gcmd = ["gobuster","dir","-u",url,"-w",str(wl),"-t",str(THREADS),
                "-q","-k","--no-error","--timeout","10s","-o",str(outf)]
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

def vhost_scan(ip, port, scheme, root, wd, tag):
    if not (ENABLE_VHOST and have("ffuf") and DNS_WORDLIST.exists()): return []
    outj = wd/"vhosts.json"
    info(f"vhost fuzzing FUZZ.{root}", tag)
    run_live(["ffuf","-w",str(DNS_WORDLIST),"-u",f"{scheme}://{ip}:{port}/",
              "-H",f"Host: FUZZ.{root}","-t",str(THREADS),"-ac","-s",
              "-of","json","-o",str(outj)], t=tag, timeout=T_GOBUSTER,
             filt=lambda l: bool(l.strip()))
    subs = []
    try:
        for r in json.loads(outj.read_text()).get("results", []):
            fz = r.get("input",{}).get("FUZZ")
            if fz: subs.append(f"{fz}.{root}")
    except Exception: pass
    for s in subs: finding("VHOST", s, tag)
    return subs

def web(ip, port, out, host):
    tag = f"web:{port}"
    scheme = "https" if port in ("443","8443") else "http"
    info(f"enumerate web ({scheme})", tag)
    wd = out/"web"/port; wd.mkdir(parents=True, exist_ok=True)
    primary = host or ip
    # Initiale Seite + Hints
    if have("curl"):
        for url in ([f"{scheme}://{host}:{port}/"] if host else []) + [f"{scheme}://{ip}:{port}/"]:
            tagf = re.sub(r"\W+","_",url)
            _, body = run(["curl","-sk","-m","15","-L",url], wd/f"index_{tagf}.html", timeout=30)
            run(["curl","-skI","-m","15",url], wd/f"headers_{tagf}.txt", timeout=30)
            tt = re.search(r"(?is)<title>(.*?)</title>", body)
            if tt: info(f"{url}  <title> {tt.group(1).strip()[:70]}", tag)
            for m in list(re.finditer(r"(?i)(password|username|api[_-]?key|todo|flag|<!--.*?-->)", body))[:6]:
                s = m.group(0).strip().replace("\n"," ")[:120]
                if s: raw("hint "+s, tag)
    if not DO_WEBFUZZ:
        return
    # vHosts -> /etc/hosts -> auch fuzzen
    subs = []
    root = host.split(".",1)[-1] if host and "." in host else (host or "htb")
    if host:
        subs = vhost_scan(ip, port, scheme, root, wd, tag)
        for s in subs: add_host(ip, s)
    budget = [GOBUSTER_BUDGET]
    for tgt_host in [primary] + subs:
        gobuster_recursive(f"{scheme}://{tgt_host}:{port}", wd, tag, budget)
    # dirsearch (lokal oder im PATH)
    if ENABLE_DIRSEARCH:
        base = f"{scheme}://{primary}:{port}"
        if have("dirsearch"):
            run_live(["dirsearch","-u",base,"-q","--format=plain","-o",str(wd/"dirsearch.txt")],
                     t=tag, timeout=T_DIRSRCH, filt=lambda l: "/" in l and "%" not in l)
        elif (SCRIPT_DIR/"dirsearch"/"dirsearch.py").exists():
            run_live(["python3",str(SCRIPT_DIR/"dirsearch"/"dirsearch.py"),"-u",base,"-q",
                      "-o",str(wd/"dirsearch.txt")], t=tag, timeout=T_DIRSRCH)

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
    users = out/"users.txt"
    if have("kerbrute") and USER_WORDLIST.exists():
        info("kerbrute userenum ...", "krb")
        _, o = run_live(["kerbrute","userenum","-d",dom,"--dc",ip,str(USER_WORDLIST)],
                        t="krb", outfile=out/"scans"/"kerbrute.txt", timeout=T_GENERIC,
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
                        t="krb", outfile=out/"scans"/"asrep.txt", timeout=T_GENERIC,
                        filt=lambda l: "krb5asrep" in l or "error" in l.lower())
        if "$krb5asrep$" in o:
            finding("KRB", "AS-REP Hash -> scans/asrep.txt (hashcat -m 18200)", "krb")

def hydra_prompt(ip, svcmap, out):
    svcs = []
    if "22" in svcmap or any("ssh" in n for n,_ in svcmap.values()): svcs.append(("ssh","22"))
    if "21" in svcmap or any("ftp" in n for n,_ in svcmap.values()): svcs.append(("ftp","21"))
    if not (svcs and have("hydra")):
        if svcs and not have("hydra"): warn("hydra not installed, skipping brute")
        return
    users = out/"users.txt"
    ulist = str(users) if users.exists() else str(USER_WORDLIST)
    emit()
    if not ask(f"run hydra against {', '.join(s for s,_ in svcs)}? "
               +col("d",f"({Path(ulist).name} x {PASS_WORDLIST.name})"), default="n"):
        info("hydra skipped"); return
    if not (Path(ulist).exists() and PASS_WORDLIST.exists()):
        warn("user/pass list missing"); return
    for name, port in svcs:
        head(f"HYDRA {name}")
        _, o = run_live(["hydra","-L",ulist,"-P",str(PASS_WORDLIST),"-t","4","-f","-I",
                  "-o",str(out/"scans"/f"hydra-{name}.txt"),f"{name}://{ip}"],
                 t="hydra", timeout=T_HYDRA, filt=lambda l: "login:" in l or "valid" in l.lower())
        for m in re.finditer(r"login:\s*(\S+)\s+password:\s*(\S+)", o):
            finding("CREDS", f"{name}  {m.group(1)}:{m.group(2)}", "hydra")

def ask(q, default="n"):
    try:
        a = input(col("Y","[?] ")+q+col("d",f" [{'Y/n' if default=='y' else 'y/N'}] ")).strip().lower()
    except EOFError:
        a = ""
    return (a or default) == "y"

def main():
    if len(sys.argv) < 2:
        emit(col("G",col("b",BANNER))); emit("\n  Usage: sudo ./p4ckrat.py <IP> [name]\n"); sys.exit(1)
    ip = sys.argv[1]; name = sys.argv[2] if len(sys.argv) > 2 else ip
    out = Path("recon")/name
    for sub in ("scans","files","web"): (out/sub).mkdir(parents=True, exist_ok=True)

    logf  = open(out/"p4ckrat.log", "w", encoding="utf-8")
    findf = open(out/"findings.txt", "w", encoding="utf-8")
    findf.write(f"# p4ckrat findings - {ip} ({name}) - {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    findf.flush()
    set_logs(logf, findf)

    banner(ip, name)
    info(f"live findings  -> {out}/findings.txt", None)
    info(f"full log       -> {out}/p4ckrat.log", None)
    if not have("nmap"): err("nmap missing, abort"); sys.exit(1)

    svcmap, svc = portscan(ip, out)
    if not svcmap:
        warn("no open ports, nothing to do"); return
    finding("PORTS", ", ".join(f"{p}/{svcmap[p][0]}" for p in sorted(svcmap, key=int)))
    host = guess_hostname(ip, svc)
    if host:
        finding("HOST", host); add_host(ip, host)

    web_ports = [p for p,(n,_) in svcmap.items()
                 if "http" in n or p in ("80","443","8080","8000","8443","8081")]

    global DO_WEBFUZZ
    if web_ports:
        DO_WEBFUZZ = ask(f"run web fuzzing (gobuster+dirsearch+vhost) on port {', '.join(web_ports)}?",
                         default="y")
        if not DO_WEBFUZZ:
            info("web fuzzing skipped (only index/headers fetched)")

    head("ENUM (parallel)")
    workers = list(filter(None,[
        "ftp" if "21" in svcmap else "",
        "smb" if ("445" in svcmap or "139" in svcmap) else "",
        *[f"web:{p}" for p in web_ports],
        "kerberos" if "88" in svcmap else ""]))
    info(f"{CONCURRENCY} workers: "+col("w",", ".join(workers)))
    jobs = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        if "21" in svcmap: jobs.append(ex.submit(ftp_anon, ip, out))
        if "445" in svcmap or "139" in svcmap: jobs.append(ex.submit(smb_anon, ip, out))
        for wp in web_ports: jobs.append(ex.submit(web, ip, wp, out, host))
        if "88" in svcmap: jobs.append(ex.submit(kerberos, ip, out, host))
        for f in as_completed(jobs):
            try: f.result()
            except Exception as e: err(f"phase error: {e!r}")

    head("CREDENTIAL-SCAN")
    for h in scan_creds(out/"files", out/"creds_files.txt"): finding("CREDS", h[:160])
    for h in scan_creds(out/"web",   out/"creds_web.txt"):   finding("CREDS", h[:160])

    hydra_prompt(ip, svcmap, out)

    head("DONE")
    ok(f"done in {_el()} -> {col('G',str(out))}/")
    info(col("w",f"{out}/findings.txt")+col("d","  (live findings)"))
    info(col("w",f"{out}/scans/services.txt")+col("d","  ")+col("w",f"{out}/web/")
         +col("d","  ")+col("w",f"{out}/files/"))
    emit()
    try: logf.close(); findf.close()
    except Exception: pass

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: err("\nabgebrochen.")
