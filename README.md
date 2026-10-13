# p4ckrat

```
          _____          __                   __
______   /  |  |   ____ |  | ______________ _/  |_
\____ \ /   |  |__/ ___\|  |/ /\_  __ \__  \\   __\
|  |_> >    ^   /\  \___|    <  |  | \// __ \|  |
|   __/\____   |  \___  >__|_ \ |__|  (____  /__|
|__|        |__|      \/     \/            \/
```

**Full-auto recon & loot grabber for CTF / HackTheBox boxes.**
One command -> p4ckrat scans the box, grabs every file it can reach via FTP/SMB,
hunts credentials in the loot, enumerates Kerberos users and lines up the
low-hanging fruit - in parallel, with a clean live-updating terminal output and
a `findings.txt` you can `tail -f`.

The philosophy: **the terminal is the report.** p4ckrat only writes a file to
disk when it actually grabbed something worth keeping - never a tree of empty
folders.

> by **p4cket** - [github.com/pwl-de](https://github.com/pwl-de)

## Usage

```bash
sudo ./p4ckrat.py <IP>
# e.g.
sudo ./p4ckrat.py 10.10.10.3
```

`sudo` lets it write discovered hostnames to `/etc/hosts`. Without root it just
prints them. Runs on your attacker box (Kali / Pwnbox). Results land in a
`p4ckrat/` folder in the **current directory** - no name prompt, no arguments
beyond the IP.

## Sample output

```
port-scan
[*] nmap full port scan (all 65535 ports)
    nmap Discovered open port 80/tcp
[+] ports: 21/ftp, 22/ssh, 53/domain, 80/http, 443/ssl/http, 445/smb
[+] host: friendzone.red

enum (parallel)
[-] ftp no anon ftp: 530 login incorrect
[+] smb: readable shares: Files, general, Development
[+] smb: SMB-Files -> p4ckrat/files/smb
```

`[+]` lines are the highlights, mirrored live into `findings.txt`. Each phase
tag (`ftp`, `smb`, `web:80`, ...) is colour-coded so the parallel output stays
readable.

## What it does

| Phase | Action |
|-------|--------|
| **Port-Scan** | `nmap -p-` (fast, live "Discovered open port") -> `-sCV` on open ports only. Output is streamed, not saved. |
| **Hostname** | derives vhost from HTTP redirect / TLS cert / LDAP -> auto-adds to `/etc/hosts` |
| **FTP** | anonymous login -> pulls **all** files recursively -> `files/ftp/` (only if files are actually downloaded) |
| **SMB** | `smbmap` perms + grabs every readable share recursively -> `files/smb/` (empty shares leave nothing behind) |
| **Web** | fetches the index page and flags inline hints; the HTML is **only saved** (to `files/web/`) if something interesting shows up (passwords, tokens, flags, comments...). Then, **after a y/n prompt**, runs **recursive gobuster** - hits stream live into `findings.txt`, no file dumps. |
| **Kerberos** | `kerbrute` user-enum -> **AS-REP roast** (`GetNPUsers`). A found hash is saved to `files/asrep_hashes.txt` (hashcat -m 18200). |
| **Creds** | regex-scans all looted files under `files/` for passwords, keys, tokens, connection strings |
| **Hydra** | **asked at the end** (y/N) - SSH/FTP brute with small lists, off the critical path. The one remaining prompt. |

### Speed
Enum phases (FTP, SMB, every web port, Kerberos) run **concurrently** in a thread
pool. Everything streams live so you can act on the first finding before the rest
finishes. Hydra is not inline - it only runs if you confirm at the end.

## Config

Edit the config block at the top of `p4ckrat.py`:

| Var | Meaning |
|-----|---------|
| `WORDLIST` | main gobuster wordlist (default: SecLists raft-small-directories - bump to raft-medium for more coverage) |
| `RECURSE_WORDLIST` | smaller list for recursive sub-dir fuzzing |
| `GOBUSTER_EXT` | file extensions to append (fewer = faster; each one multiplies requests) |
| `GOBUSTER_DEPTH` / `GOBUSTER_BUDGET` | recursion depth & total-run cap |
| `USER_WORDLIST` / `PASS_WORDLIST` | for Kerberos enum + Hydra |
| `DOMAIN` | force the AD domain (empty = auto-detect) |
| `THREADS` / `RATE` / `CONCURRENCY` | tuning knobs (gobuster threads, nmap min-rate, parallel enum workers) |
| `ENABLE_HOSTS` | toggle auto-writing discovered hosts to `/etc/hosts` |
| `T_*` | per-tool timeouts (anti-hang) |

Wordlists auto-resolve: local `../wordlists/SecLists`, then `/usr/share/seclists`.

## Dependencies

`nmap` is required. Everything else is optional and skipped if missing:
`smbclient`, `smbmap`, `gobuster`, `kerbrute`, `impacket-GetNPUsers`, `hydra`,
`curl`. FTP grab + credential scan use only the Python standard library (3.8+).

```bash
# Kali: meist alles schon da, sonst:
sudo apt install -y nmap smbclient smbmap gobuster hydra seclists
pipx install impacket
go install github.com/ropnop/kerbrute@latest
```

## Output layout

p4ckrat creates a `p4ckrat/` folder in the current directory. It always contains
the log and findings; `files/` (and its sub-folders) only appear when something
was actually grabbed:

```
p4ckrat/
├── findings.txt            LIVE highlights (ports, creds, shares, hashes...)
├── p4ckrat.log             full console log, colour-stripped
└── files/                  only if loot was found
    ├── ftp/                anonymous-FTP downloads
    ├── smb/<share>/        readable SMB shares
    ├── web/<url>.html      web pages that contained something interesting
    └── asrep_hashes.txt    AS-REP roast hashes
```

If a run finds nothing beyond open ports, you get just `findings.txt` +
`p4ckrat.log` - no empty `files/`, no scan dumps, no web folder.

**`findings.txt`** updates live while the run is going - `tail -f p4ckrat/findings.txt`
in a second terminal to watch quick wins land in real time.

## Prompts
Two interactive y/n gates:
- **Gobuster** (recursive dir fuzz) - asked right after the port scan, before the
  parallel enum phase. Defaults to `yes`.
- **Hydra** (SSH/FTP brute) - asked at the very end, off the critical path.
  Defaults to `no`.

Both auto-pick their default when run non-interactively (piped / no TTY).

## Disclaimer
For authorized testing only - CTFs, HackTheBox, labs and boxes you own or have
explicit permission to test. Don't point it at anything else.

---

Made by **p4cket** - [github.com/pwl-de](https://github.com/pwl-de)
