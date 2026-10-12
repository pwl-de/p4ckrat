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
One command -> p4ckrat scans the box, grabs every file it can reach, hunts
credentials in the loot, maps web vhosts, recursively fuzzes directories,
enumerates Kerberos users and lines up the low-hanging fruit - in parallel,
with a clean live-updating output and a `findings.txt` you can `tail -f`.

> by **p4cket** - [github.com/pwl-de](https://github.com/pwl-de)

## Usage

```bash
sudo ./p4ckrat.py <IP> [name]
# e.g.
sudo ./p4ckrat.py 10.10.10.3 lame
```

`sudo` lets it write discovered hostnames to `/etc/hosts`. Without root it just
prints them. Runs on your attacker box (Kali / Pwnbox). Results land in
`recon/<name>/`.

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
[*] web:443 vhost fuzzing FUZZ.red
[+] vhost: administrator1.friendzone.red
[+] web: http://friendzone.red/admin (301)
```

`[+]` lines are the highlights, mirrored live into `findings.txt`. Each phase
tag (`ftp`, `smb`, `web:80`, ...) is colour-coded so the parallel output stays
readable.

## What it does

| Phase | Action |
|-------|--------|
| **Port-Scan** | `nmap -p-` (fast, live "Discovered open port") -> `-sCV` on open ports only |
| **Hostname** | derives vhost from HTTP redirect / TLS cert / LDAP -> auto-adds to `/etc/hosts` |
| **FTP** | anonymous login -> pulls **all** files recursively -> `files/ftp/` |
| **SMB** | `smbmap` perms + grabs every readable share recursively -> `files/smb/` |
| **Web** | dumps index/headers, flags inline hints, then (after a **y/n prompt**) **recursive gobuster** + **dirsearch** |
| **vHosts** | `ffuf` subdomain fuzz -> each found vhost is added to hosts **and fuzzed too** |
| **Kerberos** | `kerbrute` user-enum -> `users.txt` -> **AS-REP roast** (`GetNPUsers`, hashcat -m 18200) |
| **Creds** | regex-scans all looted files for passwords, keys, tokens, connection strings |
| **Hydra** | **asked at the end** (y/N) - SSH/FTP brute with small lists, off the critical path |

### Recursion
When gobuster finds a directory (e.g. `/admin`), p4ckrat fuzzes it again with a
smaller wordlist, down to `GOBUSTER_DEPTH` levels. Discovered vhosts get the
same dir-fuzzing treatment. A global `GOBUSTER_BUDGET` caps the total number of
runs so it never explodes.

### Speed
Enum phases (FTP, SMB, every web port, Kerberos) run **concurrently** in a thread
pool. Everything streams live so you can act on the first finding before the rest
finishes. Hydra is no longer inline - it only runs if you confirm at the end.

## Config

Edit the `CONFIG` block at the top of `p4ckrat.py`:

| Var | Meaning |
|-----|---------|
| `WORDLIST` | main gobuster wordlist (default: SecLists raft-small-directories - bump to raft-medium for more coverage) |
| `GOBUSTER_EXT` | file extensions to append (fewer = faster; each one multiplies requests) |
| `RECURSE_WORDLIST` | smaller list for recursive sub-dir fuzzing |
| `DNS_WORDLIST` | vhost/subdomain list |
| `USER_WORDLIST` / `PASS_WORDLIST` | for Kerberos enum + Hydra |
| `DOMAIN` | force the AD domain (empty = auto-detect) |
| `THREADS` / `RATE` / `CONCURRENCY` | tuning knobs |
| `GOBUSTER_DEPTH` / `GOBUSTER_BUDGET` | recursion depth & total-run cap |
| `ENABLE_*` | toggle gobuster / dirsearch / vhost / hosts |
| `T_*` | per-tool timeouts (anti-hang) |

Wordlists auto-resolve: local `../wordlists/SecLists`, then `/usr/share/seclists`.

## Dependencies

`nmap` is required. Everything else is optional and skipped if missing:
`smbclient`, `smbmap`, `gobuster`, `dirsearch`, `ffuf`, `kerbrute`,
`impacket-GetNPUsers`, `hydra`, `curl`. FTP grab + credential scan use only the
Python standard library (3.8+).

```bash
# Kali: meist alles schon da, sonst:
sudo apt install -y nmap smbclient smbmap gobuster ffuf hydra seclists
pipx install impacket && pipx install dirsearch
go install github.com/ropnop/kerbrute@latest
```

## Output layout

```
recon/<name>/
├── findings.txt      LIVE highlights (ports, creds, shares, vhosts, hashes...)
├── p4ckrat.log       full console log, colour-stripped
├── scans/            nmap, smbmap, kerbrute, asrep, hydra
├── files/            ftp/ + smb/  (all looted files)
├── web/<port>/       index, headers, gobuster_*, dirsearch, vhosts.json
├── users.txt         enumerated AD users
├── creds_files.txt   credential hits in looted files
└── creds_web.txt     credential hits in web responses
```

**`findings.txt`** updates live while the run is going - `tail -f recon/<name>/findings.txt`
in a second terminal to watch quick wins land in real time.

## Prompts
Two interactive y/n gates keep the slow stuff optional:
- **Web-Fuzzing** (gobuster/dirsearch/vhost) - asked right after the port scan.
- **Hydra** (SSH/FTP brute) - asked at the very end, off the critical path.

Both default safely (web = yes, hydra = no) and auto-pick the default when run
non-interactively (piped / no TTY).

## Disclaimer
For authorized testing only - CTFs, HackTheBox, labs and boxes you own or have
explicit permission to test. Don't point it at anything else.

---

Made by **p4cket** - [github.com/pwl-de](https://github.com/pwl-de)
