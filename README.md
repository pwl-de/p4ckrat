# p4ckrat

```
          _____          __                   __
______   /  |  |   ____ |  | ______________ _/  |_
\____ \ /   |  |__/ ___\|  |/ /\_  __ \__  \\   __\
|  |_> >    ^   /\  \___|    <  |  | \// __ \|  |
|   __/\____   |  \___  >__|_ \ |__|  (____  /__|
|__|        |__|      \/     \/            \/
```

**Full-auto recon & loot grabber for CTF / HackTheBox / VulnLab boxes.**

Point it at one IP: p4ckrat scans the box, enumerates every service in parallel,
grabs the loot, scans it for passwords, and sprays those passwords back at the box
to find a working login — live in the terminal, with a `findings.txt` you can
`tail -f`.

> by **p4cket** — [github.com/pwl-de](https://github.com/pwl-de)

## Usage

```bash
sudo ./p4ckrat.py <IP>
# e.g.
sudo ./p4ckrat.py 10.129.82.231 -d baby.vl
```

Output lands in `./p4ckrat/<IP>/` (`findings.txt`, `p4ckrat.log`, `files/`) — one
folder per target, so a new box never overwrites the previous run. Override with
`-o DIR`. Run as root so it can add discovered vhosts to `/etc/hosts` (a stale entry
for a recycled box IP is rewritten, not duplicated).

Useful flags (`./p4ckrat.py -h` for all):

```
-d DOMAIN      force the AD domain (else auto-detected)
-o DIR         output directory (default: p4ckrat/<IP>/)
--udp          also run a parallel UDP top-20 scan
--nuclei       run nuclei on discovered web ports
--crawl        crawl web ports with katana/gau
--secretsdump  run secretsdump once SMB admin access is found
--no-gobuster  skip the recursive dir fuzz (no prompt)
--no-spray     disable the credential-spray / pivot phase
--dry-run      print the commands that would run, execute nothing
-q / -v        quieter (findings only) / verbose (all tool lines + commands)
```

## Dependencies

`nmap` required; everything else optional and skipped if missing (`netexec`,
`smbclient`, `enum4linux-ng`, `ldapsearch`, `gobuster`, `ffuf`, `nuclei`,
impacket, `hydra`, `searchsploit`, …).

```bash
sudo apt install -y nmap netexec smbclient enum4linux-ng gobuster ffuf nuclei \
                    hydra exploitdb seclists ldap-utils snmp nfs-common \
                    redis-tools rsync sshpass && pipx install impacket
```

## Disclaimer

Authorized testing only — CTFs, labs, and boxes you own or have permission to test.
