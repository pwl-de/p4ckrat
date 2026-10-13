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

One command and p4ckrat scans the target, grabs reachable files (FTP/SMB), fuzzes
web dirs, enumerates Kerberos users (AS-REP roast) and scans the loot for
credentials - all in parallel, with live terminal output and a `findings.txt` you
can `tail -f`. It only writes a file to disk when it actually grabbed something.

> by **p4cket** - [github.com/pwl-de](https://github.com/pwl-de)

## Usage

```bash
sudo ./p4ckrat.py <IP>      # sudo lets it add discovered vhosts to /etc/hosts
```

Runs on your attacker box (Kali / Pwnbox). Results land in a `p4ckrat/` folder in
the current directory (`findings.txt`, `p4ckrat.log`, and `files/` if loot was
found). Two optional y/n prompts: gobuster (after the port scan, default yes) and
hydra brute (at the end, default no).

Config knobs (wordlists, threads, timeouts, domain, `/etc/hosts` toggle) are the
block at the top of `p4ckrat.py`.

## Dependencies

`nmap` is required; everything else is optional and skipped if missing
(`smbclient`, `smbmap`, `gobuster`, `kerbrute`, `impacket-GetNPUsers`, `hydra`,
`curl`). FTP grab + cred scan use only the Python stdlib (3.8+).

```bash
sudo apt install -y nmap smbclient smbmap gobuster hydra seclists
pipx install impacket
go install github.com/ropnop/kerbrute@latest
```

## Disclaimer

For authorized testing only - CTFs, HackTheBox, labs and boxes you own or have
explicit permission to test.
