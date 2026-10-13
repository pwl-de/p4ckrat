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

Point it at one IP and p4ckrat scans the box, enumerates every service it finds in
parallel, grabs any loot it can reach, scans that loot for credentials, and then
sprays those credentials back at the box to find a foothold — all with live
terminal output and a `findings.txt` you can `tail -f`.

What it touches: nmap (TCP + optional UDP), FTP/SMB/NFS loot, SMB/LDAP/RPC/SNMP/
Redis/rsync enum, DB default-cred probes, web (fingerprint → gobuster → robots/
sitemap → vhost fuzz → optional nuclei/crawl → default-cred checks), Kerberos
AS-REP & Kerberoast, searchsploit, SSH-key loot. The highlight is the **credential
loop**: it harvests passwords from the loot (including prose like *"set the
password to …"* and AD `description` fields), then sprays **every password against
every known user** over LDAP/SMB/WinRM (a `must-change` result still counts as a
valid hit), so a password hidden in one account's notes finds the account it
actually belongs to.

> by **p4cket** — [github.com/pwl-de](https://github.com/pwl-de)

## Usage

```bash
sudo ./p4ckrat.py <IP>
```

Example:

```bash
sudo ./p4ckrat.py 10.129.82.231 --udp -d baby.vl
```

Results land in `./p4ckrat/` (`findings.txt`, `p4ckrat.log`, and `files/` if loot
was found). `sudo` lets it add discovered vhosts to `/etc/hosts`. Two optional y/n
prompts: gobuster (after the port scan, default yes) and hydra (near the end,
default no).

Common flags: `-d DOMAIN`, `--udp`, `--nuclei`, `--crawl`, `--secretsdump`,
`--no-gobuster`, `--no-spray`, `-q`/`-v`, `--dry-run`. See `./p4ckrat.py -h`.

## Dependencies

`nmap` is required; everything else is optional and skipped if missing (e.g.
`netexec`, `smbclient`, `enum4linux-ng`, `gobuster`, `ffuf`, `whatweb`, `nuclei`,
`ldapsearch`, impacket, `hydra`, `searchsploit`, `sshpass`). FTP grab + credential
scan use only the Python stdlib (3.8+).

```bash
sudo apt install -y nmap netexec smbclient enum4linux-ng gobuster ffuf whatweb \
                    nuclei hydra exploitdb seclists ldap-utils snmp nfs-common \
                    redis-tools rsync sshpass
pipx install impacket
```

## Disclaimer

For authorized testing only — CTFs, HackTheBox, labs and boxes you own or have
explicit permission to test.
