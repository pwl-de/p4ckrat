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

Output lands in `./p4ckrat/` (`findings.txt`, `p4ckrat.log`, `files/`). Run as
root so it can add discovered vhosts to `/etc/hosts`. Flags: `./p4ckrat.py -h`.

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
