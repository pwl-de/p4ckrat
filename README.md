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

One command and p4ckrat scans the target and enumerates what it finds - all in
parallel, with live terminal output and a `findings.txt` you can `tail -f`. It
only writes a file to disk when it actually grabbed something.

Covers: nmap port scan (+ optional UDP top-20), FTP/SMB/NFS loot grab, SMB user
enum (enum4linux-ng / RID cycling), LDAP anonymous bind, SNMP, RPC, Redis, rsync,
MSSQL/MySQL/PostgreSQL default-cred probes, web index + recursive gobuster + vhost
fuzzing (+ optional nuclei), Kerberos AS-REP roast, a credential scan of the loot,
optional hydra brute, and a **credential-spray / pivot** phase that replays every
found `user:pass` against SSH/SMB/WinRM/FTP.

> by **p4cket** - [github.com/pwl-de](https://github.com/pwl-de)

## Usage

```bash
sudo ./p4ckrat.py <IP>      # sudo lets it add discovered vhosts to /etc/hosts
```

Flags:

| Flag | Effect |
|------|--------|
| `-d, --domain <dom>` | force the AD domain (else auto-detect) |
| `--udp` | also run a parallel UDP top-20 scan (DNS/SNMP/TFTP) |
| `--nuclei` | run nuclei on discovered web ports |
| `--no-gobuster` | skip gobuster (no prompt) |
| `--no-spray` | disable the credential-spray / pivot phase |
| `-q` / `-v` | quiet (findings only) / verbose (all tool lines + commands) |
| `--dry-run` | print the commands that *would* run, execute nothing |

Runs on your attacker box (Kali / Pwnbox). Results land in a `p4ckrat/` folder in
the current directory (`findings.txt`, `p4ckrat.log`, and `files/` if loot was
found). Two optional y/n prompts: gobuster (after the port scan, default yes) and
hydra brute (near the end, default no).

Config knobs (wordlists, threads, timeouts, `/etc/hosts` toggle) are the block at
the top of `p4ckrat.py`.

## Dependencies

`nmap` is required; everything else is optional and skipped if missing
(`smbclient`, `smbmap`, `enum4linux-ng`, `rpcclient`, `gobuster`, `ffuf`,
`nuclei`, `kerbrute`, `impacket-GetNPUsers`, `hydra`, `curl`, `ldapsearch`,
`snmpwalk`, `showmount`, `redis-cli`, `rsync`, `sshpass`, `netexec`/`nxc`, DB
clients). FTP grab + cred scan use only the Python stdlib (3.8+).

```bash
sudo apt install -y nmap smbclient smbmap gobuster ffuf hydra seclists \
                    ldap-utils snmp nfs-common redis-tools rsync sshpass
pipx install impacket
go install github.com/ropnop/kerbrute@latest
```

## Disclaimer

For authorized testing only - CTFs, HackTheBox, labs and boxes you own or have
explicit permission to test.
