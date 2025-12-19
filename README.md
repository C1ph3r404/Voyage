# Voyage - TryHackMe Write-Up & Exploits  

## Overview  
Voyage is a Linux-based TryHackMe challenge that starts as a web exploitation task and slowly drags you into Docker hell before climbing out with kernel-level privileges.   

---

## Attack Path Summary  

### 1️⃣ Enumeration
Initial recon via `nmap` exposed:
- HTTP (80)
- SSH (22)
- SSH alternative port (2222)

Port 80 revealed Joomla + a juicy `robots.txt` that helped fingerprint the CMS version.  

### 2️⃣ Joomla Exploit  
Version 4.2.7 exposed an info disclosure vuln (CVE via ExploitDB), leaking creds through API endpoints. That got us SSH access on port 2222.  

✔️ foothold gained.  
✔️ inside Docker.  

### 3️⃣ Docker Escape #1  
Mapped internal subnet → found another host → SSH port-forwarding → reverse shell through insecure deserialization on a local web app cookie.  

Boom — second container.  

### 4️⃣ Docker Escape #2 → Host Root  
Found `cap_sys_module` enabled → wrote malicious kernel module → compiled → loaded → execution pops reverse shell as root on the host.  

💀 Game over.  

---

## Requirements
- python
- netcat
- SSH
- `nmap` + `ffuf`
- working brain 🧠  

---

## 🏁 Flags  
Obviously removed. Go earn them yourself 🫡  

---

## 📚 References  
- HackTricks Capabilities: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html  
- Docker Escape Notes: https://exploit-notes.hdks.org/exploit/container/docker/docker-escape/  

---

## ⚠️ Disclaimer  
Everything here is for educational + lab usage only.  
If you try this in the wild, you’re on your own buddy.  
