## Cyber Security Internship – Task 1 Report

**Task Name:** Scan Your Local Network for Open Ports  
**Objective:** Discover open ports on devices in your local network to understand network exposure  
**Tools Used:** Nmap, NSE,  Wireshark 

---

### 1. 📝 Introduction

Port scanning is a method used to identify open ports and services available on a networked device. It helps in understanding potential vulnerabilities in a system and is a foundational step in network reconnaissance for both defenders and attackers.

---

### 2. ⚙️ Environment Setup

- **Operating System:** Windows 11 / Kali Linux / Ubuntu WSL
    
- **Nmap Version:** 7.94
    
- **IP Range Used:**  192.168.1.0/24
    
- **Local IP Address:** 192.168.1.33
    

---

### 3. 🔍 Scanning Process

#### a. **Command Used**

```bash
nmap -sS 192.168.1.0/24

nmap --script=vuln 192.168.1.1
```

#### b. **Explanation**

- `-sS`: TCP SYN scan (stealthy and fast)
    
- `192.168.1.0/24`: Scans all 256 IPs in the local subnet
    

---

### 4. 📄 Results

- **Devices Found:** 1 host is up.
	- 192.168.1.1
    
- **Open Ports:** 

| PORT    | STATE | SERVICE  | VERSION                  |
| ------- | ----- | -------- | ------------------------ |
| 21/tcp  | open  | ftp      | GNU Inetutils FTPd 1.4.1 |
| 53/tcp  | open  | domain   | dnsmasq 2.87             |
| 80/tcp  | open  | http     | Boa HTTPd 0.93.15        |
| 443/tcp | open  | ssl/http | Boa HTTPd 0.93.15        |

	
- **Screenshots:**

![image alt](https://github.com/Vamsi212/Internship-Task1/blob/fa65baa975455b41412ba0ad46681453d54db11a/screenshots/screenshot1.png)

![image alt](https://github.com/Vamsi212/Internship-Task1/blob/fa65baa975455b41412ba0ad46681453d54db11a/screenshots/screenshot2.png)


---

### 5. 🔐 Security Analysis

- Identify potentially risky open ports : 21 - FTP, 80 -HTTP , 443 - HTTPS
- Identified Vulnerabilities (SEVERITY RISK Factor : HIGH)

![image alt](https://github.com/Vamsi212/Internship-Task1/blob/fa65baa975455b41412ba0ad46681453d54db11a/screenshots/screenshot3.png)

![image alt](https://github.com/Vamsi212/Internship-Task1/blob/fa65baa975455b41412ba0ad46681453d54db11a/screenshots/screenshot4.png)

![image alt](https://github.com/Vamsi212/Internship-Task1/blob/fa65baa975455b41412ba0ad46681453d54db11a/screenshots/screenshot5.png)

![image alt](https://github.com/Vamsi212/Internship-Task1/blob/fa65baa975455b41412ba0ad46681453d54db11a/screenshots/screenshot6.png)


- Suggestions for securing these ports (e.g., close unused ports, use firewall)


| Port | Service | Problem                                                                                                                                           | Solution                                                                                                                                                                                                                                                                                     |
| ---- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 21   | FTP     | FTP transmits credentials in cleartext.                                                                                                           | - Disable FTP if not in use.<br>    <br>- Replace with **SFTP** or **FTPS** for secure file transfer.<br>    <br>- Use strong access control and limit IPs allowed to connect.                                                                                                               |
| 22   | SSH     | Port is filtered, might be intentionally firewalled.                                                                                              | - Change default port from 22 to something higher (e.g., 2202).<br>    <br>- Use key-based authentication, **disable password login**.<br>    <br>- Enable fail2ban or rate-limiting to block brute-force attempts.                                                                          |
| 53   | DNS     | DNS services can be misused for amplification attacks or poisoning.                                                                               | - Restrict DNS to internal IPs only.<br>    <br>- Disable recursion for external queries.<br>    <br>- Monitor DNS traffic for anomalies.                                                                                                                                                    |
| 80   | HTTP    | **Vulnerabilities:**<br><br>- Detected **CSRF form** (`/boaform/admin/formLogin`)<br>    <br>- XSS scan attempted, but no stored or DOM XSS found | - Redirect HTTP to HTTPS.<br>        <br>- Implement **anti-CSRF tokens**.<br>        <br>- Sanitize user inputs and use security headers (`Content-Security-Policy`, etc.).                                                                                                                 |
| 443  | HTTPS   | **Vulnerabilities:**<br><br>- Heartbleed (CVE-2014-0160)<br>    <br>- POODLE (CVE-2014-3566)<br>    <br>- CCS Injection (CVE-2014-0224)           | - Upgrade **OpenSSL** to latest version (>=1.0.1h or newer).<br>    <br>- **Disable SSLv3** and weak cipher suites (`TLS_RSA_WITH_AES_128_CBC_SHA`).<br>    <br>- Prefer **TLS 1.2 or TLS 1.3** only.<br>    <br>- Reissue certificates if Heartbleed has been detected (possible key leak). |

### **General Hardening Recommendations**

- Use a **firewall (e.g., UFW, iptables)** to allow only needed ports.
    
- Run `nmap` scans regularly to detect changes.
    
- Keep all services updated (especially SSL libraries).
    
- Enable **intrusion detection systems (IDS)** like Snort or Suricata.
    
- Document exposed services and regularly audit them.




---

### 6. 📘 Learnings

- Gained hands-on experience using Nmap for port and vulnerability scanning.

- Understood the role of port scanning in identifying exposed services.

- Learned how attackers use scans to find weak points in a network.

- Detected real-world vulnerabilities like Heartbleed, POODLE, and CSRF.

- Learned how to analyze scan results and recommend security fixes.

- Improved skills in documentation and basic network security.

    

---

