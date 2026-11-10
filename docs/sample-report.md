# Vulnerability scan report

Generated: 2026-11-10 19:56 UTC

## Scan details

| Item | Value |
|------|-------|
| Nmap version | 7.94 |
| Command | `nmap -sV --top-ports 1000 -T3 --open -oX - -- 192.0.2.0/24` |
| Started | Mon Nov 10 19:00:00 2026 |
| Duration (s) | 48.20 |
| Hosts up / down | 5 / 251 |

## Summary

| Priority | Hosts | Findings |
|----------|------:|---------:|
| Critical | 2 | 2 |
| High | 1 | 3 |
| Medium | 1 | 4 |
| Low | 0 | 0 |
| Info | 1 | 6 |

## Top priorities (up to 15)

| # | Host | Port | Service | Score | Priority | Why |
|--:|------|------|---------|------:|----------|-----|
| 1 | 192.0.2.30 | 80/tcp | http | 9.8 | Critical | 2 CVE(s) reported by the vulners script, highest CVSS 9.8. |
| 2 | 192.0.2.20 | 23/tcp | telnet | 9.0 | Critical | Telnet service exposed |
| 3 | 192.0.2.30 | 6379/tcp | redis | 8.0 | High | Datastore commonly deployed without authentication |
| 4 | 192.0.2.10 | 80/tcp | http | 7.5 | High | Apache HTTP Server 2.2 no longer receives security updates. (found Apache httpd 2.2.34 ((Ubuntu))) |
| 5 | 192.0.2.20 | 21/tcp | ftp | 7.0 | High | FTP service exposed |
| 6 | 192.0.2.40 | 3389/tcp | ms-wbt-server | 6.5 | Medium | RDP exposed |
| 7 | 192.0.2.20 | 445/tcp | microsoft-ds | 6.0 | Medium | SMB file sharing exposed |
| 8 | 192.0.2.40 | 445/tcp | microsoft-ds | 6.0 | Medium | SMB file sharing exposed |
| 9 | 192.0.2.40 | 389/tcp | ldap | 4.5 | Medium | LDAP without TLS |

## Hosts

### 192.0.2.30 (app01.lab.example): Critical (9.9)

OS guess: Linux 5.4

| Port | Service | Version | Score | Priority |
|------|---------|---------|------:|----------|
| 80/tcp | http | Apache httpd 2.4.49 ((Unix)) | 9.8 | Critical |
| 6379/tcp | redis | Redis key-value store 7.0.15 | 8.0 | High |
| 22/tcp | ssh | OpenSSH 8.9p1 (Ubuntu Linux; protocol 2.0) | 1.5 | Info |

Recommended actions:

- **80/tcp**: Redirect to HTTPS and enable HSTS.
- **80/tcp**: Apply vendor patches for the listed CVEs, or upgrade the affected software.
- **6379/tcp**: Bind to localhost or a private interface.
- **6379/tcp**: Enable authentication and TLS.

### 192.0.2.20 (legacy01.lab.example): Critical (9.2)

OS guess: Linux 3.x

| Port | Service | Version | Score | Priority |
|------|---------|---------|------:|----------|
| 23/tcp | telnet | Linux telnetd | 9.0 | Critical |
| 21/tcp | ftp | vsftpd 3.0.3 | 7.0 | High |
| 445/tcp | microsoft-ds | Samba smbd 4 (workgroup: LAB) | 6.0 | Medium |

Recommended actions:

- **23/tcp**: Disable telnet and use SSH.
- **23/tcp**: Block the port at the host firewall.
- **21/tcp**: Replace with SFTP or FTPS.
- **21/tcp**: Disable anonymous access if it is not needed.
- **445/tcp**: Limit to required clients.
- **445/tcp**: Disable SMBv1 and require signing.

### 192.0.2.10 (web01.lab.example): High (7.5)

OS guess: Linux 5.15 - 6.1

| Port | Service | Version | Score | Priority |
|------|---------|---------|------:|----------|
| 80/tcp | http | Apache httpd 2.2.34 ((Ubuntu)) | 7.5 | High |
| 22/tcp | ssh | OpenSSH 9.6p1 (Ubuntu Linux; protocol 2.0) | 1.5 | Info |
| 443/tcp | http | nginx 1.24.0 | 1.0 | Info |

Recommended actions:

- **80/tcp**: Redirect to HTTPS and enable HSTS.
- **80/tcp**: Upgrade to a supported Apache 2.4 release.

### 192.0.2.40 (dc01.lab.example): Medium (6.7)

OS guess: Microsoft Windows Server 2019

| Port | Service | Version | Score | Priority |
|------|---------|---------|------:|----------|
| 3389/tcp | ms-wbt-server | Microsoft Terminal Services | 6.5 | Medium |
| 445/tcp | microsoft-ds | - | 6.0 | Medium |
| 389/tcp | ldap | Microsoft Windows Active Directory LDAP (Domain: lab.example) | 4.5 | Medium |
| 53/tcp | domain | - | 1.0 | Info |
| 88/tcp | kerberos-sec | Microsoft Windows Kerberos (server time: 2026-11-10 19:00:00Z) | 1.0 | Info |

Recommended actions:

- **3389/tcp**: Restrict to a management network or VPN.
- **3389/tcp**: Enforce MFA and Network Level Authentication.
- **445/tcp**: Limit to required clients.
- **445/tcp**: Disable SMBv1 and require signing.
- **389/tcp**: Require LDAPS or StartTLS and disable simple binds over clear text.

### 192.0.2.50 (util01.lab.example): Info (1.5)

OS guess: Linux 6.x

| Port | Service | Version | Score | Priority |
|------|---------|---------|------:|----------|
| 22/tcp | ssh | OpenSSH 9.6p1 (Ubuntu Linux; protocol 2.0) | 1.5 | Info |

## Method and limits

- Each open port is scored 0-10 from an editable rule set (`rules.toml`) and, when the vulners script was used, the highest CVSS score it reported.
- A host score is its highest finding plus a small bonus (up to 1.0) when several findings are Medium or above.
- Bands: Critical 9+, High 7+, Medium 4+, Low 2+, Info below 2.
- Scores express exposure risk. They are not proof that a vulnerability exists, and this scan does not test authentication or exploitability.
