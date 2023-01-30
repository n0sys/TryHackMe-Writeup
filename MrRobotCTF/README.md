# MrRobot CTF Writeup
<!-- Description -->
![machine](imgs/machine.png)
Completed on ??/??/20??
<!-- /Description -->
## Table of Contents
<!-- TOC -->
- [TryHackMe - MrRobot CTF - WriteUp](#TryHackMe-MrRobot-CTF-Writeup)
  - [Table of Contents](#table-of-contents)
  - [Let's Get Going!](#lets-get-going)
    - [Enumeration](#enumeration)
    - [Exploitation](#exploitation)
    - [Post Exploitation](#post-exploitation)
<!-- /TOC -->
---
## Let's Get Going
### Enumeration
We start as usual with the nmap scan
```bash
$ nmap -sC -sV -oN nmap/initial $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-29 18:39 EST
Nmap scan report for 10.10.250.193
Host is up (0.11s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.86 seconds
```
---
### Exploitation
---
### Post Exploitation
---

> Any feedback would be appreciated. Thank you !
