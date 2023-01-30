# Wonderland Writeup
<!-- Description -->
![Wonderland](imgs/machine.png)
Completed on ??/??/20??
<!-- /Description -->
## Table of Contents
<!-- TOC -->
- [TryHackMe - Wonderland - WriteUp](#TryHackMe-Wonderland-Writeup)
  - [Table of Contents](#table-of-contents)
  - [Let's Get Going!](#lets-get-going)
    - [Enumeration](#enumeration)
      - [Nmap Scan](#nmap-scan)
      - [Nikto Scan](#nikto-scan)
      - [Directory Fuzzing](#directory-fuzzing)
    - [Exploitation](#exploitation)
    - [Post Exploitation](#post-exploitation)
<!-- /TOC -->
---
## Let's Get Going
### Enumeration
#### Nmap Scan
We start as usual with the nmap scan
```bash
$ nmap -sC -sV -oN nmap/initial $IP     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-30 16:10 EST
Nmap scan report for 10.10.138.169
Host is up (0.11s latency).
Not shown: 918 closed tcp ports (conn-refused), 80 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8eeefb96cead70dd05a93b0db071b863 (RSA)
|   256 7a927944164f204350a9a847e2c2be84 (ECDSA)
|_  256 000b8044e63d4b6947922c55147e2ac9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
As the port 80 is open, I decided to check the website myself.
![Wonderland](imgs/website.png)
The page source reveals nothing and checking common file names and directories returned nothing. So I decided to continue with a nikto scan and some directory fuzzing with ffuf.
#### Nikto Scan
```bash
$ nikto -h http://$IP              
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.138.169
+ Target Hostname:    10.10.138.169
+ Target Port:        80
+ Start Time:         2023-01-30 16:16:10 (GMT-5)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3092: /img/: This might be interesting...
+ 7889 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2023-01-30 16:39:43 (GMT-5) (1413 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
The nikto scan returned no results.
#### Directory Fuzzing
```bash
$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://$IP/FUZZ -e ".php,.html"      

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.138.169/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .php .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________
index.html              [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 259ms]
img                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 188ms]
r                       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 157ms]
```
The directory fuzzing was successful and we find a way to keep going. Upon visiting /r we got the following
```
Keep Going.
"Would you tell me, please, which way I ought to go from here?"
```
The /r was kinda odd as a directory name, so I tried /r/a and got a result as well! 
```
Keep Going.
"That depends a good deal on where you want to get to," said the Cat.
```
/r/a/a gave no results while /r/a/b was successful. It seems like the story is playing out within the subdirectories. You can notice as well that /r/a/b kinda build up to the word "rabbit" which was a title in the root directory page. And eventually, visiting /r/a/b/b/i/t returns a hint.
![Wonderland](imgs/door.png)
So Alice must now open the door to enter wonderland. In the page source, you find as well what looks like credentials
```
alice:HowDothTheLittleCrocodileImproveHisShiningTail
```
After doing some directory fuzzing and getting no results, I decided to search elsewhere. The final page found mentions a door to access wonderland which could mean the machine and a way to access remote machines is SSH! Using the found credentials we successfuly login to the machine.
```bash
$ ssh alice@$IP
Last login: Mon May 25 16:37:21 2020 from 192.168.170.1
alice@wonderland:~$
```

---
### Exploitation
---
### Post Exploitation
---

> Any feedback would be appreciated. Thank you !
