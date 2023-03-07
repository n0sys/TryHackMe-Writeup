## Task 8
```
# Skip port scan
$ nmap -sn -v 10.200.*.* 
Nmap done: 65536 IP addresses (4 hosts up) scanned in 4135.57 seconds
CTRL + SHIFT + F Host is up
10.200.0.0
10.200.107.250
10.200.107.33 (web server)
10.200.0.7
```
```
$ nmap -sV -sC -p- 10.200.107.30 10.200.107.250 10.200.0.7
```

## Task 9
Quest 1:
[Holo](imgs/task9_imgs.png)

Quest 2:
```
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.200.107.33 -H "Host: FUZZ.holo.live"  --fs 21456


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.200.107.33
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.holo.live
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 21456
________________________________________________

admin                   [Status: 200, Size: 1845, Words: 453, Lines: 76, Duration: 2571ms]
dev                     [Status: 200, Size: 7515, Words: 639, Lines: 272, Duration: 4614ms]
www.www                 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 256ms]
```

## Task 10

