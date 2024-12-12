---
title: "Learning Python: Hash Cracking"
description: Working through making a Python program to crack SHA-256 Passwords
date: 2024-12-07 00:00:00 +0000
categories: [Learning Topics, Python]
tags: [Python, tools, sha256, lab, pentest, hash, pwn]
pin: true
math: true
mermaid: true
comments: true
media_subpath: /images/PythonHashCrack
img_path: /images/PythonHashCrack
image:
  path: thumbnail.jpeg
---

 Continuing my journey with Python, this post will walkthrough the process of creating another Python based tool. This time, for cracking hashes.

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Create a Python program to crack hashes using a wordlist.
{: .prompt-info }
<!-- markdownlint-restore -->

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> UPDATE: This tool is now available on my GitHub: [Z3R0Sec Hashcracker](https://github.com/Z3R0-sec/zs_hashcracker)
{: .prompt-info }
<!-- markdownlint-restore -->

## Introduction: Lab Setup

Be sure to have `pwntools` and `hashlib` installed before getting started. This can be done with the following command: 

```shell
pip install pwntools hashlib
```

Be sure to also have a wordlist available, `rockyou.txt` will be used here.

## Creating v1.0

Like the last post, I'll go through each section of the code to explain what it does and why it is needed. The first version of the code will be a simple script that will take a hash and a wordlist as input, and attempt to crack the hash using the passwords in the wordlist. Starting with the imports:

```python
from pwn import * 
import sys
import hashlib
```

These first line imports the `pwn` module, which is a powerful library with many useful features for both penetration testing and security. The `sys` module is used to handle system-specific parameters and functions, and `hashlib` allows for the use of hashing algorithms, SHA-256 in this case.

```python
if len(sys.argv) != 2:
    print("Invalid arguments")
    print(">> {} <sha256sum>".format(sys.argv[0]))
    exit()
```

This block of code checks if the correct number of arguments are passed to the script. If not, it will print an error message and exit the program. The correct usage is `python3 script.py <sha256sum>`, where `<sha256sum>` is the hash to be cracked.

```python
wanted_hash = sys.argv[1]
password_file = "rockyou.txt"
attempts = 0
```

Here, the script takes the hash to be cracked from the command line arguments and assigns it to the variable `wanted_hash`. The `password_file` variable is set to the path of the wordlist file, and the `attempts` variable is used to count the number of attempts made to crack the hash. This can be changed later to allow for user input.

```python
with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p:
```

This line creates a progress bar using the `log.progress` function. The progress bar will show the hash being cracked and the number of attempts made.

```python
    with open(password_file, "r", encoding='latin-1') as password_list:
```

This line opens the password file in read mode with the encoding set to `latin-1`. This is done to handle any special characters that may be present in the wordlist.

```python
        for password in password_list:
            password = password.strip("\n").encode('latin-1')  
```

This block of code reads each line in the wordlist file, strips the newline character, and encodes the password using `latin-1` encoding, again to handle any special characters that may be present in the wordlist.

```python
            password_hash = hashlib.sha256(password).hexdigest()  
            p.status("[{}] Trying password: {}".format(attempts, password.decode('latin-1')))
```

This line hashes the password using the SHA-256 algorithm and converts it to a hexadecimal string. The progress bar is updated with the number of attempts and the password being tried.

```python
            if password_hash == wanted_hash:
                p.success("Password hash found after {} attempts! '{}' hashes to {}".format(attempts, password.decode('latin-1'), password_hash))
                exit(0)  
            attempts += 1

    p.failure("Password hash not found after {} attempts!".format(attempts)) 
```

This block of code checks if the hashed password matches the hash to be cracked. If a match is found, the progress bar is updated with a success message and the program exits. If no match is found, the number of attempts is incremented. If the wordlist is exhausted and no match is found, the progress bar is updated with a failure message.

The final version of the script is below:

```python
from pwn import * 
import sys
import hashlib

if len(sys.argv) != 2:
    print("Invalid arguments")
    print(">> {} <sha256sum>".format(sys.argv[0]))
    exit()

wanted_hash = sys.argv[1]
password_file = "rockyou.txt"
attempts = 0

with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p:
    with open(password_file, "r", encoding='latin-1') as password_list:
        for password in password_list:
            password = password.strip("\n").encode('latin-1')  
            password_hash = hashlib.sha256(password).hexdigest()  
            p.status("[{}] Trying password: {}".format(attempts, password.decode('latin-1')))  

            if password_hash == wanted_hash:
                p.success("Password hash found after {} attempts! '{}' hashes to {}".format(attempts, password.decode('latin-1'), password_hash))
                exit(0)  
            attempts += 1

    p.failure("Password hash not found after {} attempts!".format(attempts))  
```

In the next section, we will test the script to see if it works as expected.

### Testing v1.0

First, let's test if an error message is displayed when the script is run without the correct number of arguments. 

![Screenshot](picture1.png)

Next, we will need to make create a hash to crack. This can be done simply in the command line, the word "python" will be used as an example here:

  ```shell
  echo -ne python | sha256sum
  ```

This will output a hash that can be used as input for the script. The hash will be used as the argument for the script, and the script will attempt to crack it using the `rockyou.txt` wordlist.  

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Be sure to pick a word in the wordlist file to encode.
{: .prompt-warning }
<!-- markdownlint-restore -->

![Screenshot](picture2.png)

The script successfully cracks the hash and displays the password that corresponds to the hash. The script works as expected. In the next section, we will improve the script.

## Improving the Code: Adding Support for more Hashes

This is the updated code:

```python
from pwn import * 
import sys
import hashlib

if len(sys.argv) != 3:
    print("Invalid arguments")
    print("Usage: {} <hash_type> <sha256sum>".format(sys.argv[0]))
    exit()

hash_type = sys.argv[1].lower()  
wanted_hash = sys.argv[2]  
password_file = "rockyou.txt"
attempts = 0

def calculate_hash(password, hash_type):
    hash_object = hashlib.new(hash_type)
    hash_object.update(password.encode('latin-1'))  
    return hash_object.hexdigest()

with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p:
    with open(password_file, "r", encoding='latin-1') as password_list:
        for password in password_list:
            password = password.strip("\n")  
            password_hash = calculate_hash(password, hash_type)  
            p.status("[{}] Trying password: {}".format(attempts, password))  
            
            if password_hash == wanted_hash:
                p.success("Password hash found after {} attempts! '{}' hashes to {}".format(attempts, password, password_hash))
                exit(0)  
            attempts += 1

    p.failure("Password hash not found after {} attempts!".format(attempts))  
```
The updated code that will now accept multiple types of hashes. This is not automatic and must be passed in as input when the script is called.

Changes made:

The program now accepts the hash type as a command-line argument, allowing the user to specify the hash algorithm they want to use, such as SHA-256, MD5, or SHA-1.

A function has been added to calculate the hash based on the selected hash type. It uses `hashlib.new(hash_type)` to create a hash object of the specified algorithm.

### Testing v2.0

Using the earlier command to generate another hash, this time using the MD5 algorithm:

```shell
echo -ne python | md5sum
```

And as the output below shows, the script succesfully cracked the hash using the MD5 algorithm:

![Screenshot](picture3.png)

## Conclusion

In this lab, we have successfully developed a Python[^1] tool capable of cracking various types of hashes by leveraging the `hashlib`[^2] module. While numerous tools exist for hash cracking, this lab showcases the ability to create custom tools using Python. The tool will be available on my [GitHub](https://github.com/Z3R0-sec) for anyone to use safely and responsibly.

### Useful Resources

[^1]: Source: [Python Documentation](https://docs.python.org/3/)
[^2]: Source: [hashlib](https://docs.python.org/3/library/hashlib.html)