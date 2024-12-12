---
title: "Learning Python: Exploiting Restricted SQL Injection"
description: Re-configuring the previous Python program to exploit a restricted SQL injection vulnerability
date: 2024-12-10 00:00:00 +0000
categories: [Learning Topics, Python]
tags: [Python, tools, sql, lab, pentest, hash, web, flask]
pin: true
math: true
mermaid: true
comments: true
media_subpath: /images/PythonRestrictedSQL
img_path: /images/PythonRestrictedSQL
image:
  path: thumbnail.jpeg
---

Refer to my prevoius post, [Learning Python: SQL Injection](https://z3r0-sec.github.io/posts/PythonSQLinject/), to learn about the test environment and the initial version of the Python tool. It shows how to set up the vulnerable app to test the script on. This post will focus on reconfiguring the tool to exploit restricted SQL injection vulnerabilities.

<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Rework the existing Python tool to exploit restricted SQL injection vulnerabilities.
{: .prompt-info }
<!-- markdownlint-restore -->
<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
> Objectives: Do not use this tool on any web page without permission. 
{: .prompt-danger }
<!-- markdownlint-restore -->

## Introduction

In the previous lab, I went over what SQL Injection was, how it works, and how to exploit it. I also concluded with suggestions on mitigating this risk in order to protect your web applications. The app we used was a simple `Flask` app with a `SQLite` database, and intentionally vulnerable. Below is the table of users in the database:

| ID | Username | Password Hash                                  |
| --- | -------- | --------------------------------------------- |
| 1   | admin    | 0192023a7bbd73250516f069df18b500              |
| 2   | user1    | 482c811da5d5b4bc6d497ffa98491e38              |
| 3   | user2    | 4ca7c5c27c2314eecc71f67501abb724              |

The attack we used was called a blind SQL injection attack, or boolean-based, which is a type of SQL injection attack that asks the database true or false questions and determines the answer based on the application's response. This was used to extract the password hash character by character. Refer to the following output of the previous tool, showing the number of queries required to identify the hash length and extract the password hash:

![Screenshot](picture1.png){: width="872" height="300"}

The tool shows the exact number of queries, and can vary depending on the size of the hash and individual characters.

While this worked, most applications have security measures in place to prevent this type of attack, such as limiting the number of queries that can be made. 

### Defenses put in Place

When an application implements security measures, such as limiting the number of queries, it can significantly hamper automated tools like SQLmap. If an application limits the number of queries, it becomes crucial to optimize the exploitation strategy. For example, if the application limits queries to 128 and each character of a 32-character hash has 16 possible values, you can only make 4 queries per character before exceeding the limit.

### Why Not Use SQLmap?

While SQLmap is a powerful and widely-used tool for automating SQL injection detection and exploitation, it may not always be the best choice. Custom scripts offer greater flexibility and tailored solutions, allowing for the adaptation to specific application behaviors and constraints that automated tools like SQLmap might miss. In a scenario where queries are limited, SQL might again struggle to obtain results. Additionally, SQLmap can be resource-intensive, making custom scripts a more performance-efficient option. Furthermore, writing your own script provides valuable insights into the mechanics of SQL injection, or any exploit you are working on, enhancing both offensive and defensive security practices.

### Binary Search Strategy

The concept that will be used to enchance our program to work when queries are limited is called a binary search. This is a search algorithm that finds the position of a target value within a sorted array. It compares the target value to the middle element of the array and continues narrowing down the search range until the target value is found. This approach is efficient and can be adapted to extract data character by character in a limited-query environment.

A loop will be used to iterate through each character of the hash, and for each character, a binary search will be performed to determine the correct value. This process will be repeated until the entire hash is extracted. This strategy minimizes the number of queries required to extract the hash, making it suitable for restricted SQL injection scenarios.

## Example: Application with API

Imagine you're exploiting a time-based blind SQL injection vulnerability via an API, and you're tasked with extracting the hash of a user's password. The hash is stored in a database and is a long alphanumeric string (for example, an MD5 or SHA256 hash). However, you're constrained to only 128 queries for each hash extraction.

Using binary search, you can significantly reduce the number of queries by narrowing down the possibilities for each character of the hash.

**Step-by-Step Application:**
1. ***Determine the Range:*** Assume the hash is composed of hexadecimal characters (0-9, a-f). For each character in the hash, there are 16 possible values. You can treat these possibilities as a range from '0' to 'f' (0–15 in decimal).

2. ***Make the First Query:*** To find the first character of the hash, you start by testing the middle value of the range ('8' in the case of hexadecimal). You inject a time-based SQL query that checks if the first character of the hash is greater than or equal to '8'. If the response is delayed (due to the SLEEP function), this means the first character is greater than or equal to '8'. If there's no delay, the first character is smaller than '8': 
```sql
SELECT IF(SUBSTRING(hash_column, 1, 1) >= '8', SLEEP(5), 0);
```

3. ***Narrow the Range:*** Depending on the response, you halve the range. If the first character is greater than or equal to '8', you now test values between '8' and 'f'. If it’s smaller, you test between '0' and '7'.

4. ***Repeat for Each Character:*** After finding the first character, you apply the same strategy for each subsequent character in the hash. Each time, you reduce the range of possible characters, narrowing it down with each query.

5. ***Completion:*** After 4 queries for each of the 32 characters (using binary search), you'll have the full hash with only 128 queries—significantly fewer than if you were brute-forcing each character one by one.

By applying binary search, you effectively decrease the query count from 256 (if testing each character sequentially) to just 128, taking advantage of the limited-query environment to quickly extract the hash. This approach showcases the power of binary search in optimizing SQL injection techniques, allowing attackers to bypass query limitations while extracting sensitive data from a database in a fraction of the time.

Below are examples of binary search put into a table to better understand the concept:

| Query# | Alphabet         | Question | Result |       
| ------ | ---------------- | -------- | ------ |
| 1      | 0123456789abcdef | \>7?     | False  |
| 2      | 01234567         | \>3?     | True   |
| 3      | 34567            | \>5?     | True   |
| 4      | 567              | \>6?     | False  |

| Query# | Alphabet         | Question | Result |
| ------ | ---------------- | -------- | ------ |
| 1      | 0123456789abcdef | \>7?     | True   |
| 2      | 789abcdef        | \>b?     | False  |
| 3      | 789ab            | \>9?     | True   |
| 4      | 9ab              | \>a?     | True   |

## Adding Binary Search to the Tool

The following section will highlight the new function that will be added to the tool to perform binary searches. Here is the new function:

```python
def extract_hash_bst(charset, user_id, password_length):
    found = ""
    for index in range(0, password_length):
        start = 0
        end = len(charset) -1
        while start <= end:
            if end - start == 1:
                if start == 0 and boolean_query(index, user_id, charset[start]):
                    found += charset[start]
                else:
                    found += charset[start + 1]
                break
            else:
                middle = (start + end) // 2
                if boolean_query(index, user_id, charset[middle]):
                    end = middle
                else:
                    start = middle
    return found
```

The function `extract_hash_bst` takes three arguments: `charset`, `user_id`, and `password_length`. The `charset` is the set of characters to search for, `user_id` is the target user ID, and `password_length` is the length of the password hash. The function iterates through each character of the hash and performs a binary search to determine the correct value. The `boolean_query` function is used to send SQL queries and evaluate the application's response.

The function `extract_hash_bst` improves the efficiency of extracting a password hash by using a binary search tree (BST) approach instead of a linear search. 

## Testing the Binary Search Function

Adding this onto our script, we can now run it with the following command:

```shell
python3 restricted_sql_injection.py -t http://127.0.0.1:5000/login
```

![Screenshot](picture2.png){: width="872" height="300"}

In addition to the expected output from the previous version of the tool, the new version now outputs the hash again, but this time the number of queries is reduced to 128 for every hash, effectively halfing the amount required. This is a significant improvement in efficiency and demonstrates the effectiveness of the binary search strategy in a limited-query environment.

## What's the Use?

Binary search can be an efficient technique for reducing the number of queries needed to extract data from a database. If you're exploiting an SQL injection vulnerability through an API, and there are constraints on the number of queries you can make, binary search helps in quickly narrowing down possible values without brute-forcing all options.

Looking at the bigger picture, every application or system has its own unique security measures and constraints. Whether it's some form of input validation, rate limiting, or query restrictions, attackers need to adapt their strategies to bypass these defenses. Using popular tools like SQLmap is great, but understanding the underlying principles and developing custom scripts tailored to specific scenarios can provide a deeper understanding of the attack surface and enhance both your offensive and defensive security skills.


## Conclusion

In this lab, I reconfigured the Python tool developed in the previous post by adding a binary search function to optimize the extraction of password hashes in a limited-query environment. By applying binary search, the tool significantly reduced the number of queries required to extract the hash, showcasing the efficiency and adaptability of custom scripts. This is the last of the Python projects for now as I move on to more Blue Team focused projects. The next language I will cover will be Rust. I hope you enjoyed this series and learned something new about Python! 

### Closing Thoughts

Being able to tailor your tools and techniques to the specific constraints of a target system is a valuable skill in the world of cybersecurity, and reading code is the first step. If not to learn how to program, learning coding languages can improve your understanding of how attacks work and how to defend against them.

I first went to college to study computer science in hopes of becoming a programmer without fully knowing what I was getting myself into. I didn't enjoy it as much as I wanted to and I found myself stumbling around the IT field until I found cybersecurity. I found that I enjoyed the hands-on aspect of it and the constant learning that comes with it. I've been able to apply my programming knowledge to my cybersecurity journey and it has helped me understand the tools and techniques used in the field. Getting back into programming has been a great experience for me, and I hope to continue learning and improving my skills. I utilized TCM Security's Python 101 for Hackers course to refresh my Python skills and learn how to apply them to cybersecurity. I highly recommend this course to anyone looking to learn Python for cybersecurity purposes. You won't develop the skills to become a programmer, but you will learn enough to get your journey started. I encourage anyone interested in cybersecurity to learn programming, as it can be a valuable asset in your career.

