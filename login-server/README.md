# **Part 2B**

## *Improvements I have done (an overview of my design):*

- Made a logout-button, aswell as it's logout-functionality

- Made a more secure secretkey. I used the command: 

`python -c 'import secrets; print(secrets.token_hex())'`

- Moved users and messages to separate SQL-tables. 

- Provided some security against SQL-injection

- Made a place where you can register a users.

- Made the "Show All" button work

- Passwords are being hashed and salts are added.

- The users written in plaintext in app.py can not be used to login



## *Features of my application:*

- Users can not send messages to users that not exist

- Minimum length of passwords is 8 letters, improving security


## *Instructions:*

Just run Flask go to LocalHost at your browser!

(You may need to check if you have downloaded all the imported packages)

## *Security concerns I have found:*

- The application does not use Flask correctly: The code does not follow the method for implementation, as the Flask-homepage recommends. This leads to bad code-structure and security flaws.

- The application does not show the sender then a message is sent. This ruins the integrity of the application.

- You do not need a password to log in. This is bad, and also ruins the integrity.

- The secret key is too short.

- The messages that is being sent is not encrypted, ruins confidentiality. Opens for MitM-attacks

- The application is vulnerable to DOS (and DDOS) attacks. This could be done by either taking down the application itself, or by deleting the DB. Ruins availability.

- The content of the DB containing all sent messages is not encrypted, ruining confidentiality.

- Having usernames with corresponding passwords in the source-code is a big **NO-NO**. Usernames, **hashed** passwords and salts should be stored in a separate DB.

- The excisting DB is vulnerable to SQL-injection. This could be fixed by implementing a stronger DB, ex. with prepared statements or stored procedures.

- The application has unused Python-files. This could lead to an exploit of a backdoor, which could lead to a breach of the application. Also, having unused files in a application is unnecessary.

- The application is also vulnerable to XSS. This can be done sending a message that looks something like: 

`<span *malicious code*> *some message* </span>`

- CSRF can be used in the application. 


## Answering the questions related to the task:

- ### Anyone with access could try to attack this application (any hat really). I would assume an attacker would do one of two things:

    - Take the application down (DOS-attacks, SQL-injection, XSS)

    - Stay hidden and act as a "spy" (MitM-attack, message-altering, spoofing)



- ### Types of damage that could be done:

    - Confidentiality:

        - Altering messages after they are sent, and before they are stored in the DB

        - Messages are not encrypted

    - Integrity:

        - Login as another person

        - Changing the content of any of the DB's (using SQL-injection)

    - Availability:

        - Taking down any or all of the DB's (DOS- or DDOS-attacks)

        - Changing the hashes of the passwords or salts (SQL-injection)

        - Deleting tables (SQL-injection)

- ### Limits:

    - The more of the vulnerabilities that are getting fixed, the more difficult it would be to find one and to exploit it.


- ### Limits beyond our reach:

    - If the entire Internet goes down, availability sinks like Titanic

    - If there are bugs in the modules/packages we are using (like Flask), attackers with that knowledge may use it to do malicious actions.
        - However, it is our responsibility up keep the modules/packages up to date.

    - If people have bad routines on storing their passwords etc. (like writing the passwords down in a physical notebook)

    - General *social engineering*


- ### Main attack vector:

    - The main attack vector would have to be wherever you can write anything, like:
        - The username/password (both for login and registration) fields
        - The message field
        - The search field

- ### What I have done to protect against attacks:

    - Passwords are hashed, meaning the plaintext-passwords can not be exploited, BUT the hashed-passwords still can be exploited. 

    - Password-length requirement (somewhat) delays brute-force attacks

    - Login-requirements

    - Checking if users actually exict

    - Prepared SQL-statements

- ### Access Control Model

    - My solution does not have an Access Control Model, but I i were to implement one, I would use RBAC

- ### Is the security good enough?

    - We can never know. You can only be aware of the vulnerabilities if someone finds one. This could both be a white-hat or a black-hat.

    - "The application is secure until it isn't"