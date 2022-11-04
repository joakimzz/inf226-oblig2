import time
import hashlib
import apsw
import sys
import bcrypt

try:
    connection = apsw.Connection(".tiny.db")
    c = connection.cursor()
except apsw.Error as error:
    print(error)
    sys.exit(1)

def hashing(pw):
    salt = bcrypt.gensalt()
    hash = hashlib.sha256(salt + pw.encode())
    return hash.hexdigest(), salt

def check_pw(pw, hashed_pw, salt):
    return hashlib.sha256(salt + pw.encode()).hexdigest() == hashed_pw


def main():
    try:
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
            message_id integer PRIMARY KEY, 
            username VARCHAR(24) NOT NULL,
            receiver VARCHAR(24) NOT NULL,
            message TEXT NOT NULL,
            time TIME NOT NULL
            );''')

        c.execute('''CREATE TABLE IF NOT EXISTS announcements (
            id integer PRIMARY KEY, 
            author TEXT NOT NULL,
            text TEXT NOT NULL);''')

        c.execute('''CREATE TABLE IF NOT EXISTS users(
            username VARCHAR(24) PRIMARY KEY,
            password CHAR(64) NOT NULL,
            salt VARCHAR(30) NOT NULL
            );''')

    except apsw.Error as error:
        print(error)
        sys.exit(1)

if __name__ == '__main__':
    main()