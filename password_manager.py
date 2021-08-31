from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from cryptography.fernet import Fernet

import hashlib
import sqlite3
import base64
import os


class Database:
    def __init__(self):
        self.conn = sqlite3.connect("passwords.db")
        self.c = self.conn.cursor()

        self.c.execute(" CREATE TABLE IF NOT EXISTS master (password text) ")
        self.c.execute(
            " CREATE TABLE IF NOT EXISTS passwords (name text, email text, password text)"
        )

        self.c.execute("SELECT * FROM master WHERE rowid='1'")
        password = self.c.fetchone()

        if password is None:
            self.c.execute("INSERT INTO master VALUES ('none')")

        self.conn.commit()

    def get_hashed_password(self):
        self.c.execute("SELECT * FROM master WHERE rowid='1'")
        password = self.c.fetchone()

        if password[0] == "none":
            return None
        else:
            return password[0]

    def set_hashed_password(self, password):
        hashed_password = self.hash(password)
        self.c.execute("UPDATE master SET password=? WHERE rowid=1", (hashed_password,))
        self.conn.commit()

    def add_record(self, name, email, password):
        self.c.execute(
            "INSERT INTO passwords VALUES (?, ?, ?)",
            (
                name,
                email,
                password,
            ),
        )
        self.conn.commit()

    def delete_record(self, name, email):
        self.c.execute(
            "DELETE FROM passwords WHERE name=? AND email=?",
            (
                name,
                email,
            ),
        )
        self.conn.commit()

    def get_records(self):
        self.c.execute("SELECT * FROM passwords")
        return self.c.fetchall()

    def hash(self, password):
        hash_object = hashlib.md5(password.encode())
        return hash_object.hexdigest()


class Record:
    def __init__(self, name, email, password, database):
        self.name = name
        self.email = email
        self.password = password
        self.database = database
        self.added = False

    def add(self):
        self.database.add_record(self.name, self.email, self.password)
        self.added = True

    def delete(self):
        self.database.delete_record(self.name, self.email)
        self.added = False


class Manager:
    def __init__(self):
        self.database = Database()
        self.hashed_password = self.database.get_hashed_password()
        self.f = None
        self.logged_in = False
        self.records = []
        self.load_records()

    def parse_option(self, option, *args, **kwargs):
        if option.lower() == "setup":
            self.setup(args[0], args[1])
        elif option.lower() == "login":
            self.login(args[0])
        elif option.lower() == "logout":
            self.logout()
        elif option.lower() == "add":
            self.add_record(args[0], args[1], args[2])
        elif option.lower() == "delete":
            self.delete_record(args[0], args[1])
        elif option.lower() == "get":
            self.get_record(args[0], args[1])
        elif option.lower() == "aget":
            self.get_records()
        elif option.lower() == "help":
            self.send_info("info", "SETUP - set your master password")
            self.send_info(
                "info", "LOGIN - login to the manager with your master password"
            )
            self.send_info("info", "LOGOUT - logout of the manager")
            self.send_info("info", "ADD - add a record to the database")
            self.send_info("info", "DELETE - delete a record in the database")
            self.send_info("info", "GET - display a specific record from the database")
            self.send_info("info", "AGET - display all records from the database")
        else:
            self.send_info("error", "not a valid option")

    def setup(self, password, password2):
        if not self.database.get_hashed_password():
            if password == password2:
                self.database.set_hashed_password(password)
                self.hashed_password = self.database.get_hashed_password()
            else:
                self.send_info("error", "passwords don't match")
        else:
            # Add an override system
            self.send_info("error", "master password already exists")

    def login(self, password):
        if self.hashed_password:
            if self.hash(password) == self.hashed_password:
                self.logged_in = True
                self.f = Fernet(self.get_key(password))
                self.send_info("success", "logged in")
            else:
                self.send_info("error", "incorrect master password")
        else:
            self.send_info("error", "master password not set")

    def logout(self):
        if self.logged_in:
            self.f = None
            self.logged_in = False
            self.send_info("info", "logging out")
            self.send_info("success", "logged out")
        else:
            self.send_info("warning", "already logged out")

    def add_record(self, name, email, password):
        if self.logged_in:
            for record in self.records:
                if record.name == name and record.email == email:
                    self.send_info("error", "record already exists")
                    return

            record = Record(
                name, email, self.f.encrypt(password.encode()), self.database
            )
            record.add()
            self.records.append(record)
            self.send_info("info", f"adding record: {record.name}, {record.email}")
            self.send_info("success", "record added")
        else:
            self.send_info("error", "not logged in")

    def delete_record(self, name, email):
        if self.logged_in:
            record = self.find_record(name, email)

            if record:
                record.delete()
                self.records.remove(record)
                self.send_info(
                    "info", f"deleting record: {record.name}, {record.email}"
                )
                self.send_info("success", "record deleted")
            else:
                self.send_info("error", "record does not exist")
        else:
            self.send_info("error", "not logged in")

    def get_record(self, name, email):
        if self.logged_in:
            record = self.find_record(name, email)

            if record:
                self.send_info("info", f"record name: {record.name}")
                self.send_info("info", f"record email: {record.email}")
                self.send_info(
                    "info",
                    f"record password: {self.f.decrypt(record.password).decode()}",
                )
                self.send_info("success", "record returned successfully")
            else:
                self.send_info("error", "record does not exist")

        else:
            self.send_info("error", "not logged in")

    def get_records(self):
        if self.logged_in:
            for record in self.records:
                self.send_info(
                    "info",
                    f"{record.name}, {record.email}, {self.f.decrypt(record.password).decode()}",
                )

            self.send_info("success", "returned all records successfully")
        else:
            self.send_info("error", "not logged in")

    def find_record(self, name, email):
        r = None

        for record in self.records:
            if record.name == name and record.email == email:
                if record.added:
                    r = record

        return r

    def load_records(self):
        records = self.database.get_records()

        for record in records:
            r = Record(record[0], record[1], record[2], self.database)
            r.added = True
            self.records.append(r)

    def hash(self, password):
        hash_object = hashlib.md5(password.encode())
        return hash_object.hexdigest()

    def get_key(self, password):
        backend = default_backend()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"salt",
            iterations=100000,
            backend=backend,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        return key

    def send_info(self, type, info):
        print(f"[{type.upper()}] {info.upper()}")
