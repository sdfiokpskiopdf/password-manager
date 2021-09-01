from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from cryptography.fernet import Fernet

import hashlib
import sqlite3
import base64
import sys
import os
import re


class Error(Exception):
    """
    Base email class for exceptions
    """

    pass


class EmailError(Error):
    """
    Exception raised for invalid email address

    Attributes:
        expression -- input expression in which the error occured
        message -- explanation of the error
    """

    def __init__(self, expression, message):
        self.expression = expression
        self.message = message


class Database:
    """
    Class controlling the database that stores the records
    """

    def __init__(self):
        """
        Initialize database
        """
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
        """
        function that querys the database for the master password

        :return: the hash of the master password if it exists, otherwise returns None
        """
        self.c.execute("SELECT * FROM master WHERE rowid='1'")
        password = self.c.fetchone()

        if password[0] == "none":
            return None
        else:
            return password[0]

    def set_hashed_password(self, password):
        """
        function that updates the database with the master password

        :param password: the plain text password to be stored in the database
        :return: the hashed password that has been stored in the database
        """
        hashed_password = Manager.hash(password)
        self.c.execute("UPDATE master SET password=? WHERE rowid=1", (hashed_password,))
        self.conn.commit()

        return hashed_password

    def add_record(self, name, email, password):
        """
        function that inserts a new record into the database

        :param name: the name of the record
        :param email: the email of the record
        :param password: the encrypted password of the record
        :return: None
        """
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
        """
        function that deletes a record from the database

        :param name: the name of the record to be deleted
        :param email: the email of the record to be deleted
        :return: None
        """
        self.c.execute(
            "DELETE FROM passwords WHERE name=? AND email=?",
            (
                name,
                email,
            ),
        )
        self.conn.commit()

    def get_records(self):
        """
        function that querys the database for all records
        :return: list of tuples of records
        """
        self.c.execute("SELECT * FROM passwords")
        return self.c.fetchall()


class Record:
    """
    Class storing and controlling record information

    Atrributes:
        name -- name of the record
        email -- email of the record
        password -- encrypted password of the record
        database -- connection to the database
    """

    def __init__(self, name, email, password, database):
        self.name = name
        self._email = email
        self.password = password
        self.database = database
        self.added = False

    def add(self):
        """
        function that adds the record to the database and records that it has been added

        :return: None
        """
        self.database.add_record(self.name, self._email, self.password)
        self.added = True

    def delete(self):
        """
        function that deletes the record from the database and records that it has been deleted

        :return: None
        """
        self.database.delete_record(self.name, self._email)
        self.added = False

    @property
    def email(self):
        """
        getter for the email property

        :return: email
        """
        return self._email

    @email.setter
    def email(self, email):
        """
        setter for the email property
        checks if the email is a valid email

        :param email: the email to be set
        :return: None
        """

        regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

        if not re.fullmatch(regex, email):
            raise EmailError(
                "if re.fullmatch(regex, email):",
                "supplied email is not a valid email address",
            )

        self._email = email


class Manager:
    """
    Class controlling and storing information about the download manager
    """

    def __init__(self):
        self.database = Database()
        self.hashed_password = self.database.get_hashed_password()
        self.f = None
        self.logged_in = False
        self.records = []
        self.load_records()

    def parse_option(self, option, *args, **kwargs):
        """
        Determine which function to run via the option provided

        :return: None
        """
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
        elif option.lower() == "exit":
            self.exit()
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
        """
        fucnction to set a master pasword

        :param password: password to set
        :param password2: confiirmation password
        :return: None
        """
        if not self.database.get_hashed_password():
            if password == password2:
                self.hashed_password = self.database.set_hashed_password(password)
            else:
                self.send_info("error", "passwords don't match")
        else:
            # Add an override system
            self.send_info("error", "master password already exists")

    def login(self, password):
        """
        function to login to pasword manager

        :param password: master password
        :return: None
        """
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
        """
        function to logout of pasword manager

        :return: None
        """
        if self.logged_in:
            self.f = None
            self.logged_in = False
            self.send_info("info", "logging out")
            self.send_info("success", "logged out")
        else:
            self.send_info("warning", "already logged out")

    def add_record(self, name, email, password):
        """
        function to add a record to the password manager

        :param name: name of the record
        :param email: email of the record
        :param password: password of the record
        :return: None
        """
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
        """
        function to delete record

        :param name: name of record
        :param email: email of record
        :return: None
        """
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
        """
        function to get record

        :param name: name of record
        :param email: email of record
        :return: None
        """
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
        """
        function to get all records

        :return: None
        """
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
        """
        function to load all records from the database

        :return: None
        """
        records = self.database.get_records()

        for record in records:
            r = Record(record[0], record[1], record[2], self.database)
            r.added = True
            self.records.append(r)

    def exit(self):
        """
        function to exit the download manager

        :return: None
        """
        self.logout()
        sys.exit()

    @staticmethod
    def hash(password):
        """
        function to hash a password with the MD5 hash algorithm

        :param password: plain text password to hash
        :return: hashed password
        """
        hash_object = hashlib.md5(password.encode())
        return hash_object.hexdigest()

    @staticmethod
    def get_key(password):
        """
        function to derive a unique encryption key from the users plain text password

        :param password: plain text password to derive from
        :return: unique encryption key
        """
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"salt",
            iterations=100000,
            backend=backend,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        return key

    @staticmethod
    def send_info(type, info):
        """
        function print out formatted information

        :param type: type of information (warning, error, info, success)
        :return: None
        """
        print(f"[{type.upper()}] {info.upper()}")
