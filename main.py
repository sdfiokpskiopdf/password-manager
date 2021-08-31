class Database:
    def __init__(self):
        pass

    def get_hashed_password(self):
        pass


class Record:
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password
        self.added = False

    def add(self):
        self.added = True

    def delete(self):
        self.added = False


class Manager:
    def __init__(self):
        self.database = Database()
        self.hashed_password = self.database.hashed_password()
        self.logged_in = False
        self.records = []

    def parse_option(self, option, *args, **kwargs):
        # Parse option
        pass

    def login(self, password):
        if self.hash(password) == self.hashed_password:
            self.logged_in = True
            self.send_info("success", "logged in")
        else:
            self.send_info("error", "incorrect master password")

    def logout(self):
        if self.logged_in:
            self.logged_in = False
        else:
            self.send_info("warning", "already logged out")

    def add_record(self, name, email, password):
        if self.logged_in:
            for record in self.records:
                if record.name == name and record.email == email:
                    self.send_info("error", "record already exists")
                    return None

            record = Record(name, email, password)
            record.add()
            self.records.append(record)
            self.send_info("info", f"adding record: {record.name}, {record.email}")
            self.send_info("success", "record added")
        else:
            self.send_info("error", "not logged in")

    def delete_record(self, name=None, email=None):
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

    def get_record(self, name=None, email=None):
        if self.logged_in:
            record = self.find_record(name, email)

            if record:
                self.send_info("info", f"record name: {record.name}")
                self.send_info("info", f"record email: {record.email}")
                self.send_info("info", f"record password: {record.password}")
                self.send_info("success", "record returned successfully")
            else:
                self.send_info("error", "record does not exist")

        else:
            self.send_info("error", "not logged in")

    def find_record(self, name=None, email=None):
        r = None

        for record in self.records:
            if record.name == name or record.email == email:
                if record.added:
                    r = record

        return r

    def hash(password):
        # Run hashing algo
        pass

    def send_info(type, info):
        print(f"[{type.upper()}] {info.upper()}")
