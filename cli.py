import password_manager

manager = password_manager.Manager()

while True:
    option = input("What would you like to do? type HELP for commands: ")

    if option.lower() == "setup":
        password1 = input("What would you like the master password to be: ")
        password2 = input("Confirm password: ")

        manager.parse_option(option, password1, password2)
    elif option.lower() == "login":
        password = input("What is the master password: ")

        manager.parse_option(option, password)
    elif option.lower() == "add":
        name = input("Name of record: ")
        email = input("Email of record: ")
        password = input("Password of record: ")

        manager.parse_option(option, name, email, password)
    elif option.lower() == "delete":
        name = input("Name of record: ")
        email = input("Email of record: ")

        manager.parse_option(option, name, email)
    elif option.lower() == "get":
        name = input("Name of record: ")
        email = input("Email of record: ")

        manager.parse_option(option, name, email)
    else:
        manager.parse_option(option)

    print("----------------------------------------")
