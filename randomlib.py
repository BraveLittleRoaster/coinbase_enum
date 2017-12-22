import random
import sqlite3
import logging
from faker import Faker



class GenerateRandoms:

    @staticmethod
    def generate_fname_lname():

        fake = Faker()
        fake.seed(random.randrange(1, 99999))
        fname = fake.first_name()
        lname = fake.last_name()
        return [fname, lname]

    @staticmethod
    def generate_state():

        fake = Faker()
        fake.seed(random.randrange(1, 99999))
        return fake.state_abbr()

    @staticmethod
    def generate_username():
        # Generates a random username. GoDaddy Requires 5-12 characters, all lowercase.
        uname_len = random.randrange(5, 12)
        char_dict = "abcdefghijklmnopqrstuvwxyz"

        uname = ""

        for i in range(uname_len):
            next_index = random.randrange(len(char_dict))
            uname = uname + char_dict[next_index]

        return uname

    @staticmethod
    def generate_password():
        # GoDaddy has extremely specific password requirements.
        # 8-14 characters, starts with letter, include a lower case letter, include a number, include a special
        # Allowed specials = !@#$%
        # These will ensure that every password generated meets GoDaddy requirements (tested 10k passwords).
        pwd = ""
        pw_length = random.randrange(8, 14)

        alphabet = "!@#$%abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        first_char_dict = "abcdefghijklmnopqrstuvwxyz"
        num_dict = "0123456789"
        random_number = num_dict[random.randrange(0, len(num_dict))]
        special_char_dict = "!@#$%"
        random_special = special_char_dict[random.randrange(0, len(special_char_dict))]

        # Must include a letter on the first char, and must include a lowercase. Might as well meet both.
        first_char = first_char_dict[random.randrange(0,len(first_char_dict))]
        pwd = pwd + first_char
        for i in range(pw_length):
            next_index = random.randrange(len(alphabet))
            pwd = pwd + alphabet[next_index]

        rand_special_index = random.randrange(1, (pw_length - 1))
        rand_number_index = random.randrange(1, (pw_length - 1))
        # Reroll if the index slices match up
        while rand_number_index == rand_special_index:
            rand_number_index = random.randrange(1, (pw_length - 1))
        # MUST contain a special and number, but not on the first character.
        for letter in pwd:
            if letter == pwd[rand_special_index]:
                pwd = pwd.replace(letter, random_special)
            elif letter == pwd[rand_number_index]:
                pwd = pwd.replace(letter, random_number)

        return pwd

    @staticmethod
    def generate_useragent():
        # Generate and return a random valid user agent. Sometimes it throws old shit like Windows95 in there.
        # Old user agents like windows 95 with modern browsers (latest chrome) MIGHT flag traffic as suspicious.
        # If this is a problem, use: from randomagents import GetRandomAgent and run GetRandomAgent()
        fake = Faker()
        fake.seed(random.randrange(1, 99999))
        check = random.randint(0, 100)

        if check <= 50:
            ua = fake.chrome()
        else:
            ua = fake.firefox()

        return ua

    @staticmethod
    def generate_servername():
        server_len = random.randrange(10, 25)
        char_dict = "abcdefghijklmnopqrstuvwxyz0123456789-"

        server = ""

        for i in range(server_len):
            next_index = random.randrange(len(char_dict))
            server = server + char_dict[next_index]

        return server

    @staticmethod
    def generate_hash():
        fake = Faker()
        return fake.md5()

    @staticmethod
    def generate_procname():
        fake = Faker()
        return fake.password(length=random.randrange(10, 18), special_chars=False, digits=True,
                             upper_case=True, lower_case=True)