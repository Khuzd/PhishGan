"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""

import os
import sqlite3
import platform


def chromeExtraction(date):
    """
    :param date: int
    Extract history of local Google Chrome browser
    :return: list
    """

    # path to user's history database (Chrome)
    if platform.system()=='Windows':
        data_path = os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data\Default"
    else :
        data_path = os.path.expanduser('~') + r"/.config/google-chrome/Default"


    history_db = os.path.join(data_path, 'history')

    if os.path.isfile(history_db):
        # connection
        c = sqlite3.connect(history_db)
        cursor = c.cursor()
        try:
            select_statement = "SELECT urls.url, urls.last_visit_time FROM urls;"
            cursor.execute(select_statement)
        except sqlite3.OperationalError:
            print("[!] The database is locked! Please exit Chrome and run the script again.")
            return []

        results = cursor.fetchall()  # tuple

        URLs = []
        for url, time in results:
            if time > date:
                URLs.append(url)

        return URLs

    else :
        print("Chrome is not installed")
        return []

def firefoxExtraction(date):
    """
        Extract history of local Firefox browser
        :param date: int
        :return: list
        """

    # path to user's history database (Firefox)
    if platform.system() == 'Windows':
        data_path = os.path.expanduser('~') + r"\AppData\Roaming\Mozilla\Firefox\Profiles"

    else :
        data_path = os.path.expanduser('~') + r"/.mozilla/firefox"

    files = os.listdir(data_path)
    history_db = os.path.join(data_path +"\\" + files[0] , 'places.sqlite')


    if os.path.isfile(history_db):
        c = sqlite3.connect(history_db)
        cursor = c.cursor()

        try:
            select_statement = "select moz_places.url,moz_places.last_visit_date from moz_places;"
            cursor.execute(select_statement)

        except sqlite3.OperationalError:
            print("[!] The database is locked! Please exit Firefox and run the script again.")
            return []

        results = cursor.fetchall()

        URLs = []
        for url,last in results:
            if last is not None and last>date:
                URLs.append(url)

        return URLs
    else :
        print("Firefox is not installed")
        return []