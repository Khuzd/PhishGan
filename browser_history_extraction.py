"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""

from logging import getLogger
from os import path, listdir
from platform import system
from sqlite3 import connect, OperationalError

# Import logger
logger = getLogger('main')


def chrome_extraction(date):
    """
    :param date: int
    Extract history of local Google Chrome browser
    :return: list
    """

    # path to user's history database (Chrome)
    if system() == 'Windows':
        data_path = path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data\Default\\"
    elif system() == 'Linux':
        data_path = path.expanduser('~') + r"/.config/google-chrome/Default/"
    elif system() == 'Darwin':
        data_path = path.expanduser('~') + r"/Library/Caches/Google/Chrome/Default/"
    else:
        logger.critical("Unrecognised operating system")
        return

    history_db = path.join(data_path, 'history')

    logger.debug(history_db)

    # ---------------------
    #  Load history
    # ---------------------
    if path.isfile(history_db):
        # connection
        c = connect(history_db)
        cursor = c.cursor()
        try:
            select_statement = "SELECT urls.url, urls.last_visit_time FROM urls;"
            cursor.execute(select_statement)
        except OperationalError:
            print("[!] The database is locked! Please exit Chrome and run the script again.")
            logger.warning("[!] The database is locked! Please exit Chrome and run the script again.")
            return []

        results = cursor.fetchall()  # tuple

        URLs = []
        for url, time in results:
            if time > date and "http" in url:
                URLs.append(url)

        return URLs

    else:
        print("Chrome is not installed")
        logger.info("Chrome is not installed")
        return []


def firefox_extraction(date):
    """
        Extract history of local Firefox browser
        :param date: int
        :return: list
        """

    # path to user's history database (Firefox)
    if system() == 'Windows':
        data_path = path.expanduser('~') + r"\AppData\Roaming\Mozilla\Firefox\Profiles\\"

    elif system() == 'Linux':
        data_path = path.expanduser('~') + r"/.mozilla/firefox"
    elif system() == 'Darwin':
        data_path = path.expanduser('~') + r"/Library/Application Support/Firefox/Profiles/"

    else:
        logger.critical("Unrecognised operating system")
        return

    files = listdir(data_path)
    history_db = path.join(data_path + files[0], 'places.sqlite')

    # ---------------------
    #  Load history
    # ---------------------
    if path.isfile(history_db):
        c = connect(history_db)
        cursor = c.cursor()

        try:
            select_statement = "select moz_places.url,moz_places.last_visit_date from moz_places;"
            cursor.execute(select_statement)

        except OperationalError:
            print("[!] The database is locked! Please exit Firefox and run the script again.")
            logger.warning("[!] The database is locked! Please exit Chrome and run the script again.")
            return []

        results = cursor.fetchall()

        URLs = []
        for url, last in results:
            if last is not None and last > date and "http" in url:
                URLs.append(url)

        return URLs
    else:
        print("Firefox is not installed")
        logger.info("Firefox is not installed")
        return []


def opera_extraction(date):
    """
    Extract history of local opera browser
    :param date: int
    :return: list
    """

    # path to user's history database (Opera)
    if system() == 'Windows':
        data_path = path.expanduser('~') + r"\AppData\Roaming\Opera Software\Opera Stable\\"

    elif system() == 'Linux':
        data_path = path.expanduser('~') + r"/.opera/"

    elif system() == 'Darwin':
        data_path = path.expanduser('~') + r"/Library/Opera/"

    else:
        logger.critical("Unrecognised operating system")
        return

    history_db = path.join(data_path, 'History')

    # ---------------------
    #  Load history
    # ---------------------
    if path.isfile(history_db):
        c = connect(history_db)
        cursor = c.cursor()

        try:
            select_statement = "select urls.url,urls.last_visit_time from urls;"
            cursor.execute(select_statement)

        except OperationalError:
            print("[!] The database is locked! Please exit Opera and run the script again.")
            logger.warning("[!] The database is locked! Please exit Chrome and run the script again.")
            return []

        results = cursor.fetchall()

        URLs = []
        for url, last in results:
            if last is not None and last > date and "http" in url:
                URLs.append(url)

        return URLs
    else:
        print("Opera is not installed")
        logger.info("Opera is not installed")
        return []
