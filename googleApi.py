"""
File used to make requests to Google APIs
-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
Copyright (c) 2019 Khuzd
"""

import logging
import time
from socket import error
import json
import requests

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Import logger
logger = logging.getLogger('phishGan')

# api obtained on this URL : https://developers.google.com/api-client-library/python/guide/aaa_apikeys
# cse create on this URL : http://www.google.com/cse/
my_api_key_custom_search = open("api_keys/google_api_key_custom_search.txt").read()
my_cse_id_custom_search = open("api_keys/google_cse_id_custom_search.txt").read()

my_api_key_safe_browsing = open("api_keys/google_api_key_safe_browsing.txt").read()


def google_search(search_term):
    """
    Used to check if a research on Google give some results with Google api
    :param search_term: str
    :return: bool
    """
    try:
        try:
            service = build("customsearch", "v1", developerKey=my_api_key_custom_search, cache_discovery=False)
        except error:
            time.sleep(10)
            try:
                service = build("customsearch", "v1", developerKey=my_api_key_custom_search, cache_discovery=False)
            except error:
                time.sleep(30)
                try:
                    service = build("customsearch", "v1", developerKey=my_api_key_custom_search, cache_discovery=False)
                except error:
                    time.sleep(60)
                    service = build("customsearch", "v1", developerKey=my_api_key_custom_search, cache_discovery=False)
        try:
            res = service.cse().list(q=search_term, cx=my_cse_id_custom_search, num=10).execute()
        except HttpError:
            time.sleep(10)
            try:
                res = service.cse().list(q=search_term, cx=my_cse_id_custom_search, num=10).execute()
            except HttpError:
                time.sleep(30)
                try:
                    res = service.cse().list(q=search_term, cx=my_cse_id_custom_search, num=10).execute()
                except:
                    time.sleep(60)
                    res = service.cse().list(q=search_term, cx=my_cse_id_custom_search, num=10).execute()

        return 'items' in res
    except Exception as e:
        logger.critical(e)
        return "error"


def google_safe_browsing_check(url):
    """
    Use to check the google safe browsing api
    :param url: str or list
    :return:
    """

    dest = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + my_api_key_safe_browsing

    URLs = []
    if type(url) is str:
        URLs.append({"url": url})

    else:
        for link in url:
            URLs.append({"url": link})

    i = 0

    answer = {"matches": []}

    while len(URLs) > i * 499:
        data = {
            "client": {
                "clientId": "PhishGan",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["THREAT_TYPE_UNSPECIFIED", "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": URLs[i * 499:(i + 1) * 499]
            }
        }

        data = json.dumps(data)

        req = json.loads(requests.post(url=dest, data=data).text)
        print(req)
        try:
            answer["matches"] = answer["matches"] + req["matches"]
        except KeyError:
            pass

        i += 1
    return answer
