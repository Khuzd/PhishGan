"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""

import logging
import time
from socket import error

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Import logger
logger = logging.getLogger('main')

# api obtained on this URL : https://developers.google.com/api-client-library/python/guide/aaa_apikeys
# cse create on this URL : http://www.google.com/cse/
my_api_key = open("api_keys/google_api_key.txt").read()
my_cse_id = open("api_keys/google_cse_id.txt").read()


def google_search(search_term):
    """
    Used to check if a research on Google give some results with Google api
    :param search_term: str
    :return: bool
    """
    try:
        try:
            service = build("customsearch", "v1", developerKey=my_api_key, cache_discovery=False)
        except error:
            time.sleep(10)
            try:
                service = build("customsearch", "v1", developerKey=my_api_key, cache_discovery=False)
            except error:
                time.sleep(300)
                try:
                    service = build("customsearch", "v1", developerKey=my_api_key, cache_discovery=False)
                except error:
                    time.sleep(60)

        try:
            res = service.cse().list(q=search_term, cx=my_cse_id, num=10).execute()
        except HttpError:
            time.sleep(10)
            try:
                res = service.cse().list(q=search_term, cx=my_cse_id, num=10).execute()
            except HttpError:
                time.sleep(30)
                try:
                    res = service.cse().list(q=search_term, cx=my_cse_id, num=10).execute()
                except:
                    time.sleep(60)
                    res = service.cse().list(q=search_term, cx=my_cse_id, num=10).execute()

        return 'items' in res
    except Exception as e:
        logger.critical(e)
        return "error"
