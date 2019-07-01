"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""

from googleapiclient.discovery import build

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
    service = build("customsearch", "v1", developerKey=my_api_key)
    res = service.cse().list(q=search_term, cx=my_cse_id, num=10).execute()

    return 'items' in res
