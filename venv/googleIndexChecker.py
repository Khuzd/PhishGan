"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""

from googleapiclient.discovery import build
import pprint

# api obtained on this URL : https://developers.google.com/api-client-library/python/guide/aaa_apikeys
# cse create on this URL : http://www.google.com/cse/
my_api_key = "AIzaSyCo3NlIoPHGg41cVlmMvAwmW7H-TFUFbzE"
my_cse_id = "014847826172846365912:woel7dy4mym"


def google_search(search_term):
    service = build("customsearch", "v1", developerKey=my_api_key)
    res = service.cse().list(q=search_term, cx=my_cse_id, num=10).execute()

    return 'items' in res
