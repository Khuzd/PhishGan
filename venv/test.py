"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
"""

import sys
import requests
from bs4 import BeautifulSoup as bs

def get_rank(domain_to_query):
    result = {'Global':''}
    url = "http://www.alexa.com/siteinfo/" + domain_to_query
    page = requests.get(url).text
    soup = bs(page)
    for span in soup.find_all('span'):
        if span.has_attr("class"):
            if "globleRank" in span["class"]:
                for strong in span.find_all("strong"):
                    if strong.has_attr("class"):
                        if "metrics-data" in strong["class"]:
                            result['Global'] = strong.text
            # Extracting CountryRank
            if "countryRank" in span["class"]:
                image = span.find_all("img")
                for img in image:
                    if img.has_attr("title"):
                        country = img["title"]
                for strong in span.find_all("strong"):
                    if strong.has_attr("class"):
                        if "metrics-data" in strong["class"]:
                            result[country] = strong.text
    return result

if __name__ == '__main__':
    print (get_rank("google.com"))