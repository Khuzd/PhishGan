"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
"""



# Google says don't use this script: https://twitter.com/methode/status/783733724655517696
# This script is a violation of Google Terms of Service. Don't use it.



import requests
import csv
import os
import time
from bs4 import BeautifulSoup
from urllib.parse import urlencode

seconds = input('Enter number of seconds to wait between URL checks: ')
output = os.path.join(os.path.dirname(__file__), input('Enter a filename (minus file extension): ')+'.csv')
# urlinput = os.path.join(os.path.dirname(__file__), input('Enter input text file: '))
urls = ["amazon.fr"]

proxies = {
    'https' : 'https://localhost:8123',
    'http' : 'http://localhost:8123'
    }

user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
headers = { 'User-Agent' : user_agent}

f = csv.writer(open(output, "w+", newline="\n", encoding="utf-8"))
f.writerow(["URL", "Indexed"])

for line in urls:
    query = {'q': 'site:' + line}
    google = "https://www.google.com/search?" + urlencode(query)
    print(google)
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        check = soup.find(id="rso").find("div").find("div").find("h3").find("a")
        print (check)
        href = check['href']
        f.writerow([line,"True"])
        print(line + " is indexed!")
    except AttributeError:
        f.writerow([line,"False"])
        print(line + " is NOT indexed!")
    print("Waiting " + str(seconds) + " seconds until checking next URL.\n")
    time.sleep(float(seconds))