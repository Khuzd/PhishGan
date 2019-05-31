"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""

import json

"""
    dictionnary form for PhishTank
    {
    'phish_id': 'int'
    'url': 'string' -> url of the phishing site
    'phish_detail_url': 'string' -> details of the phising site
    'submission_time': 'date : yyyy-mm-dd-hh-mm-ss+hh:ss' -> date of the submission to phisTank
    'verified': 'bool' -> if the site has been verified by phisTank
    'verification_time': 'date : yyyy-mm-dd-hh-mm-ss+hh:ss' -> date of the verification by phisTank
    'online': 'bool' -> online or not
    'details': [
        {
        'ip_address': 'string' -> ip of the phishing site
        'cidr_block': 'string' -> Classless Inter-Domain Routing 
        'announcing_network': 'int'
        'rir': 'string' -> Regional Internet Registry
        'country': 'string' -> abbreviation of the country of the site
        'detail_time': 'date : yyyy-mm-dd-hh-mm-ss+hh:ss'}]
    'target': 'string' -> name of the original site wich is the target of the phishing site
    }
"""

def listFeatures(path):
    """

    :param path: path to the phishtank json file
    :return: list of all sites with all of theese features
    """
    phishTankDict = jsonToDict(path)
    phishTankSitesFeatures = []

    for site in phishTankDict:
        phishTankSitesFeatures.append(extractFeatures(site))

    return phishTankSitesFeatures

def jsonToDict(path):
    """
    Transform a json file into a python dictonnary
    :param path: string represents the path to the data stored in json format
    :return: dictonnary
    """

    with open(path) as json_data:
        data_dict = json.load(json_data)
    return data_dict

def extractFeatures(site):
    """

    :param site: dictionnary contains all information about site
    :return: List [domain,tld,brandname,editDbrandName,digitCount,lenght,isKnownTld,www,keywords,punnycode,randomDomain]
    """
    features = []

    knownTld = ["com","net","fr","uk","us","de","it","es","gouv","gov"]

    try:
        domain = site["url"].split('//')[1].split('/')[0]
        tld=""
        if (not domain.split('.')[-1].isdigit()):
            tld = domain.split('.')[-1]
            domain = domain[:len(domain)-(len(tld)+1)]

        features.append(domain)
        features.append(tld)

    except:
       print("problem with parsing: " + site["url"])

    brandname = '0'
    features.append(brandname)

    editDbrandName = 0
    features.append(editDbrandName)

    digitCount = sum(c.isdigit() for c in site["url"])
    features.append(digitCount)

    features.append(len(site["url"]))

    if (tld in knownTld):
        features.append(1)
    else:
        features.append(0)

    www = 0
    features.append(www)

    keywords = 0
    features.append(keywords)

    punnyCode = 0
    if "--xn" in site["url"]:
        punnyCode = 1
    features.append(punnyCode)

    randomDomain = 0
    features.append(randomDomain)

    return features
