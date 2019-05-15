"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
"""

import re
import whois
import datetime
import requests
from bs4 import BeautifulSoup
import socket
import subprocess
import sys
# from m2ext import SSL
# from M2Crypto import X509

URL_SHORTENER = ["shrinkee.com","goo.gl","7.ly","adf.ly","admy.link","al.ly","bc.vc","bit.do","doiop.com","ity.im","url.ie","is.gd","linkmoji.co","sh.dz24.info","lynk.my","mcaf.ee","yep.it","ow.ly","x61.ch","qr.net","shrinkee.com","u.to","ho.io","thinfi.com","tiny.cc","tinyurl.com","tny.im","flic.krp","v.gd","y2u.be","cutt.us","zzb.bz","adfoc.us","bit.ly","cur.lv","git.io","hec.su","viid.me","tldrify.com","tr.im"]
CCTLD =[".ac",".ad",".ae",".af",".ag",".ai",".al",".am",".an",".ao",".aq",".ar",".as",".at",".au",".aw",".ax",".az",".ba",".bb",".bd",".be",".bf",".bg",".bh",".bi",".bj",".bl",".bm",".bn",".bo",".bq",".br",".brussels",".bs",".bt",".bu",".bv",".bw",".by",".bz",".bzh",".ca",".cat",".cc",".cd",".cf",".cg",".ch",".ci",".ck",".cl",".cm",".cn",".co",".corsica",".cr",".cs ",".cu",".cv",".cw",".cx",".cy",".cz",".dd",".de",".dj",".dk",".dm",".do",".dz",".ec",".ee",".eg",".eh",".er",".es",".et",".eu",".fi",".fj",".fk",".fm",".fo",".fr",".ga",".gb",".gd",".ge",".gf",".gg",".gh",".gi",".gl",".gm",".gn",".gp",".gq",".gr",".gs",".gt",".gu",".gw",".gy",".hk",".hm",".hn",".hr",".ht",".hu",".id",".ie",".il",".im",".in",".io",".iq",".ir",".is",".it",".je",".jm",".jo",".jp",".ke",".kg",".kh",".ki",".km",".kn",".kp",".kr",".krd",".kw",".ky",".kz",".la",".lb",".lc",".li",".lk",".lr",".ls",".lt",".lu",".lv",".ly",".ma",".mc",".md",".me",".mf",".mg",".mh",".mk",".ml",".mm",".mn",".mo",".mp",".mq",".mr",".ms",".mt",".mu",".mv",".mw",".mx",".my",".mz",".na",".nc",".ne",".nf",".ng",".ni",".nl",".no",".np",".nr",".nu",".nz",".om",".pa",".pe",".pf",".pg",".ph",".pk",".pl",".pm",".pn",".pr",".ps",".pt",".pw",".py",".qa",".quebec",".re",".ro",".rs",".ru",".rw",".sa",".sb",".sc",".sd",".se",".sg",".sh",".si",".sj",".sk",".sl",".sm",".sn",".so",".sr",".ss",".st",".su",".sv",".sx",".sy",".sz",".tc",".td",".tf",".tg",".th",".tj",".tk",".tl",".tm",".tn",".to",".tp",".tr",".tt",".tv",".tw",".tz",".ua",".ug",".uk",".um",".us",".uy",".uz",".va",".vc",".ve",".vg",".vi",".vn",".vu",".wf",".ws",".ye",".yt",".yu",".za",".zm",".zr",".zw"]
PORTS_TO_SCAN=[(21,False),(22,False),(23,False),(80,True),(443,True),(445,False),(1433,False),(1521,False),(3306,False),(3389,False)]


def IPtesting(domain):
    """
    test if the domain is a IP adress
    :param domain: string
    :return: bool
    """


    if (re.match(r"(.)+\.(.)+\.(.)+",domain)) != None:
        return 1
    else :
        return -1

def leghtTesting(url):
    """
    test if url lenght is <54, between 54 and 75 or over 75
    :param url:string
    :return: -1,0 or 1
    """

    if (len(url<54)):
        return -1
    elif (len(url>54) and len(url<75)):
        return 0
    else:
        return 1

def shortenerTEsting(url):
    """
    test if the url is a short url
    :param url: string
    :return: bool
    """
    for short in URL_SHORTENER:
        if short.lower() in url:
            return 1

    return -1

def atSymbolTetsting(url):
    """
    test if the at symbol is in url
    :param url: string
    :return: bool
    """
    if ("@" in url):
        return 1
    return -1

def doubleSlashTesting(url):
    """
    test if there is double slash in url
    :param url: string
    :return: bool
    """
    if ("//" in url):
        return 1
    return -1

def dashTesting(url):
    """
        test if there is dash in url
        :param url: string
        :return: bool
        """
    if ("-" in url):
        return 1
    return -1

def subDomainTesting(domain):
    """
    test if there are too many subdomains
    :param domain:string
    :return: -1,0 or 1
    """

    for tld in CCTLD:
        if (re.match(("(.)*"+tld+"$"),domain)):
            domain = domain[:len(domain)-len(tld)]
            if domain.count('.') <= 1 :
                return -1
            elif domain.count('.') == 2 :
                return 0
            else :
                return 1

def ageCertificateTesting(domain):
    return 0

def expirationDomainTesting(domain):
    """
    test if the valid duration of the domain is enough long
    :param domain:string
    :return: bool
    """

    now = datetime.datetime.now()
    today = datetime.date(now.year,now.month,now.day)

    w=whois.whois(domain).expiration_date
    expiration = datetime.date(w[0],w[1],w[2])

    delta = expiration-today

    if delta.days > 365:
        return -1
    else :
        return 1

def faviconTesting(html, domain):
    """
    test if the favicon url is from the same domain as the site
    :param html: string (html source code)
    :param domain: string
    :return: bool
    """

    soup = BeautifulSoup(html)
    head = soup.find("head")
    favicon=head.find("link", {"rel" : "icon"})

    if favicon != None:
        linkFavicon=favicon.get("href")
        if domain not in linkFavicon:
            return 1

    return -1

def portTesting(domain):
    """
    test all important ports to check if they are opened or closed
    :param domain: string
    :return: bool or error
    """

    try:
        remoteServerIP = socket.gethostbyname(domain)

        for port in PORTS_TO_SCAN:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((remoteServerIP, port[0]))
            sock.close()

            if result == 0 and port[2] == False:
                return 1
            elif result != 0 and port[2] == True:
                return 1
        return -1

    except:
        return -2

def httpTesting(url):
    """
    test if there is the http token into the URL
    :param url: string
    :return: bool
    """
    if "http" in url :
        return 1

    return -1

def requestedURL(html, domain):
    """
    test the percentage of external objects
    :param html: string (html source code)
    :param domain: string
    :return: -1,0 or 1
    """

    totalLinks = 0
    externalLinks = 0

    m=[]

    soup = BeautifulSoup(html)

    for p in soup.find_all("img"):
        if "http" in p.get("src"):
            m.append(p.get('src'))

    for p in soup.find_all("video"):
        for q in p.find_all("source"):
            if "http" in q.get("src"):
                m.append(q.get('src'))

    for p in soup.find_all("audio"):
        for q in p.find_all("source"):
            if "http" in q.get("src"):
                m.append(q.get('src'))

    for link in m:
        if domain not in link:
            externalLinks+=1
        totalLinks +=1

    if totalLinks != 0 :
        percentage = externalLinks/totalLinks
        if percentage >= 0.61:
            return 1
        elif percentage >= 0.22:
            return 0

    return -1

def anchorsTesting(html,domain):
    return 0

def tagsLinksTesting(html, domain):
    """
    test the percentage of external links into meta, script and link tags
    :param html: string (html source code)
    :param domain: string
    :return: -1,0 or 1
    """
    totalLinks = 0
    externalLinks = 0

    m = []

    soup = BeautifulSoup(html)

    meta = soup.find_all("meta")
    links = soup.find_all("link")
    scripts = soup.find_all("script")

    for tag in meta:
        for link in re.findall(re.compile("\"http.*?\""), str(tag)):
            m.append(link)

    for tag in links:
        if "http" in tag.get("href"):
            m.append(tag.get("href"))

    for tag in scripts:
        if "http" in tag.get("href"):
            m.append(tag.get("href"))


    for link in m:
        if domain not in link:
            externalLinks+=1
        totalLinks +=1

    if totalLinks != 0 :
        percentage = externalLinks/totalLinks
        if percentage >= 0.81:
            return 1
        elif percentage >= 0.17:
            return 0

    return -1

def SFHTesting(html,domain):
    return 0

def emailTesting(html):
    return 0

def abnormalURLTesting(url):
    return 0

def frowardingTesting(url):
    return 0

def barCustomTesting(html):
    return 0

def rightClickTesting(html):
    return 0

def popUpTesting(html):
    return 0

def IFrameTesting(html):
    return 0

def domainAgeTesting(doamin):
    return 0

def DNSRecordTesting(domain):
    return 0

def trafficTesting(domain):
    return 0

def pageRankTesting(domain):
    return 0

def googleIndexTesting(domain):
    return 0

def linksPointingToTesting(url):
    return 0

def statisticReportTEsting(domain):
    return 0




def UrlToDatabase (url):
    """
    analyse the url to create a list of 30 features which can be used for GAN implementation. Refer to documentation for all criteria
    :param url: string
    :return: list
    """

    features=[]

    html = requests.get(url).content

    if url[:6] == "http://":
        url = url[7:]
        http = "http"

    elif url[:7] == "https://":
        url = url[8:]
        http = "https"

    else :
        http = ""

    domain = url.split("/")

    # testing ip adress
    features.append(IPtesting(domain))

    # testing lenght of the url
    features.append(leghtTesting(url))

    # testing shortener url
    features.append(shortenerTEsting(url))

    #testing at symbol
    features.append(atSymbolTetsting(url))

    #testing double slash
    features.append(doubleSlashTesting(url))

    # testing dash
    features.append(dashTesting(url))

    # testing subdomain count
    features.append(subDomainTesting(domain))

    # testing age of the domain certificate
    features.append(ageCertificateTesting(domain))

    # testing expiration date of domain
    features.append(expirationDomainTesting(domain))

    # testing favicon href
    features.append(faviconTesting(html,domain))

    # testing ports
    features.append(portTesting(domain))

    if features[-1] == -2 :
        return -1

    # testing http token
    features.append(httpTesting(url))

    # testing request URL
    features.append(requestedURL(html,domain))

    # testing anchors





    return features














