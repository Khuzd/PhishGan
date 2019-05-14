"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
"""

import re
from m2ext import SSL
from M2Crypto import X509

URL_SHORTENER = ["shrinkee.com","goo.gl","7.ly","adf.ly","admy.link","al.ly","bc.vc","bit.do","doiop.com","ity.im","url.ie","is.gd","linkmoji.co","sh.dz24.info","lynk.my","mcaf.ee","yep.it","ow.ly","x61.ch","qr.net","shrinkee.com","u.to","ho.io","thinfi.com","tiny.cc","tinyurl.com","tny.im","flic.krp","v.gd","y2u.be","cutt.us","zzb.bz","adfoc.us","bit.ly","cur.lv","git.io","hec.su","viid.me","tldrify.com","tr.im"]
CCTLD =[".ac",".ad",".ae",".af",".ag",".ai",".al",".am",".an",".ao",".aq",".ar",".as",".at",".au",".aw",".ax",".az",".ba",".bb",".bd",".be",".bf",".bg",".bh",".bi",".bj",".bl",".bm",".bn",".bo",".bq",".br",".brussels",".bs",".bt",".bu",".bv",".bw",".by",".bz",".bzh",".ca",".cat",".cc",".cd",".cf",".cg",".ch",".ci",".ck",".cl",".cm",".cn",".co",".corsica",".cr",".cs ",".cu",".cv",".cw",".cx",".cy",".cz",".dd",".de",".dj",".dk",".dm",".do",".dz",".ec",".ee",".eg",".eh",".er",".es",".et",".eu",".fi",".fj",".fk",".fm",".fo",".fr",".ga",".gb",".gd",".ge",".gf",".gg",".gh",".gi",".gl",".gm",".gn",".gp",".gq",".gr",".gs",".gt",".gu",".gw",".gy",".hk",".hm",".hn",".hr",".ht",".hu",".id",".ie",".il",".im",".in",".io",".iq",".ir",".is",".it",".je",".jm",".jo",".jp",".ke",".kg",".kh",".ki",".km",".kn",".kp",".kr",".krd",".kw",".ky",".kz",".la",".lb",".lc",".li",".lk",".lr",".ls",".lt",".lu",".lv",".ly",".ma",".mc",".md",".me",".mf",".mg",".mh",".mk",".ml",".mm",".mn",".mo",".mp",".mq",".mr",".ms",".mt",".mu",".mv",".mw",".mx",".my",".mz",".na",".nc",".ne",".nf",".ng",".ni",".nl",".no",".np",".nr",".nu",".nz",".om",".pa",".pe",".pf",".pg",".ph",".pk",".pl",".pm",".pn",".pr",".ps",".pt",".pw",".py",".qa",".quebec",".re",".ro",".rs",".ru",".rw",".sa",".sb",".sc",".sd",".se",".sg",".sh",".si",".sj",".sk",".sl",".sm",".sn",".so",".sr",".ss",".st",".su",".sv",".sx",".sy",".sz",".tc",".td",".tf",".tg",".th",".tj",".tk",".tl",".tm",".tn",".to",".tp",".tr",".tt",".tv",".tw",".tz",".ua",".ug",".uk",".um",".us",".uy",".uz",".va",".vc",".ve",".vg",".vi",".vn",".vu",".wf",".ws",".ye",".yt",".yu",".za",".zm",".zr",".zw"]
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



def UrlToDatabase (url):
    """
    analyse the url to create a list of 30 features which can be used for GAN implementation. Refer to documentation for all criteria
    :param url: string
    :return: list
    """

    features=[]

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










