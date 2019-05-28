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
import dns.resolver
import googleIndexChecker
import json
import struct
import ssl
import time
from multiprocessing import Process, Queue
import csv

URL_SHORTENER = ["shrinkee.com", "goo.gl", "7.ly", "adf.ly", "admy.link", "al.ly", "bc.vc", "bit.do", "doiop.com",
                 "ity.im", "url.ie", "is.gd", "linkmoji.co", "sh.dz24.info", "lynk.my", "mcaf.ee", "yep.it", "ow.ly",
                 "x61.ch", "qr.net", "shrinkee.com", "u.to", "ho.io", "thinfi.com", "tiny.cc", "tinyurl.com", "tny.im",
                 "flic.krp", "v.gd", "y2u.be", "cutt.us", "zzb.bz", "adfoc.us", "bit.ly", "cur.lv", "git.io", "hec.su",
                 "viid.me", "tldrify.com", "tr.im"]

CCTLD = [".ac", ".ad", ".ae", ".af", ".ag", ".ai", ".al", ".am", ".an", ".ao", ".aq", ".ar", ".as", ".at", ".au", ".aw",
         ".ax", ".az", ".ba", ".bb", ".bd", ".be", ".bf", ".bg", ".bh", ".bi", ".bj", ".bl", ".bm", ".bn", ".bo", ".bq",
         ".br", ".brussels", ".bs", ".bt", ".bu", ".bv", ".bw", ".by", ".bz", ".bzh", ".ca", ".cat", ".cc", ".cd",
         ".cf", ".cg", ".ch", ".ci", ".ck", ".cl", ".cm", ".cn", ".co", ".corsica", ".cr", ".cs ", ".cu", ".cv", ".cw",
         ".cx", ".cy", ".cz", ".dd", ".de", ".dj", ".dk", ".dm", ".do", ".dz", ".ec", ".ee", ".eg", ".eh", ".er", ".es",
         ".et", ".eu", ".fi", ".fj", ".fk", ".fm", ".fo", ".fr", ".ga", ".gb", ".gd", ".ge", ".gf", ".gg", ".gh", ".gi",
         ".gl", ".gm", ".gn", ".gp", ".gq", ".gr", ".gs", ".gt", ".gu", ".gw", ".gy", ".hk", ".hm", ".hn", ".hr", ".ht",
         ".hu", ".id", ".ie", ".il", ".im", ".in", ".io", ".iq", ".ir", ".is", ".it", ".je", ".jm", ".jo", ".jp", ".ke",
         ".kg", ".kh", ".ki", ".km", ".kn", ".kp", ".kr", ".krd", ".kw", ".ky", ".kz", ".la", ".lb", ".lc", ".li",
         ".lk", ".lr", ".ls", ".lt", ".lu", ".lv", ".ly", ".ma", ".mc", ".md", ".me", ".mf", ".mg", ".mh", ".mk", ".ml",
         ".mm", ".mn", ".mo", ".mp", ".mq", ".mr", ".ms", ".mt", ".mu", ".mv", ".mw", ".mx", ".my", ".mz", ".na", ".nc",
         ".ne", ".nf", ".ng", ".ni", ".nl", ".no", ".np", ".nr", ".nu", ".nz", ".om", ".pa", ".pe", ".pf", ".pg", ".ph",
         ".pk", ".pl", ".pm", ".pn", ".pr", ".ps", ".pt", ".pw", ".py", ".qa", ".quebec", ".re", ".ro", ".rs", ".ru",
         ".rw", ".sa", ".sb", ".sc", ".sd", ".se", ".sg", ".sh", ".si", ".sj", ".sk", ".sl", ".sm", ".sn", ".so", ".sr",
         ".ss", ".st", ".su", ".sv", ".sx", ".sy", ".sz", ".tc", ".td", ".tf", ".tg", ".th", ".tj", ".tk", ".tl", ".tm",
         ".tn", ".to", ".tp", ".tr", ".tt", ".tv", ".tw", ".tz", ".ua", ".ug", ".uk", ".um", ".us", ".uy", ".uz", ".va",
         ".vc", ".ve", ".vg", ".vi", ".vn", ".vu", ".wf", ".ws", ".ye", ".yt", ".yu", ".za", ".zm", ".zr", ".zw"]

PORTS_TO_SCAN = [(21, False), (22, False), (23, False), (80, True), (443, True), (445, False), (1433, False),
                 (1521, False), (3306, False), (3389, False)]

TRUSTED_ISSUERS = ["geotrust", "godaddy", "network solutions", "thawte", "comodo", "doster", "verisign", "symantec",
                   "rapidssl", "digicert"]



def IPtesting(domain):
    """
    test if the domain is a IP adress
    :param domain: string
    :return: -1 or 1
    """

    if (re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(domain))) != None:
        return 1
    elif (re.match(r"0x..\.0x..\.0x..\.0x..", str(domain))) != None:
        return 1
    else:
        return -1


def leghtTesting(url):
    """
    test if url lenght is <54, between 54 and 75 or over 75
    :param url:string
    :return: -1,0 or 1
    """

    if ((len(url)) < 54):
        return -1
    elif (len(url) > 54 and len(url) < 75):
        return 0
    else:
        return 1


def shortenerTEsting(url):
    """
    test if the url is a short url
    :param url: string
    :return: -1 or 1
    """
    for short in URL_SHORTENER:
        if short.lower() in url:
            return 1

    return -1


def atSymbolTetsting(url):
    """
    test if the at symbol is in url
    :param url: string
    :return: -1 or 1
    """
    if ("@" in url):
        return 1
    return -1


def doubleSlashTesting(url):
    """
    test if there is double slash in url
    :param url: string
    :return: -1 or 1
    """
    if ("//" in url):
        return 1
    return -1


def dashTesting(url):
    """
        test if there is dash in url
        :param url: string
        :return: -1 or 1
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
    if len(domain.split("www.")) == 2:
        domain = domain.split("www.")[1]

    for tld in CCTLD:
        if (re.match(("(.)*" + tld + "$"), str(domain))):
            domain = domain[:len(domain) - len(tld)]
            if domain.count('.') <= 1:
                return -1
            elif domain.count('.') == 2:
                return 0
            else:
                return 1
    if domain.count('.') <= 1:
        return -1
    elif domain.count('.') == 2:
        return 0
    else:
        return 1


def ageCertificateTesting(domain):
    """
    test if the certificate is not too young and delivered by a trusted issuer
    :param domain: string
    :return: -1,0 or 1
    """

    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
    try:
        s.connect((domain, 443))
        cert = s.getpeercert()
    except:

        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        try:
            s.connect((domain, 443))
            cert = s.getpeercert()
        except:
            return 1

    issuer = dict(x[0] for x in cert['issuer'])["organizationName"].lower()
    beginDate = datetime.datetime.strptime(cert["notBefore"].split(' GMT')[0], '%b  %d %H:%M:%S %Y')
    endDate = datetime.datetime.strptime(cert["notAfter"].split(' GMT')[0], '%b  %d %H:%M:%S %Y')

    delta = endDate - beginDate

    # print (issuer)
    # print (TRUSTED_ISSUERS)

    for trusted in TRUSTED_ISSUERS:
        if trusted in issuer:
            if delta.days >= 365:
                return -1

    return 0


def expirationDomainTesting(whois):
    """
    test if the valid duration of the domain is enough long
    :param whois:string
    :return: -1 or 1
    """

    now = datetime.datetime.now()

    expiration = whois.expiration_date
    if type(expiration) == list:
        expiration = expiration[0]

    try:
        delta = expiration - now
    except:
        return -2

    if delta.days > 365:
        return -1
    else:
        return 1


def faviconTesting(html, domain):
    """
    test if the favicon url is from the same domain as the site
    :param html: string (html source code)
    :param domain: string
    :return: -1 or 1
    """

    soup = BeautifulSoup(html, features="lxml")
    head = soup.find("head")
    favicon = None
    if head != None:
        favicon = head.find("link", {"rel": "icon"})

    if favicon != None:
        linkFavicon = favicon.get("href")
        if domain not in linkFavicon:
            return 1

    return -1


def portTesting(domain):
    """
    test all important ports to check if they are opened or closed
    :param domain: string
    :return: -1 or 1 or error
    """

    try:
        remoteServerIP = socket.gethostbyname(domain)

        for port in PORTS_TO_SCAN:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((remoteServerIP, port[0]))
            sock.close()

            if result == 0 and port[1] == False:
                return 1
            elif result != 0 and port[1] == True:
                return 1
        return -1

    except Exception as e:
        print(e)
        return -2


def httpTesting(url):
    """
    test if there is the http token into the URL
    :param url: string
    :return: -1 or 1
    """
    if "http" in url:
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

    m = []

    soup = BeautifulSoup(html, features="lxml")

    for p in soup.find_all("img"):
        if p.has_attr("src") and "http" in p.get("src"):
            m.append(p.get('src'))

    for p in soup.find_all("video"):
        for q in p.find_all("source"):
            if q.has_attr("src") and "http" in q.get("src"):
                m.append(q.get('src'))

    for p in soup.find_all("audio"):
        for q in p.find_all("source"):
            if q.has_attr("src") and "http" in q.get("src"):
                m.append(q.get('src'))

    for link in m:
        if domain not in link:
            externalLinks += 1
        totalLinks += 1

    if totalLinks != 0:
        percentage = externalLinks / totalLinks
        if percentage >= 0.61:
            return 1
        elif percentage >= 0.22:
            return 0

    return -1


def anchorsTesting(html, domain):
    """
    test the percentage of external links anchors
    :param html: string (html source code)
    :param domain: string
    :return: -1,0 or 1
    """
    soup = BeautifulSoup(html, features="lxml")

    tags = soup.findAll("a", href=True)
    anchors = []
    for tag in tags:
        anchors.append(tag.get("href"))

    totalLink = len(anchors)
    externalLinks = 0

    for anchor in anchors:
        if 'http' in anchor and domain not in anchor:
            externalLinks += 1

    if externalLinks == 0 or externalLinks / totalLink < 0.31:
        return -1

    elif externalLinks / totalLink <= 0.67:
        return 0

    return 1


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

    soup = BeautifulSoup(html, features="lxml")

    meta = soup.find_all("meta")
    links = soup.find_all("link")
    scripts = soup.find_all("script")

    for tag in meta:
        for link in re.findall(re.compile("\"http.*?\""), str(tag)):
            m.append(link)

    for tag in links:
        if tag.has_attr("href") and "http" in tag.get("href"):
            m.append(tag.get("href"))

    for tag in scripts:
        if tag.has_attr("href") and "http" in tag.get("href"):
            m.append(tag.get("href"))

    for link in m:
        if domain not in link:
            externalLinks += 1
        totalLinks += 1

    if totalLinks != 0:
        percentage = externalLinks / totalLinks
        if percentage >= 0.81:
            return 1
        elif percentage >= 0.17:
            return 0

    return -1


def SFHTesting(html, domain):
    """
    test if the Server Form Handler of all forms is not suspicious
    :param html: string (html source code)
    :param domain: string
    :return: -1,0 or 1
    """
    soup = BeautifulSoup(html, features="lxml")

    for form in soup.find_all("form"):
        if (str(form.get("action")) == ""):
            return 1

        elif (str(form.get("action")) == "about:blank"):
            return 1

        elif (domain not in str(form.get("action"))):
            return 0
    return -1


def emailTesting(html):
    """
    test if no user's informations are send by email
    :param html: string (html source code)
    :return: -1 or 1
    """
    soup = BeautifulSoup(html, features="lxml")

    for form in soup.find_all("form"):
        if (re.match(r"mail\(.*?\)", str(form))):
            return 1
        elif (re.match(r"mailto:", str(form))):
            return 1
    return -1


def abnormalURLTesting(url):
    """
    test if the domain name from WHOIS is in the RUL
    :param url: string
    :return: -1 or 1
    """

    whoisURL = whois.whois(url)["domain_name"]
    if type(whoisURL) == list:
        whoisURL = whoisURL[0]

    if (whoisURL!= None and whoisURL.lower() not in url):
        return 1
    return -1


def forwardingTesting(url, http):
    """
    test the number of forwarding
    :param url: string
    :return: -1,0 or 1
    """
    countForward = len(requests.get(http + "://" + url).history)

    if countForward <= 1:
        return -1

    if countForward < 4:
        return 0

    return 1


def barCustomTesting(html):
    """
    Check if the status bar is not abnormally modify
    :param html: string (html source code)
    :return: -1 or 1
    """

    soup = BeautifulSoup(html, features="lxml")

    for tag in soup.find_all(onmouseover=True):
        if "window.status" in str(tag):
            return 1

    return -1


def rightClickTesting(html):
    """
    test if the right click is not disabled
    :param html: string (html source code)
    :return: -1 or 1
    """
    if (re.match(r"\"contextmenu\".*?preventdefaut", str(html)) != None):
        return 1
    return -1


def popUpTesting(html):
    """
    testing if popup with text fields
    :param html: string (html source code)
    :return: -1 or 1
    """
    if re.match(r"prompt\(.+?\);", str(html)):
        return 1
    return -1


def IFrameTesting(html):
    """
    testing if the site use Iframe
    :param html: string (html source code)
    :return: -1 or 1
    """

    soup = BeautifulSoup(html, features="lxml")
    if "iframe" in str(soup):
        return 1

    else:
        return -1


def domainAgeTesting(whois):
    """
    testing if domain age is greater than 6 months
    :param doamin: string
    :return: -1 or 1
    """

    now = datetime.datetime.now()
    today = datetime.date(now.year, now.month, now.day)

    creation = whois.creation_date

    if type(creation) == list:
        creation = creation[0]
    try:
        delta = now - creation
    except:
        return -2

    if delta.days > 365 / 2:
        return -1
    else:
        return 1


def DNSRecordTesting(domain):
    """
    test if the domain is recorded in a DNS
    :param domain: string
    :return: -1 or 1
    """

    if len(domain.split("www.")) == 2:
        domain = domain.split("www.")[1]

    try:
        empty = True
        resolver = dns.resolver.Resolver()
        answer = resolver.query(domain, "NS")
        i = 0
        while empty and i < len(answer):
            if answer[i].target != "":
                empty = False
            i += 1
    except:
        return 1

    if empty == False:
        return -1

    return 1


def trafficTesting(domain):
    """
    collect the website rank on AWIS database and test if it is not abnormal
    :param domain: string
    :return: -1,0 or 1
    """
    try:
        soup = BeautifulSoup(requests.get("https://www.alexa.com/siteinfo/" + domain).content, features="lxml")
        tag = soup.find(id="card_rank").find("", {"class": "rank-global"}).find("", {"class": "big data"})
        rank = int("".join(re.findall('\d+', str(tag))))
    except AttributeError:
        return 1

    if rank > 100000:
        return 0

    return -1


def pageRankTesting(domain):
    return -1


def googleIndexTesting(url):
    """
    test if url is indexed by google
    :param url: string
    :return: -1 or 1
    """
    # index = googleIndexChecker.google_search("site:" + url)
    # if index:
    #     return -1
    # return 1
    # html = requests.get('https://www.google.com/search?q=site:'+url, headers=headers, proxies=proxies).content
    # soup=BeautifulSoup(html, features="lxml")
    # try:
    #     if soup.find(id="resultStats").contents != []:
    #         #print(soup.findAll(id="resultStats").text)
    #         return -1
    # except AttributeError:
    #     print("google fail")
    #     time.sleep(20)
    #     try :
    #         if soup.find(id="resultStats").contents != []:
    #             # print(soup.findAll(id="resultStats").text)
    #             return -1
    #     except:
    #         return -2
    #
    # return 1
    try:
        soup = BeautifulSoup(requests.get("https://www.ecosia.org/search?q=site%3A"+url, stream=False).content,features="lxml")
        results = re.findall('\d+',soup.find("",{"class":"card-title card-title-result-count"}).text)
        if len(results) == 1 and results[0]=='0':
            return 1
        return -1
    except Exception as e:
        print(e)
        pass




def linksPointingToTesting(url):
    """
    collect the count of all sites which linked to the url on AWIS database and test if it is not abnormal
    :param domain: string
    :return: -1,0 or 1
    """
    soup = BeautifulSoup(requests.get("https://www.alexa.com/siteinfo/" + url).content, features="lxml")
    try:
        countLinks = int("".join(soup.find("", {"class": "linksin"}).find("", {"class": "big data"}).get_text().split(",")))
    except AttributeError:
        return 1
    if countLinks == 0:
        return 1
    elif countLinks <= 2:
        return 0

    return -1


def statisticReportTEsting(domain):
    """
    test if the ip address of the domain is in top 50 of www.stopbadware.org
    :param domain:
    :return: -1 or 1
    """
    IPdomain = socket.gethostbyname(domain)

    jsonDictIP = json.loads(
        requests.post("https://www.stopbadware.org/sites/all/themes/sbw/clearinghouse.php", data={'q': 'tops'}).text)

    IPList = []

    for site in jsonDictIP['top_ip']:
        IPList.append(socket.inet_ntoa(struct.pack('!L', int(site['ip_addr']))))

    for ip in IPList:
        if ip == domain:
            return 1

    return -1


def UrlToDatabase(url, queue):
    """
    analyse the url to create a list of 30 features which can be used for GAN implementation. Refer to documentation for all criteria
    :param url: string
    :return: list
    """

    features = []

    if len(url.split("http://")) == 2:
        http = "http"
        url = url.split("http://")[1]

    elif len(url.split("https://")) == 2:
        http = "https"
        url = url.split("https://")[1]

    domain = url.split("/")[0]

    retry = True
    while (retry):  # to retry if whois database kick us
        try:
            whoisDomain = whois.whois(str(domain))
            retry = False
        except (whois.parser.PywhoisError,socket.gaierror):
            print("URL : " + domain + " not in whois database")
            # time.sleep(1.5)
            queue.put(-1)
            return
        except (ConnectionResetError,socket.timeout):
            pass

    try:
        html = requests.get("https://" + url, ).content
        http = "https"

    except:
        try:
            html = requests.get("http://" + url).content
            http = "http"
        except:
            try:
                html = requests.get(url).content
                http = ""
            except:
                print("Can not get HTML content from : " + url)
                # time.sleep(1.5)
                queue.put(-1)
                return

    # print(http)
    # print(url)
    # print(domain)

    print("Testing : " + url)

    # testing ip adress
    features.append(IPtesting(domain))

    # testing lenght of the url
    features.append(leghtTesting(url))

    # testing shortener url
    features.append(shortenerTEsting(url))

    # testing at symbol
    features.append(atSymbolTetsting(url))

    # testing double slash
    features.append(doubleSlashTesting(url))

    # testing dash
    features.append(dashTesting(url))

    # testing subdomain count
    features.append(subDomainTesting(domain))

    # testing age of the domain certificate
    if http == "https":
        features.append(ageCertificateTesting(domain))
    else:
        features.append(1)

    # testing expiration date of domain
    features.append(expirationDomainTesting(whoisDomain))
    if features[-1]== -2:
        return -1
    # testing favicon href
    features.append(faviconTesting(html, domain))

    # testing ports
    features.append(portTesting(domain))

    if features[-1] == -2:
        print("port testing error")
        queue.put(-1)
        return

    # testing http token
    features.append(httpTesting(url))

    # testing request URL
    features.append(requestedURL(html, domain))

    # testing anchors
    features.append(anchorsTesting(html, domain))

    # testing tags links
    features.append(tagsLinksTesting(html, domain))

    # testing SFH
    features.append(SFHTesting(html, domain))

    # testing email
    features.append(emailTesting(html))

    # testing abnormal url
    features.append(abnormalURLTesting(url))

    # testing forwarding
    features.append(forwardingTesting(url, http))

    # testing abnormal status bar
    features.append(barCustomTesting(html))

    # testing right click disabling
    features.append(rightClickTesting(html))

    # testing popup
    features.append(popUpTesting(html))

    # testing IFrame
    features.append(IFrameTesting(html))

    # testing domain age
    features.append(domainAgeTesting(whoisDomain))
    if features[-1]== -2:
        return -1

    # testing DNS record
    features.append(DNSRecordTesting(domain))

    # testing traffic
    features.append(trafficTesting(domain))

    # testing page rank
    features.append(pageRankTesting(domain))

    #features.append(googleIndexTesting(url))
    features.append(-1)
    if features[-1]== -2:
        return -2

    features.append(linksPointingToTesting(url))

    features.append(statisticReportTEsting(domain))

    queue.put(features)
    return


if __name__ == "__main__":
    # execute only if run as a script
    t0 = time.time()
    columns = ["having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol", "double_slash_redirecting",
               "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State", "Domain_registeration_length", "Favicon", "port",
               "HTTPS_token", "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email",
               "Abnormal_URL", "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
               "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report"]

    failledURLS=[]
    notReacheable = []



    count = 1
    begin = 1
    with open("data/top25000.csv", newline='') as csvinfile:

            for row in csv.reader(csvinfile, delimiter=',', quotechar='|'):
                print ("first : " + str(count))

                if count >= begin:
                    queue = Queue()
                    proc = Process(target=UrlToDatabase,
                                   args=(row[0], queue,))  # creation of a process calling longfunction with the specified arguments
                    proc.start()

                    try:
                        results = queue.get(timeout=50)
                        print(results)
                        proc.join()
                        if results == -1:
                            notReacheable.append(results)
                        elif results == -2:
                            failledURLS.append(row[1])
                        else:
                            with open('data/top25000out.csv', 'a') as outcsvfile:
                                writer = csv.writer(outcsvfile, delimiter=',', quotechar='"')
                                writer.writerow([row[0]] + results)

                    except Exception as e:
                        failledURLS.append(row[0])
                        print(e)
                    proc.terminate()
                count += 1

    realfailledURLS = []

    count=1
    for url in failledURLS:
        print("second" + str(count))
        count +=1
        queue = Queue()
        proc = Process(target=UrlToDatabase,
                       args=(url, queue,))  # creation of a process calling longfunction with the specified arguments
        proc.start()

        try:
            results = queue.get(timeout=90)
            proc.join()
            if results == -1:
                notReacheable.append(results)
            else:
                with  open('data/top25000out.csv', 'a') as outcsvfile:
                    writer = csv.writer(outcsvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    writer.writerow([url] + results)
        except:
            realfailledURLS.append(url)
        proc.terminate()


    print("failed : ")
    print(realfailledURLS)






    print("Time for 100 URL : " + str(time.time()-t0))
