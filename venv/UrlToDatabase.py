"""

-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
"""

import csv
import datetime
import json
import logging
import re
import socket
import ssl
import struct

import dns.resolver
import requests
import socks
from bs4 import BeautifulSoup
from func_timeout import func_timeout, FunctionTimedOut

import googleIndexChecker
from libs.whois import whois
from libs.whois.parser import PywhoisError

# Import logger
logger = logging.getLogger('main')

# ---------------------
#  Set constants
# ---------------------

columns = ["having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol", "double_slash_redirecting",
           "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State", "Domain_registeration_length", "Favicon", "port",
           "HTTPS_token", "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email",
           "Abnormal_URL", "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
           "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report"]

URL_SHORTENER = ["shrinkee.com", "goo.gl", "7.ly", "adf.ly", "admy.link", "al.ly", "bc.vc", "bit.do", "doiop.com",
                 "ity.im", "url.ie", "is.gd", "linkmoji.co", "sh.dz24.info", "lynk.my", "mcaf.ee", "yep.it", "ow.ly",
                 "x61.ch", "qr.net", "shrinkee.com", "u.to", "ho.io", "thinfi.com", "tiny.cc", "tinyurl.com", "tny.im",
                 "flic.krp", "v.gd", "y2u.be", "cutt.us", "zzb.bz", "adfoc.us", "bit.ly", "cur.lv", "git.io", "hec.su",
                 "viid.me", "tldrify.com", "tr.im", "link.do"]

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


class URL:
    def __init__(self, url, manualInit=False):
        # ---------------------
        #  Define attributes
        # ---------------------
        self.http = None
        self.url = url
        self.domain = None
        self.whoisDomain = None
        self.html = None

        # ---------------------
        #  Calculate attributes
        # ---------------------

        # http, url and domain attributes
        if not manualInit:

            if len(url.split("http://")) != 1:
                self.http = "http"
                self.url = url.split("http://")[1]

            elif len(url.split("https://")) != 1:
                self.http = "https"
                self.url = url.split("https://")[1]

            self.domain = self.url.split("/")[0].split(":")[0]

            # whoisDomain attribute
            retry = True
            while retry:  # to retry if whois database kick us
                try:
                    retry = False
                    self.whoisDomain = func_timeout(30, whois, kwargs={'Url': str(self.domain)})

                except (PywhoisError, socket.gaierror, socks.GeneralProxyError):
                    logger.error("URL : " + self.domain + " not in whois database")
                    # time.sleep(1.5)
                except (ConnectionResetError, socket.timeout, ConnectionAbortedError):
                    pass

                except FunctionTimedOut:
                    logger.error("Whois timeout")

            # html and http attributes
            try:
                self.html = func_timeout(30, requests.get, kwargs={'url': "https://" + self.url}).content
                self.http = "https"

            except FunctionTimedOut:
                logger.error("Get timeout")

            except:
                try:
                    self.html = func_timeout(30, requests.get, kwargs={'url': "http://" + self.url}).content
                    self.http = "http"
                except FunctionTimedOut:
                    logger.error("Get timeout")

                except:
                    try:
                        self.html = func_timeout(30, requests.get, kwargs={'url': self.url}).content
                        self.http = ""

                    except FunctionTimedOut:
                        logger.error("Get timeout")

                    except:
                        logger.error("Can not get HTML content from : " + self.url)
                        # time.sleep(1.5)
        if self.whoisDomain != None:
            self.domain = self.whoisDomain.domain

        ## Weights
        self.ipWeight = "error"
        self.lenghtWeight = "error"
        self.shorteningWeight = "error"
        self.atWeight = "error"
        self.doubleSlashWeight = "error"
        self.dashWeight = "error"
        self.subDomainWeight = "error"
        self.certificateAgeWeight = "error"
        self.expirationWeight = "error"
        self.faviconWeight = "error"
        self.portWeight = "error"
        self.httpWeight = "error"
        self.requestedWeight = "error"
        self.anchorsWeight = "error"
        self.tagWeight = "error"
        self.SFHWeight = "error"
        self.emailWeight = "error"
        self.abnormalWeight = "error"
        self.forwardWeight = "error"
        self.barCustomWeight = "error"
        self.rightClickWeight = "error"
        self.popupWeight = "error"
        self.iFrameWeight = "error"
        self.domainAgeWeight = "error"
        self.dnsWeight = "error"
        self.trafficWeight = "error"
        self.pageRankWeight = "error"
        self.indexingWeight = "error"
        self.linksWeight = "error"
        self.statisticWeight = "error"

        return

    def IPtesting(self):
        """
        test if the domain is a IP adress
        :return: -1 or 1
        """

        if (re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(self.domain))) is not None:
            self.ipWeight = 1
            return
        elif (re.match(r"0x..\.0x..\.0x..\.0x..", str(self.domain))) is not None:
            self.ipWeight = 1
            return
        else:
            self.ipWeight = -1
            return

    def leghtTesting(self):
        """
        test if url lenght is <54, between 54 and 75 or over 75
        :return: -1,0 or 1
        """

        if len(self.url) < 54:
            self.lenghtWeight = -1
            return
        elif 54 < len(self.url) < 75:
            self.lenghtWeight = 0
            return
        else:
            self.lenghtWeight = 1
            return

    def shortenerTEsting(self):
        """
        test if the url is a short url
        :return: -1 or 1
        """
        for short in URL_SHORTENER:
            if short.lower() in self.url.lower():
                self.shorteningWeight = 1
                return

        self.shorteningWeight = -1
        return

    def atSymbolTetsting(self):
        """
        test if the at symbol is in url
        :return: -1 or 1
        """
        if "@" in self.url:
            self.atWeight = 1
            return
        self.atWeight = -1
        return

    def doubleSlashTesting(self):
        """
        test if there is double slash in url
        :return: -1 or 1
        """
        if "//" in self.url:
            self.doubleSlashWeight = 1
            return
        self.doubleSlashWeight = -1
        return

    def dashTesting(self):
        """
            test if there is dash in url
            :return: -1 or 1
            """
        if "-" in self.url:
            self.dashWeight = 1
            return
        self.dashWeight = -1
        return

    def subDomainTesting(self):
        """
        test if there are too many subdomains
        :return: -1,0 or 1
        """
        if len(self.domain.split("www.")) == 2:
            domain = self.domain.split("www.")[1]
        else:
            domain = self.domain

        for tld in CCTLD:
            if re.match(("(.)*" + tld + "$"), str(domain)):
                domain = domain[:len(domain) - len(tld)]
                if domain.count('.') <= 1:
                    self.subDomainWeight = -1
                    return
                elif domain.count('.') == 2:
                    self.subDomainWeight = 0
                    return
                else:
                    self.subDomainWeight = 1
                    return
        if domain.count('.') <= 1:
            self.subDomainWeight = -1
            return
        elif domain.count('.') == 2:
            self.subDomainWeight = 0
            return
        else:
            self.subDomainWeight = 1
            return

    def ageCertificateTesting(self):
        """
        test if the certificate is not too young and delivered by a trusted issuer
        :return: -1,0 or 1
        """

        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=self.domain)
        try:
            s.connect((self.domain, 443))
            cert = s.getpeercert()
        except:

            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(socket.socket(), server_hostname=self.domain)
            try:
                s.connect((self.domain, 443))
                cert = s.getpeercert()
            except:
                self.certificateAgeWeight = 1
                return

        issuer = dict(x[0] for x in cert['issuer'])["organizationName"].lower()
        beginDate = datetime.datetime.strptime(cert["notBefore"].split(' GMT')[0], '%b  %d %H:%M:%S %Y')
        endDate = datetime.datetime.strptime(cert["notAfter"].split(' GMT')[0], '%b  %d %H:%M:%S %Y')

        delta = endDate - beginDate

        for trusted in TRUSTED_ISSUERS:
            if trusted in issuer:
                if delta.days >= 365:
                    self.certificateAgeWeight = -1
                    return

        self.certificateAgeWeight = 0
        return

    def expirationDomainTesting(self):
        """
        test if the valid duration of the domain is enough long
        :return: -1 or 1
        """
        if self.whoisDomain is not None:
            now = datetime.datetime.now()

            expiration = self.whoisDomain.expiration_date
            if type(expiration) == list:
                expiration = expiration[0]

            try:
                delta = expiration - now
            except:
                logger.error("error expiration domain testing")
                self.expirationWeight = 0
                return

            if delta.days > 365:
                self.expirationWeight = -1
                return
            else:
                self.expirationWeight = 1
                return
        else:
            self.expirationWeight = 1

    def faviconTesting(self):
        """
        test if the favicon url is from the same domain as the site
        :return: -1 or 1
        """

        soup = BeautifulSoup(self.html, features="lxml")
        head = soup.find("head")
        favicon = None
        if head is not None:
            favicon = head.find("link", {"rel": "icon"})

        if favicon is not None:
            linkFavicon = favicon.get("href")
            if self.domain not in linkFavicon:
                self.faviconWeight = 1
                return

        self.faviconWeight = -1
        return

    def portTesting(self):
        """
        test all important ports to check if they are opened or closed
        :return: -1 or 1 or error
        """

        try:
            try:
                remoteServerIP = socket.gethostbyname(self.domain)
            except socket.gaierror:
                remoteServerIP = socket.gethostbyname(self.url.split("/")[0].split(":")[0])

            for port in PORTS_TO_SCAN:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((remoteServerIP, port[0]))
                sock.close()

                if result == 0 and port[1] is False:
                    self.portWeight = 1
                    return
                elif result != 0 and port[1] is True:
                    self.portWeight = 1
                    return
            self.portWeight = -1
            return

        except Exception as e:
            logger.error(e)
            return -2

    def httpTesting(self):
        """
        test if there is the http token into the URL
        :return: -1 or 1
        """
        if "http" in self.url.lower():
            self.httpWeight = 1
            return

        self.httpWeight = -1
        return

    def requestedURL(self):
        """
        test the percentage of external objects
        :return: -1,0 or 1
        """

        totalLinks = 0
        externalLinks = 0

        m = []

        soup = BeautifulSoup(self.html, features="lxml")

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
            if self.domain not in link:
                if "http" in link or "www" in link:
                    externalLinks += 1
            totalLinks += 1

        if totalLinks != 0:
            percentage = externalLinks / totalLinks
            if percentage >= 0.61:
                self.requestedWeight = 1
                return
            elif percentage >= 0.22:
                self.requestedWeight = 0
                return

        self.requestedWeight = -1
        return

    def anchorsTesting(self):
        """
        test the percentage of external links anchors
        :return: -1,0 or 1
        """
        soup = BeautifulSoup(self.html, features="lxml")

        tags = soup.findAll("a", href=True)
        anchors = []
        for tag in tags:
            anchors.append(tag.get("href"))

        totalLink = len(anchors)
        externalLinks = 0

        for anchor in anchors:
            if self.domain not in anchor:
                if "www" in anchor or "http" in anchor:
                    externalLinks += 1

        if externalLinks == 0 or externalLinks / totalLink < 0.31:
            self.anchorsWeight = -1
            return

        elif externalLinks / totalLink <= 0.67:
            self.anchorsWeight = 0
            return

        self.anchorsWeight = 1
        return

    def tagsLinksTesting(self):
        """
        test the percentage of external links into meta, script and link tags
        :return: -1,0 or 1
        """
        totalLinks = 0
        externalLinks = 0

        m = []

        soup = BeautifulSoup(self.html, features="lxml")

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
            if self.domain not in link:
                externalLinks += 1
            totalLinks += 1

        if totalLinks != 0:
            percentage = externalLinks / totalLinks
            if percentage >= 0.81:
                self.tagWeight = 1
                return
            elif percentage >= 0.17:
                self.tagWeight = 0
                return

        self.tagWeight = -1
        return

    def SFHTesting(self):
        """
        test if the Server Form Handler of all forms is not suspicious
        :return: -1,0 or 1
        """
        soup = BeautifulSoup(self.html, features="lxml")

        for form in soup.find_all("form"):
            if str(form.get("action")) == "":
                self.SFHWeight = 1
                return

            elif str(form.get("action")) == "about:blank":
                self.SFHWeight = 1
                return

            elif self.domain not in str(form.get("action")) or "http" in str(form.get("action")) or "www" in str(
                    form.get("action")):
                self.SFHWeight = 0
                return
        self.SFHWeight = -1
        return

    def emailTesting(self):
        """
        test if no user's informations are send by email
        :return: -1 or 1
        """
        # soup = BeautifulSoup(html, features="lxml")

        if "mail(" in str(self.html).lower():
            self.emailWeight = 1
            return
        elif "mailto:" in str(self.html).lower():
            self.emailWeight = 1
            return
        self.emailWeight = -1
        return

    def abnormalURLTesting(self):
        """
        test if registrant name is in the url
        :return: -1 or 1
        """
        if self.whoisDomain is not None:
            domain = self.whoisDomain.domain.split(".")[0]
            if "org" in self.whoisDomain:
                if type(self.whoisDomain["org"]) == list:
                    for org in self.whoisDomain["org"]:
                        for suborg in re.split(". | ", org):
                            if suborg.lower() in domain.lower():
                                self.abnormalWeight = -1
                                return
                elif self.whoisDomain["org"] is not None:
                    for suborg in re.split(". | ", self.whoisDomain["org"]):
                        if suborg.lower() in domain.lower():
                            self.abnormalWeight = -1
                            return

            if "org1" in self.whoisDomain:
                if type(self.whoisDomain["org1"]) == list:
                    for org in self.whoisDomain["org1"]:
                        for suborg in re.split(". | ", org):
                            if suborg.lower() in domain.lower():
                                self.abnormalWeight = -1
                                return
                elif self.whoisDomain["org1"] is not None:
                    for suborg in re.split(". | ", self.whoisDomain["org1"]):
                        if suborg.lower() in domain.lower():
                            self.abnormalWeight = -1
                            return

        self.abnormalWeight = 1
        return

    def forwardingTesting(self):
        """
        test the number of forwarding
        :return: -1,0 or 1
        """
        try:
            countForward = len(requests.get(self.http + "://" + self.url).history)
        except requests.exceptions.ConnectionError:
            try:
                countForward = len(requests.get(self.http + "://" + self.url).history)
            except requests.exceptions.ConnectionError:
                return
        if countForward <= 1:
            self.forwardWeight = -1
            return

        if countForward < 4:
            self.forwardWeight = 0
            return

        self.forwardWeight = 1
        return

    def barCustomTesting(self):
        """
        Check if the status bar is not abnormally modify
        :return: -1 or 1
        """

        soup = BeautifulSoup(self.html, features="lxml")

        for tag in soup.find_all(onmouseover=True):
            if "window.status" in str(tag).lower():
                self.barCustomWeight = 1
                return
            else:
                self.barCustomWeight = 0
                return
        self.barCustomWeight = -1
        return

    def rightClickTesting(self):
        """
        test if the right click is not disabled
        :return: -1 or 1
        """

        if "contextmenu" in str(self.html).lower():
            self.rightClickWeight = 1
            return
        # if re.findall(r"addEventListener\(.{1,2}?contextmenu", str(html)) != []:
        #     return 1
        #
        # if re.findall(r"addEvent\(.{1,2}?contextmenu", str(html)) != []:
        #     return 1
        #
        # if re.findall(r"oncontextmenu", str(html)) != []:
        #     return 1

        # if re.findall(r"onmousedown", str(html)) != []:
        #     return 1
        #
        # if re.findall(r"MOUSEDOWN", str(html)) != []:
        #     return 1

        self.rightClickWeight = -1
        return

    def popUpTesting(self):
        """
        testing if popup with text fields
        :return: -1 or 1
        """
        prompt = re.findall(r"prompt\(", str(self.html)) + re.findall(r"confirm\(", str(self.html)) + re.findall(
            r"alert\(", str(self.html))
        if prompt != []:
            if len(prompt) > 4:
                self.popupWeight = 1
                return
            if len(prompt) > 2:
                self.popupWeight = 0
                return

        self.popupWeight = -1
        return

    def IFrameTesting(self):
        """
        testing if the site use Iframe
        :return: -1 or 1
        """

        soup = BeautifulSoup(self.html, features="lxml")

        for frame in soup.find_all("iframe"):
            if frame.get("src") is not None and self.domain not in frame.get("src"):
                if "www" in frame.get("src") or "http" in frame.get("src"):
                    self.iFrameWeight = 1
                    return

        self.iFrameWeight = -1
        return

        # if "iframe" in str(soup):
        #     return 1
        #
        # else:
        #     return -1

    def domainAgeTesting(self):
        """
        testing if domain age is greater than 6 months
        :return: -1, 0 or 1
        """
        if self.whoisDomain is not None:
            now = datetime.datetime.now()

            creation = self.whoisDomain.creation_date

            if type(creation) == list:
                creation = creation[0]
            try:
                delta = now - creation
            except:
                self.domainAgeWeight = 0
                return

            if delta.days > 365 / 2:
                self.domainAgeWeight = -1
                return
            else:
                self.domainAgeWeight = 1
                return
        else:
            self.domainAgeWeight = 1

    def DNSRecordTesting(self):
        """
        test if the domain is recorded in a DNS
        :return: -1 or 1
        """

        if len(self.domain.split("www.")) == 2:
            domain = self.domain.split("www.")[1]
        else:
            domain = self.domain

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
            self.dnsWeight = 1
            return

        if not empty:
            self.dnsWeight = -1
            return

        self.dnsWeight = 1
        return

    def trafficTesting(self):
        """
        collect the website rank on AWIS database and test if it is not abnormal
        :return: -1,0 or 1
        """
        try:
            soup = BeautifulSoup(requests.get("https://www.alexa.com/siteinfo/" + self.domain).content, features="lxml")
            tag = soup.find(id="card_rank").find("", {"class": "rank-global"}).find("", {"class": "big data"})
            rank = int("".join(re.findall('\d+', str(tag))))
        except AttributeError:
            self.trafficWeight = 1
            return

        if rank > 100000:
            self.trafficWeight = 0
            return

        self.trafficWeight = -1
        return

    def pageRankTesting(self):
        """
        Test the pagerank of the domain
        :return: -1 or 1
        """
        answer = requests.get("https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=" + self.domain,
                              headers={"API-OPR": "cswc0oc4wo0gs0ssgk044044wosc0ggwgoksocg8"})

        try:
            if answer.json()["response"][0]['page_rank_decimal'] <= 2:
                self.pageRankWeight = 1
                return
            else:
                self.pageRankWeight = -1
                return
        except (KeyError, TypeError):
            logger.error("domain pagerank not found")
            self.pageRankWeight = 1
            return

    def googleIndexTesting(self):
        """
        test if url is indexed by google
        :return: -1 or 1
        """
        index = googleIndexChecker.google_search("site:" + self.url)
        if index:
            self.indexingWeight = -1
            return
        self.indexingWeight = 1
        return
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
        # try:
        #     soup = BeautifulSoup(requests.get("https://www.ecosia.org/search?q=site%3A" + url, stream=False).content,
        #                          features="lxml")
        #     results = re.findall('\d+', soup.find("", {"class": "card-title card-title-result-count"}).text)
        #     if len(results) == 1 and results[0] == '0':
        #         return 1
        #     return -1
        # except Exception as e:
        #     print(e)
        #     pass

    def linksPointingToTesting(self):
        """
        collect the count of all sites which linked to the url on AWIS database and test if it is not abnormal
        :return: -1,0 or 1
        """
        soup = BeautifulSoup(requests.get("https://www.alexa.com/siteinfo/" + self.url).content, features="lxml")
        try:
            countLinks = int(
                "".join(soup.find("", {"class": "linksin"}).find("", {"class": "big data"}).get_text().split(",")))
        except AttributeError:
            self.linksWeight = 1
            return
        if countLinks == 0:
            self.linksWeight = 1
            return
        elif countLinks <= 2:
            self.linksWeight = 0
            return

        self.linksWeight = -1
        return

    def statisticReportTEsting(self):
        """
        test if the ip address of the domain is in top 50 of www.stopbadware.org
        :return: -1 or 1
        """
        try:
            IPdomain = socket.gethostbyname(self.domain)
        except socket.gaierror:
            self.statisticWeight = -1
            return

        jsonDictIP = json.loads(
            requests.post("https://www.stopbadware.org/sites/all/themes/sbw/clearinghouse.php",
                          data={'q': 'tops'}).text)

        IPList = []

        for site in jsonDictIP['top_ip']:
            IPList.append(socket.inet_ntoa(struct.pack('!L', int(site['ip_addr']))))

        for ip in IPList:
            if ip == IPdomain:
                self.statisticWeight = 1
                return

        self.statisticWeight = -1
        return

    def featuresExtraction(self):
        """
        Extract all features and set the values into the attribute weights
        :param queue: queue
        :return: -1,-1, None or results into queue
        """
        features = []

        logger.info("Testing : " + self.url)

        # testing ip adress
        self.IPtesting()
        features.append(self.ipWeight)

        # testing lenght of the url
        self.leghtTesting()
        features.append(self.lenghtWeight)

        # testing shortener url
        self.shortenerTEsting()
        features.append(self.shorteningWeight)

        # testing at symbol
        self.atSymbolTetsting()
        features.append(self.atWeight)

        # testing double slash
        self.doubleSlashTesting()
        features.append(self.doubleSlashWeight)

        # testing dash
        self.dashTesting()
        features.append(self.dashWeight)

        # testing subdomain count
        self.subDomainTesting()
        features.append(self.subDomainWeight)

        # testing age of the domain certificate
        if self.http == "https":
            self.ageCertificateTesting()
            features.append(self.certificateAgeWeight)
        else:
            self.certificateAgeWeight = 1
            features.append(1)

        # testing expiration date of domain
        self.expirationDomainTesting()
        features.append(self.expirationWeight)
        if features[-1] == -2:
            return -1
        # testing favicon href
        self.faviconTesting()
        features.append(self.faviconWeight)

        # testing ports
        self.portTesting()
        features.append(self.portWeight)

        if features[-1] == -2:
            logger.error("port testing error")
            return -1

        # testing http token
        self.httpTesting()
        features.append(self.httpWeight)

        # testing request URL
        self.requestedURL()
        features.append(self.requestedWeight)

        # testing anchors
        self.anchorsTesting()
        features.append(self.anchorsWeight)

        # testing tags links
        self.tagsLinksTesting()
        features.append(self.tagWeight)

        # testing SFH
        self.SFHTesting()
        features.append(self.SFHWeight)

        # testing email
        self.emailTesting()
        features.append(self.emailWeight)

        # testing abnormal url
        self.abnormalURLTesting()
        features.append(self.abnormalWeight)

        # testing forwarding
        self.forwardingTesting()
        features.append(self.forwardWeight)

        # testing abnormal status bar
        self.barCustomTesting()
        features.append(self.barCustomWeight)

        # testing right click disabling
        self.rightClickTesting()
        features.append(self.rightClickWeight)

        # testing popup
        self.popUpTesting()
        features.append(self.popupWeight)

        # testing IFrame
        self.IFrameTesting()
        features.append(self.iFrameWeight)

        # testing domain age
        self.domainAgeTesting()
        features.append(self.domainAgeWeight)
        if features[-1] == -2:
            return -1

        # testing DNS record
        self.DNSRecordTesting()
        features.append(self.dnsWeight)

        # testing traffic
        self.trafficTesting()
        features.append(self.trafficWeight)

        # testing page rank
        self.pageRankTesting()
        features.append(self.pageRankWeight)

        # testo google indexing
        self.googleIndexTesting()
        features.append(self.indexingWeight)

        if features[-1] == -2:
            return -2

        # testing links pointing to the webpage
        self.linksPointingToTesting()
        features.append(self.linksWeight)

        # testing statistics
        self.statisticReportTEsting()
        features.append(self.statisticWeight)

        return features

    def getFeatures(self):
        """
        Get all features
        :return: list
        """
        return ([self.ipWeight, self.lenghtWeight, self.shorteningWeight, self.atWeight, self.doubleSlashWeight,
                 self.dashWeight, self.subDomainWeight, self.certificateAgeWeight, self.expirationWeight,
                 self.faviconWeight, self.portWeight, self.httpWeight, self.requestedWeight, self.anchorsWeight,
                 self.tagWeight, self.SFHWeight, self.emailWeight, self.abnormalWeight, self.forwardWeight,
                 self.barCustomWeight, self.rightClickWeight, self.popupWeight, self.iFrameWeight, self.domainAgeWeight,
                 self.dnsWeight, self.trafficWeight, self.pageRankWeight, self.indexingWeight, self.linksWeight,
                 self.statisticWeight])

    def setFeatures(self, features):
        """
        Set the features from a list
        :param features: list
        :return: nothing
        """
        if type(features) is not list or len(features) != 30:
            logger.error("Bad argument for features setter")
            return
        self.ipWeight = features[0]
        self.lenghtWeight = features[1]
        self.shorteningWeight = features[2]
        self.atWeight = features[3]
        self.doubleSlashWeight = features[4]
        self.dashWeight = features[5]
        self.subDomainWeight = features[6]
        self.certificateAgeWeight = features[7]
        self.expirationWeight = features[8]
        self.faviconWeight = features[9]
        self.portWeight = features[10]
        self.httpWeight = features[11]
        self.requestedWeight = features[12]
        self.anchorsWeight = features[13]
        self.tagWeight = features[14]
        self.SFHWeight = features[15]
        self.emailWeight = features[16]
        self.abnormalWeight = features[17]
        self.forwardWeight = features[18]
        self.barCustomWeight = features[19]
        self.rightClickWeight = features[20]
        self.popupWeight = features[21]
        self.iFrameWeight = features[22]
        self.domainAgeWeight = features[23]
        self.dnsWeight = features[24]
        self.trafficWeight = features[25]
        self.pageRankWeight = features[26]
        self.indexingWeight = features[27]
        self.linksWeight = features[28]
        self.statisticWeight = features[29]
        return


def extraction(inputFile, output, begin=1):
    """
    Used to extract features from a csv file
    :param inputFile: str (path)
    :param output: str
    :param begin: int
    :return: nothing
    """
    failledURLS = []
    notReacheable = []

    # First try with all URLs
    count = 1
    begin = begin
    with open(inputFile, newline='', encoding='utf-8') as csvinfile:
        # Load URLs from csv file
        for row in csv.reader(csvinfile, delimiter=',', quotechar='|'):
            logger.info("first round: " + str(count))
            website = URL(row[0])
            if count >= begin:
                try:
                    # Extract features
                    results = func_timeout(50, website.featuresExtraction)
                    logger.debug(results)
                    if results == -1:
                        notReacheable.append(results)
                    elif results == -2:
                        failledURLS.append(row[0])
                    else:
                        # Write results in the right place
                        if output != "console":
                            with open(output, 'a', newline='') as outcsvfile:
                                writer = csv.writer(outcsvfile, delimiter=',', quotechar='"')
                                writer.writerow([row[0]] + results)
                        else:
                            logger.debug([row[0]] + results)

                except Exception as e:
                    failledURLS.append(row[0])
                    logger.info(e)
            count += 1

    realfailledURLS = []

    # Second try with URLs which failed due to timeout
    count = 1
    for url in failledURLS:
        logger.info("second round" + str(count))
        count += 1
        website = URL(url)

        # Extract features
        try:
            results = func_timeout(90, website.featuresExtraction)
            if results == -1:
                notReacheable.append(results)
            else:
                # Write results in the right place
                if output != "console":
                    with open(output, 'a', newline='') as outcsvfile:
                        writer = csv.writer(outcsvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                        writer.writerow([url] + results)
                else:
                    logger.debug([url] + results)
        except:
            realfailledURLS.append(url)

    # Write failed URLs in the right place
    if output != "console":
        with open(output, 'a', newline='') as outcsvfile:
            writer = csv.writer(outcsvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            for fail in realfailledURLS:
                writer.writerow(fail)
    else:
        for fail in realfailledURLS:
            logger.error("Urls failed" + str(fail))
