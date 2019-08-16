"""
File used to modelize URLs for phishing detection
-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
Copyright (c) 2019 Khuzd
"""
import csv
import datetime
import json
import logging
import pickle
import re
import socket
import ssl
import struct
from binascii import Error as hexErr
from binascii import hexlify, unhexlify

import dns.resolver
import requests
import socks
from bs4 import BeautifulSoup
from func_timeout import func_timeout, FunctionTimedOut
from myawis import CallAwis
from publicsuffixlist import PublicSuffixList

import databaseManage
import googleApi
from libs.whois import whois
from libs.whois.parser import PywhoisError

# Import logger
logger = logging.getLogger('phishGan')

# ---------------------
#  Set constants
# ---------------------

URL_SHORTENER = ["shrinkee.com", "goo.gl", "7.ly", "adf.ly", "admy.link", "al.ly", "bc.vc", "bit.do", "doiop.com",
                 "ity.im", "url.ie", "is.gd", "linkmoji.co", "sh.dz24.info", "lynk.my", "mcaf.ee", "yep.it", "ow.ly",
                 "x61.ch", "qr.net", "shrinkee.com", "u.to", "ho.io", "thinfi.com", "tiny.cc", "tinyurl.com", "tny.im",
                 "flic.krp", "v.gd", "y2u.be", "cutt.us", "zzb.bz", "adfoc.us", "bit.ly", "cur.lv", "git.io", "hec.su",
                 "viid.me", "tldrify.com", "tr.im", "link.do"]

PORTS_TO_SCAN = [(21, False), (22, False), (23, False), (80, True), (443, True), (445, False), (1433, False),
                 (1521, False), (3306, False), (3389, False)]

TRUSTED_ISSUERS = ["geotrust", "godaddy", "network solutions", "thawte", "comodo", "doster", "verisign", "symantec",
                   "rapidssl", "digicert", "google", "let's encrypt", "comodo ca limited", "cloudflare", "microsoft"]


class website:
    """
    URL Class to store all informations about a website
    """

    def __init__(self, url, manualInit=False):
        # ---------------------
        #  Define attributes
        # ---------------------
        self.http = None
        self.url = url
        self.domain = None
        self.whoisDomain = None
        self.html = None
        self.hostname = None
        self.certificate = None
        self.soup = None
        self.amazonAlexa = None
        self.pageRank = None
        self.redirectCount = None

        # ---------------------
        #  Calculate attributes
        # ---------------------

        # http, url and domain attributes
        if not manualInit:

            if "http://" in url[:7]:
                self.http = "http"
                self.url = url[7:]

            elif "https://" in url[:8]:
                self.http = "https"
                self.url = url[8:]
            else:
                self.http = ""

            self.hostname = self.url.split("/")[0].split(":")[0]
            self.domain = self.hostname

            # whoisDomain attribute
            retry = True
            while retry:  # to retry if whois database kick us
                try:
                    retry = False
                    self.whoisDomain = func_timeout(30, whois, kwargs={'Url': str(self.domain)})

                except (PywhoisError, socket.gaierror, socks.GeneralProxyError):
                    logger.error("URL : " + self.domain + " not in whois database")
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

            # get domain from whois
            if self.whoisDomain is not None:
                self.domain = self.whoisDomain.domain

            # get certificate
            if self.http == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(socket.socket(), server_hostname=self.hostname)
                try:
                    s.connect((self.hostname, 443))
                    self.certificate = s.getpeercert()
                except:

                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(socket.socket(), server_hostname=self.hostname)
                    try:
                        s.connect((self.hostname, 443))
                        self.certificate = s.getpeercert()
                    except:
                        self.certificate = None

            # Get PageRank
            try:
                self.pageRank = \
                    requests.get("https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=" + self.domain,
                                 headers={"API-OPR": open("api_keys/openPageRank_key.txt").read()}).json()[
                        "response"][0]['page_rank_decimal']
            except:
                logger.error("domain pagerank not found")
                self.pageRank = 0

            # Get AWIS Alexa information
            self.amazonAlexa = CallAwis(open("api_keys/awis_access_id.txt").read(),
                                        open("api_keys/awis_secret_access_key.txt").read()).urlinfo(self.domain)

        # Weights
        self.ipWeight = "error"
        self.lengthWeight = "error"
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
        self.subDomainLengthWeight = "error"
        self.wwwWeight = "error"
        self.validTldWeight = "error"
        self.singleCharacterSubDomainWeight = "error"
        self.exclusivePrefixRepetitionWeight = "error"
        self.tldSubDomainWeight = "error"
        self.ratioDigitSubDomainWeight = "error"
        self.ratioHexaSubDomainWeight = "error"
        self.underscoreWeight = "error"
        self.containDigitWeight = "error"
        self.vowelRatioWeight = "error"
        self.ratioDigitWeight = "error"
        self.alphabetCardinalityWeight = "error"
        self.ratioRepeatedCharacterWeight = "error"
        self.ratioConsecutiveConsonantWeight = "error"
        self.ratioConsecutiveDigitWeight = "error"

        # ScaledWeights
        self.lengthScaledWeight = "error"
        self.dashScaledWeight = "error"
        self.subDomainScaledWeight = "error"
        self.certificateAgeScaledWeight = "error"
        self.expirationScaledWeight = "error"
        self.requestedScaledWeight = "error"
        self.anchorsScaledWeight = "error"
        self.tagScaledWeight = "error"
        self.SFHScaledWeight = "error"
        self.popupScaledWeight = "error"
        self.domainAgeScaledWeight = "error"
        self.trafficScaledWeight = "error"
        self.pageRankScaledWeight = "error"
        self.linksScaledWeight = "error"
        self.subDomainLengthScaledWeight = "error"
        self.ratioDigitSubDomainScaledWeight = "error"
        self.ratioHexaSubDomainScaledWeight = "error"
        self.underscoreScaledWeight = "error"
        self.vowelRatioScaledWeight = "error"
        self.ratioDigitScaledWeight = "error"
        self.alphabetCardinalityScaledWeight = "error"
        self.ratioRepeatedCharacterScaledWeight = "error"
        self.ratioConsecutiveConsonantScaledWeight = "error"
        self.ratioConsecutiveDigitScaledWeight = "error"

    # ---------------------
    #  Classic weights calculation
    # ---------------------
    def ip_testing(self):
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
            self.ipWeight = 0
            return

    def length_testing(self):
        """
        test if url length is <54, between 54 and 75 or over 75
        :return: -1,0 or 1
        """

        if len(self.hostname) < 15:
            self.lengthWeight = 0
            return
        elif 15 <= len(self.hostname) < 19:
            self.lengthWeight = 0.5
            return
        else:
            self.lengthWeight = 1
            return

    def shortener_testing(self):
        """
        test if the url is a short url
        :return: -1 or 1
        """
        for short in URL_SHORTENER:
            if short.lower() in self.url.lower():
                self.shorteningWeight = 1
                return

        self.shorteningWeight = 0
        return

    def at_symbol_testing(self):
        """
        test if the at symbol is in url
        :return: -1 or 1
        """
        if "@" in self.url:
            self.atWeight = 1
            return
        self.atWeight = 0
        return

    def double_slash_testing(self):
        """
        test if there is double slash in url
        :return: -1 or 1
        """
        if "//" in self.url:
            self.doubleSlashWeight = 1
            return
        self.doubleSlashWeight = 0
        return

    def dash_testing(self):
        """
            test if there is dash in url
            :return: -1 or 1
            """
        if "-" in self.url:
            self.dashWeight = 1
            return
        self.dashWeight = 0
        return

    def sub_domain_testing(self):
        """
        test if there are too many subdomains
        :return: -1,0 or 1
        """
        psl = PublicSuffixList()
        psl.accept_unknown = False
        domain = self.hostname
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        if domain.count('.') <= 1:
            self.subDomainWeight = 0
            return
        elif domain.count('.') == 2:
            self.subDomainWeight = 0.5
            return
        else:
            self.subDomainWeight = 1
            return

    def age_certificate_testing(self):
        """
        test if the certificate is not too young and delivered by a trusted issuer
        :return: -1,0 or 1
        """

        issuer = dict(x[0] for x in self.certificate['issuer'])["organizationName"].lower()
        beginDate = datetime.datetime.strptime(self.certificate["notBefore"].split(' GMT')[0], '%b  %d %H:%M:%S %Y')
        endDate = datetime.datetime.strptime(self.certificate["notAfter"].split(' GMT')[0], '%b  %d %H:%M:%S %Y')

        delta = endDate - beginDate

        for trusted in TRUSTED_ISSUERS:
            if trusted in issuer:
                if delta.days >= 365:
                    self.certificateAgeWeight = 0
                    return

        self.certificateAgeWeight = 0.5
        return

    def expiration_domain_testing(self):
        """
        test if the valid duration of the domain is enough long
        :return: -1, 0 or 1
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
                self.expirationWeight = 0.5
                return

            if delta.days > 330:
                self.expirationWeight = 0
                return
            else:
                self.expirationWeight = 1
                return
        else:
            self.expirationWeight = 1

    def favicon_testing(self):
        """
        test if the favicon url is from the same domain as the site
        :return: -1 or 1
        """

        head = self.soup.find("head")
        favicon = None
        if head is not None:
            favicon = head.find("link", {"rel": "icon"})

        if favicon is not None:
            linkFavicon = favicon.get("href")
            if linkFavicon is not None and self.domain not in linkFavicon:
                self.faviconWeight = 1
                return

        self.faviconWeight = 0
        return

    def port_testing(self):
        """
        test all important ports to check if they are opened or closed
        :return: -1 or 1 or error
        """

        try:
            try:
                remoteServerIP = socket.gethostbyname(self.hostname)
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
            self.portWeight = 0
            return

        except Exception as e:
            logger.error(e)
            return -2

    def http_testing(self):
        """
        test if there is the http token into the URL
        :return: -1 or 1
        """
        if "http" in self.url.lower():
            self.httpWeight = 1
            return

        self.httpWeight = 0
        return

    def requested_url_testing(self):
        """
        test the percentage of external objects
        :return: -1,0 or 1
        """

        totalLinks = 0
        externalLinks = 0

        m = []

        for p in self.soup.find_all("img"):
            if p.has_attr("src") and "http" in p.get("src")[:4]:
                m.append(p.get('src'))

        for p in self.soup.find_all("video"):
            for q in p.find_all("source"):
                if q.has_attr("src") and "http" in q.get("src")[:4]:
                    m.append(q.get('src'))

        for p in self.soup.find_all("audio"):
            for q in p.find_all("source"):
                if q.has_attr("src") and "http" in q.get("src")[:4]:
                    m.append(q.get('src'))

        for link in m:
            if self.domain not in link:
                externalLinks += 1
            totalLinks += 1

        if totalLinks != 0:
            percentage = externalLinks / totalLinks
            if percentage >= 0.61:
                self.requestedWeight = 1
                return
            elif percentage >= 0.22:
                self.requestedWeight = 0.5
                return

        self.requestedWeight = 0
        return

    def anchors_testing(self):
        """
        test the percentage of external links anchors
        :return: -1,0 or 1
        """

        tags = self.soup.findAll("a", href=True)
        anchors = []
        for tag in tags:
            anchors.append(tag.get("href"))

        totalLink = len(anchors)
        externalLinks = 0

        for anchor in anchors:
            if self.domain not in anchor and "http":
                if "www" in anchor[:3] or "http" in anchor[:4]:
                    externalLinks += 1

        if externalLinks == 0 or externalLinks / totalLink < 0.31:
            self.anchorsWeight = 0
            return

        elif externalLinks / totalLink <= 0.67:
            self.anchorsWeight = 0.5
            return

        self.anchorsWeight = 1
        return

    def tags_links_testing(self):
        """
        test the percentage of external links into meta, script and link tags
        :return: -1,0 or 1
        """
        totalLinks = 0
        externalLinks = 0

        m = []

        meta = self.soup.find_all("meta")
        links = self.soup.find_all("link")
        scripts = self.soup.find_all("script")

        for tag in meta:
            for link in re.findall(re.compile("\"http.*?\""), str(tag)):
                m.append(link)

        for tag in links:
            if tag.has_attr("href") and "http" in tag.get("href")[:4]:
                m.append(tag.get("href"))

        for tag in scripts:
            if tag.has_attr("href") and "http" in tag.get("href")[:4]:
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
            elif percentage >= 0.05:
                self.tagWeight = 0.5
                return

        self.tagWeight = 0
        return

    def sfh_testing(self):
        """
        test if the Server Form Handler of all forms is not suspicious
        :return: -1,0 or 1
        """

        for form in self.soup.find_all("form"):
            if str(form.get("action")) == "":
                self.SFHWeight = 1
                return

            elif str(form.get("action")) == "about:blank":
                self.SFHWeight = 1
                return

            elif self.domain not in str(form.get("action")) and ("http" in str(form.get("action")) or "www" in str(
                    form.get("action"))):
                self.SFHWeight = 0.5
                return
        self.SFHWeight = 0
        return

    def email_testing(self):
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
        self.emailWeight = 0
        return

    def abnormal_url_testing(self):
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
                                self.abnormalWeight = 0
                                return
                elif self.whoisDomain["org"] is not None:
                    for suborg in re.split(". | ", self.whoisDomain["org"]):
                        if suborg.lower() in domain.lower():
                            self.abnormalWeight = 0
                            return

            if "org1" in self.whoisDomain:
                if type(self.whoisDomain["org1"]) == list:
                    for org in self.whoisDomain["org1"]:
                        for suborg in re.split(". | ", org):
                            if suborg.lower() in domain.lower():
                                self.abnormalWeight = 0
                                return
                elif self.whoisDomain["org1"] is not None:
                    for suborg in re.split(". | ", self.whoisDomain["org1"]):
                        if suborg.lower() in domain.lower():
                            self.abnormalWeight = 0
                            return

        self.abnormalWeight = 1
        return

    def forwarding_testing(self):
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
            self.forwardWeight = 0
            return

        if countForward < 4:
            self.forwardWeight = 0.5
            return

        self.forwardWeight = 1
        return

    def bar_custom_testing(self):
        """
        Check if the status bar is not abnormally modify
        :return: -1, 0 or 1
        """

        for tag in self.soup.find_all(onmouseover=True):
            if "window.status" in str(tag).lower():
                self.barCustomWeight = 1
                return
            else:
                self.barCustomWeight = 0.5
                return
        self.barCustomWeight = 0
        return

    def right_click_testing(self):
        """
        test if the right click is not disabled
        :return: -1 or 1
        """

        if "contextmenu" in str(self.html).lower():
            self.rightClickWeight = 1
            return

        self.rightClickWeight = 0

    def popup_testing(self):
        """
        testing if popup with text fields
        :return: -1, 0 or 1
        """
        prompt = re.findall(r"prompt\(", str(self.html)) + re.findall(r"confirm\(", str(self.html)) + re.findall(
            r"alert\(", str(self.html))
        if prompt:
            if len(prompt) > 3:
                self.popupWeight = 1
                return
            if len(prompt) >= 1:
                self.popupWeight = 0.5
                return

        self.popupWeight = 0

    def iframe_testing(self):
        """
        testing if the site use Iframe
        :return: -1 or 1
        """

        for frame in self.soup.find_all("iframe"):
            if frame.get("src") is not None and self.domain not in frame.get("src"):
                if "www" in frame.get("src") or "http" in frame.get("src"):
                    self.iFrameWeight = 1
                    return

        self.iFrameWeight = 0

    def domain_age_testing(self):
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
                self.domainAgeWeight = 0.5
                return

            if delta.days > 1095:
                self.domainAgeWeight = 0
                return
            elif delta.days > 365:
                self.domainAgeWeight = 0.5
                return
            else:
                self.domainAgeWeight = 1
                return
        else:
            self.domainAgeWeight = 1

    def dns_record_testing(self):
        """
        test if the domain is recorded in a DNS
        :return: -1 or 1
        """

        if len(self.hostname.split("www.")) == 2:
            domain = self.hostname.split("www.")[1]
        else:
            domain = self.hostname

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
            self.dnsWeight = 0
            return

        self.dnsWeight = 1

    def traffic_testing(self):
        """
        collect the website rank on AWIS database and test if it is not abnormal
        :return: -1,0 or 1
        """
        try:
            soup = BeautifulSoup(self.amazonAlexa, features="lxml")
            rank = int(soup.find("aws:trafficdata").find("aws:rank").contents[0])
        except (AttributeError, IndexError):
            try:
                soup = BeautifulSoup(requests.get("https://www.alexa.com/siteinfo/" + self.domain).content,
                                     features="lxml")
                tag = soup.find(id="card_rank").find("", {"class": "rank-global"}).find("", {"class": "big data"})
                rank = int("".join(re.findall('\d+', str(tag))))
            except(AttributeError, IndexError):
                self.trafficWeight = 1
                return

        if rank > 100000:
            self.trafficWeight = 0.5
            return

        self.trafficWeight = 0

    def page_rank_testing(self):
        """
        Test the pagerank of the domain
        :return: -1 or 1
        """

        if self.pageRank <= 2:
            self.pageRankWeight = 1
            return
        elif self.pageRank <= 4:
            self.pageRankWeight = 0.5
        else:
            self.pageRankWeight = 0
            return

    def google_index_testing(self):
        """
        test if url is indexed by google
        :return: -1 or 1
        """
        index = googleApi.google_search("site:" + self.url)
        if index:
            self.indexingWeight = 0
            return
        self.indexingWeight = 1

    def links_pointing_to_testing(self):
        """
        collect the count of all sites which linked to the url on AWIS database and test if it is not abnormal
        :return: -1,0 or 1
        """
        soup = BeautifulSoup(self.amazonAlexa, features="lxml")
        try:
            countLinks = int(soup.find("aws:linksincount").contents[0])
        except (AttributeError, IndexError):
            try:
                soup = BeautifulSoup(requests.get("https://www.alexa.com/siteinfo/" + self.url).content,
                                     features="lxml")
                countLinks = int(
                    "".join(soup.find("", {"class": "linksin"}).find("", {"class": "big data"}).get_text().split(",")))
            except(AttributeError, IndexError):
                self.linksWeight = 1
                return
        if countLinks < 5:
            self.linksWeight = 1
            return
        elif countLinks < 30:
            self.linksWeight = 0.5
            return

        self.linksWeight = 0

    def statistic_report_testing(self):
        """
        test if the ip address of the domain is in top 50 of www.stopbadware.org
        :return: -1 or 1
        """
        try:
            IPdomain = socket.gethostbyname(self.hostname)
        except socket.gaierror:
            self.statisticWeight = 0
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

        self.statisticWeight = 0

    def sub_domain_length_testing(self):
        """
        Use to calculate the weight of the mean of lengh subdomains
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        subdomains = domain.split(".")
        total = 0
        for subdomain in subdomains:
            total += len(subdomain)

        if total / len(subdomains) > 15:
            self.subDomainLengthWeight = 1
            return
        elif total / len(subdomains) > 9:
            self.subDomainLengthWeight = 0.5
            return

        self.subDomainLengthWeight = 0

    def www_testing(self):
        """
        test if www is at the beginning of url
        :return:
        """
        if "www" in self.url[:11]:
            self.wwwWeight = 0
            return
        self.wwwWeight = 1

    def valid_tld_testing(self):
        """
        test if the tld of url is valid
        :return:
        """
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if psl.publicsuffix(self.hostname) is None:
            self.validTldWeight = 1
            return
        self.validTldWeight = 0

    def single_character_sub_domain_testing(self):
        """
        test if there is a single character subdomain
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        subdomains = domain.split(".")
        for subdomain in subdomains:
            if len(subdomain) == 1:
                self.singleCharacterSubDomainWeight = 1
                return
        self.singleCharacterSubDomainWeight = 0

    def exclusive_prefix_repetition_testing(self):
        """
        test if the domain is a repetition of a prefix
        :return:
        """
        domain = self.hostname
        repeat = list(filter(None, domain.split(domain.split(".")[-1])))
        if len(repeat) == 1:
            self.exclusivePrefixRepetitionWeight = 0
            return
        else:
            for test in repeat:
                if test != repeat[0]:
                    self.exclusivePrefixRepetitionWeight = 0
                    return
        self.exclusivePrefixRepetitionWeight = 1

    def tld_sub_domain_testing(self):
        """
        test if there is a subdomain which is a tld
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        subdomains = domain.split(".")

        for subdomain in subdomains:
            if psl.publicsuffix("x." + subdomain) is not None:
                self.tldSubDomainWeight = 1
                return
        self.tldSubDomainWeight = 0

    def ratio_digit_sub_domain_testing(self):
        """
        Used to test the ratio of exclusive digits subdomains
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        subdomains = domain.split(".")

        exclusiveDigit = 0

        for subdomain in subdomains:
            if sum(list(map(lambda x: 1 if x.isdigit() else 0, subdomain))) == len(subdomain):
                exclusiveDigit += 1

        if exclusiveDigit / len(subdomains) != 0:
            self.ratioDigitSubDomainWeight = 1
            return
        self.ratioDigitSubDomainWeight = 0

    def ratio_hexa_sub_domain_testing(self):
        """
        Used to test the ratio of exclusive hexadecimal subdomains
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        subdomains = domain.split(".")

        exclusiveHex = 0

        for subdomain in subdomains:
            try:
                hexlify(unhexlify(subdomain))
                exclusiveHex += 1
            except hexErr:
                pass
        if exclusiveHex / len(subdomains) != 0:
            self.ratioHexaSubDomainWeight = 1
            return
        self.ratioHexaSubDomainWeight = 0

    def underscore_testing(self):
        """
        Used to test the ratio of underscore in domain
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        if domain.count("_") / len(domain) > 0:
            self.underscoreWeight = 1
            return
        self.underscoreWeight = 0

    def contain_digit_testing(self):
        """
        test if domain contain digit
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        if sum(list(map(lambda x: 1 if x.isdigit() else 0, domain))) != 0:
            self.containDigitWeight = 1
            return
        self.containDigitWeight = 0

    def vowel_ratio_testing(self):
        """
        Used to test vowel ratio in domain
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")
        if 0.27 < sum(map(lambda x: 1 if x in ["a", "e", "i", "o", "u", "y"] else 0, domain)) / len(domain):
            self.vowelRatioWeight = 0
            return
        self.vowelRatioWeight = 1

    def ratio_digit_testing(self):
        """
        Used to test ratio of digit in domain
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")
        if sum(list(map(lambda x: 1 if x.isdigit() else 0, domain))) / len(domain) > 0:
            self.ratioDigitWeight = 1
            return
        self.ratioDigitWeight = 0

    def alphabet_cardinality_testing(self):
        """
        Used to test alphabet cardinality of domain
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")

        if sum(list(map(lambda x: 1 if x.isalpha() else 0, domain))) > 14:
            self.alphabetCardinalityWeight = 1
            return
        elif sum(list(map(lambda x: 1 if x.isalpha() else 0, domain))) > 11:
            self.alphabetCardinalityWeight = 0.5
            return
        self.alphabetCardinalityWeight = 0

    def ratio_repeated_character_testing(self):
        """
        Used to test the ratio of repeated characters in domain
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")
        card = sum(list(map(lambda x: 1 if x.isalpha() else 0, domain)))
        if card in [None, 0, "error"] or type(card) is not int:
            self.ratioRepeatedCharacterWeight = 1
            return

        setDomain = list(set(domain))
        countRepeated = 0

        for character in setDomain:
            if domain.count(character) > 1:
                countRepeated += 1

        if countRepeated / card > 0.17:
            self.ratioRepeatedCharacterWeight = 1
            return
        self.ratioRepeatedCharacterWeight = 0

    def ratio_consecutive_consonant_testing(self):
        """
        Used to test the ratio of consecutive consonants in domain
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")
        replaced = ""
        for i in range(len(domain)):
            if domain[i].isalpha():
                replaced += domain[i]
            else:
                replaced += "a"

        replaced = re.split("[aeiouy]", replaced)

        countConsecutive = 0
        for splitted in replaced:
            if len(splitted) > 1:
                countConsecutive += len(splitted)

        if countConsecutive / len(domain) > 0.05:
            self.ratioConsecutiveConsonantWeight = 1
            return
        self.ratioConsecutiveConsonantWeight = 0

    def ratio_consecutive_digit_testing(self):
        """
        Used to test the ratio of consecutive digits in domain
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")
        replaced = ""
        for i in range(len(domain)):
            if domain[i].isdigit():
                replaced += domain[i]
            else:
                replaced += "a"

        replaced = replaced.split("a")

        countConsecutive = 0
        for splitted in replaced:
            if len(splitted) > 1:
                countConsecutive += len(splitted)

        if countConsecutive / len(domain) > 0.01:
            self.ratioConsecutiveDigitWeight = 1
            return
        self.ratioConsecutiveDigitWeight = 0

    # ---------------------
    #  Scaled weights calculation
    # ---------------------
    def length_scaled_calculation(self, normDict):
        """
        Get the length of hostname, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """

        norm = pickle.loads(normDict["url_length"]["normalizer"])
        scaler = pickle.loads(normDict["url_length"]["scaler"])

        result = norm.transform([[len(self.hostname)]])
        self.lengthScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def dash_scaled_calculation(self, normDict):
        """
        Count how many there are dash symbol in url, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["dash"]["normalizer"])
        scaler = pickle.loads(normDict["dash"]["scaler"])

        result = norm.transform([[self.url.count("-")]])
        self.dashScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def sub_domain_scaled_calculation(self, normDict):
        """
        Count the subdomains, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["sub_domain"]["normalizer"])
        scaler = pickle.loads(normDict["sub_domain"]["scaler"])

        psl = PublicSuffixList()
        psl.accept_unknown = False
        domain = self.hostname

        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        result = norm.transform([[domain.count(".")]])
        self.subDomainScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def age_certificate_scaled_calculation(self, normDict):
        """
        Get the duration of the ssl certificate, test if delivered by a trusted issuer, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["age_certificate"]["normalizer"])
        scaler = pickle.loads(normDict["age_certificate"]["scaler"])

        issuer = dict(x[0] for x in self.certificate['issuer'])["organizationName"].lower()
        beginDate = datetime.datetime.strptime(self.certificate["notBefore"].split(' GMT')[0], '%b  %d %H:%M:%S %Y')
        endDate = datetime.datetime.strptime(self.certificate["notAfter"].split(' GMT')[0], '%b  %d %H:%M:%S %Y')

        delta = endDate - beginDate

        isTrusted = False
        for trusted in TRUSTED_ISSUERS:
            if trusted in issuer:
                isTrusted = True

        if isTrusted:
            lentgh = delta.days * 2
        else:
            lentgh = delta.days

        result = norm.transform([[lentgh]])
        self.certificateAgeScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def expiration_domain_scaled_calculation(self, normDict):
        """
        Get the duration to expiration of the domain name, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["expiration_domain"]["normalizer"])
        scaler = pickle.loads(normDict["expiration_domain"]["scaler"])

        if self.whoisDomain is not None:
            now = datetime.datetime.now()

            expiration = self.whoisDomain.expiration_date
            if type(expiration) == list:
                expiration = expiration[0]

            try:
                delta = expiration - now
            except:
                logger.error("error expiration domain testing")
                self.expirationScaledWeight = 0.5
                return

            if delta.days < 0:
                result = norm.transform([[0]])
            else:
                result = norm.transform([[delta.days]])
            self.expirationScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def requested_url_scaled_calculation(self):
        """
        Get the proportion of external url requested
        :return: float between 0 and 1
        """

        totalLinks = 0
        externalLinks = 0

        m = []

        for p in self.soup.find_all("img"):
            if p.has_attr("src") and "http" in p.get("src")[:4]:
                m.append(p.get('src'))

        for p in self.soup.find_all("video"):
            for q in p.find_all("source"):
                if q.has_attr("src") and "http" in q.get("src")[:4]:
                    m.append(q.get('src'))

        for p in self.soup.find_all("audio"):
            for q in p.find_all("source"):
                if q.has_attr("src") and "http" in q.get("src")[:4]:
                    m.append(q.get('src'))

        for link in m:
            if self.domain not in link:
                externalLinks += 1
            totalLinks += 1

        if totalLinks != 0:
            percentage = externalLinks / totalLinks

            self.requestedScaledWeight = percentage
        else:
            self.requestedScaledWeight = 0

    def anchors_scaled_calculation(self):
        """
        Get the proportion of external url in anchors
        :return: float between 0 and 1
        """

        tags = self.soup.findAll("a", href=True)
        anchors = []
        for tag in tags:
            anchors.append(tag.get("href"))

        totalLink = len(anchors)
        externalLinks = 0

        for anchor in anchors:
            if self.domain not in anchor and "http":
                if "www" in anchor[:3] or "http" in anchor[:4]:
                    externalLinks += 1

        if totalLink != 0:
            percentage = externalLinks / totalLink

            self.anchorsScaledWeight = percentage
        else:
            self.anchorsScaledWeight = 0

    def tags_links_scaled_calculation(self):
        """
        Get the proportion of external url in tags
        :return: float between 0 and 1
        """

        totalLinks = 0
        externalLinks = 0

        m = []

        meta = self.soup.find_all("meta")
        links = self.soup.find_all("link")
        scripts = self.soup.find_all("script")

        for tag in meta:
            for link in re.findall(re.compile("\"http.*?\""), str(tag)):
                m.append(link)

        for tag in links:
            if tag.has_attr("href") and "http" in tag.get("href")[:4]:
                m.append(tag.get("href"))

        for tag in scripts:
            if tag.has_attr("href") and "http" in tag.get("href")[:4]:
                m.append(tag.get("href"))

        for link in m:
            if self.domain not in link:
                externalLinks += 1
            totalLinks += 1

        if totalLinks != 0:
            percentage = externalLinks / totalLinks

            self.tagScaledWeight = percentage
        else:
            self.tagScaledWeight = 0

    def sfh_scaled_calculation(self, normDict):
        """
        Get the proportion of external url in forms, test blank forms, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["sfh"]["normalizer"])
        scaler = pickle.loads(normDict["sfh"]["scaler"])

        boolean = False
        count = 0
        for form in self.soup.find_all("form"):
            if str(form.get("action")) == "":
                boolean = True
                count += 1

            elif str(form.get("action")) == "about:blank":
                boolean = True
                count += 1

            elif self.domain not in str(form.get("action")) and ("http" in str(form.get("action")) or "www" in str(
                    form.get("action"))):
                count += 1

        if boolean:
            count = count * 2
        result = norm.transform([[count]])
        self.SFHScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def popup_scaled_calculation(self, normDict):
        """
        Count the popup, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["popup"]["normalizer"])
        scaler = pickle.loads(normDict["popup"]["scaler"])

        prompt = re.findall(r"prompt\(", str(self.html)) + re.findall(r"confirm\(", str(self.html)) + re.findall(
            r"alert\(", str(self.html))

        result = norm.transform([[len(prompt)]])
        self.popupScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def domain_age_scaled_calculation(self, normDict):
        """
        Get the time to the first registration of the domain name, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["domain_age"]["normalizer"])
        scaler = pickle.loads(normDict["domain_age"]["scaler"])

        if self.whoisDomain is not None:
            now = datetime.datetime.now()

            creation = self.whoisDomain.creation_date

            if type(creation) == list:
                creation = creation[0]
            try:
                delta = now - creation
            except:
                self.domainAgeScaledWeight = 0.5
                return

            result = norm.transform([[delta.days]])
            self.domainAgeScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def traffic_scaled_calculation(self, normDict):
        """
        Get the rank from alexa database, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["traffic"]["normalizer"])
        scaler = pickle.loads(normDict["traffic"]["scaler"])

        try:
            soup = BeautifulSoup(self.amazonAlexa, features="lxml")
            rank = int(soup.find("aws:trafficdata").find("aws:rank").contents[0])
        except (AttributeError, IndexError):
            try:
                soup = BeautifulSoup(requests.get("https://www.alexa.com/siteinfo/" + self.domain).content,
                                     features="lxml")
                tag = soup.find(id="card_rank").find("", {"class": "rank-global"}).find("", {"class": "big data"})
                rank = int("".join(re.findall('\d+', str(tag))))
            except(AttributeError, IndexError):
                self.trafficScaledWeight = 0.5
                return

        result = norm.transform([[rank]])
        self.trafficScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def page_rank_scaled_calculation(self, normDict):
        """
        Get the pageRank, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["pageRank"]["normalizer"])
        scaler = pickle.loads(normDict["pageRanl"]["scaler"])

        result = norm.transform([[self.pageRank]])
        self.pageRankScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def links_pointing_to_scaled_calculation(self, normDict):
        """
        Count the links pointing to the domain, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["links_pointing"]["normalizer"])
        scaler = pickle.loads(normDict["links_pointing"]["scaler"])

        soup = BeautifulSoup(self.amazonAlexa, features="lxml")
        try:
            countLinks = int(soup.find("aws:linksincount").contents[0])
        except (AttributeError, IndexError):
            try:
                soup = BeautifulSoup(requests.get("https://www.alexa.com/siteinfo/" + self.url).content,
                                     features="lxml")
                countLinks = int(
                    "".join(soup.find("", {"class": "linksin"}).find("", {"class": "big data"}).get_text().split(",")))
            except(AttributeError, IndexError):
                self.linksScaledWeight = 0.5
                return
        result = norm.transform([[countLinks]])
        self.linksScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def sub_domain_length_scaled_calculation(self, normDict):
        """
        Get the lentgh mean of subdomains, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["subDomainLength"]["normalizer"])
        scaler = pickle.loads(normDict["subDomainLength"]["scaler"])

        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        subdomains = domain.split(".")
        total = 0
        for subdomain in subdomains:
            total += len(subdomain)

        result = norm.transform([[total / len(subdomains)]])
        self.subDomainLengthScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def ratio_digit_sub_domain_scaled_calculation(self):
        """
        Count the ratio of exclusive digit subdomains by count subdomains
        :return: float between 0 and 1
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        subdomains = domain.split(".")

        exclusiveDigit = 0

        for subdomain in subdomains:
            if sum(list(map(lambda x: 1 if x.isdigit() else 0, subdomain))) == len(subdomain):
                exclusiveDigit += 1

        self.ratioDigitSubDomainScaledWeight = exclusiveDigit / len(subdomains)

    def ratio_hexa_sub_domain_scaled_calculation(self):
        """
        Count the ratio of exclusive hexadecimal subdomains by count subdomains
        :return: float between 0 and 1
        """

        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        subdomains = domain.split(".")

        exclusiveHex = 0

        for subdomain in subdomains:
            try:
                hexlify(unhexlify(subdomain))
                exclusiveHex += 1
            except hexErr:
                pass

        self.ratioHexaSubDomainScaledWeight = exclusiveHex / len(subdomains)

    def underscore_scaled_calculation(self):
        """
        calculate the ratio of underscore
        :return:
        """
        """
        Calculate the ratio of count underscore symbol by len of hostname, normalize and scale it between 0 and 1
        :return:
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        self.underscoreScaledWeight = domain.count("_") / len(domain)

    def vowel_ratio_scaled_calculation(self):
        """
        Get ration of vowel in hostname by len hostname
        :return: float between 0 and 1
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")

        self.vowelRatioScaledWeight = sum(
            list(map(lambda x: 1 if x in ["a", "e", "i", "o", "u", "y"] else 0, domain))) / len(domain)

    def ratio_digit_scaled_calculation(self):
        """
        Get ratio of digit in hostname by length of hostname
        :return: float between 0 and 1
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")

        self.ratioDigitScaledWeight = sum(list(map(lambda x: 1 if x.isdigit() else 0, domain))) / len(domain)

    def alphabet_cardinality_scaled_calculation(self, normDict):
        """
        Get the cardinality of alpha characters in url, normalize and scale it between 0 and 1
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: float between 0 and 1
        """
        norm = pickle.loads(normDict["alphabetCardinality"]["normalizer"])
        scaler = pickle.loads(normDict["alphabetCardinality"]["scaler"])
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")

        result = norm.transform([[sum(list(map(lambda x: 1 if x.isalpha() else 0, domain)))]])
        self.alphabetCardinalityScaledWeight = scaler.transform(result.reshape(-1, 1))[0][0]

    def ratio_repeated_character_scaled_calculation(self):
        """
        Get ratio of repeated characters in domain by cardinality of url
        :return: float between 0 and 1
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")
        card = sum(list(map(lambda x: 1 if x.isalpha() else 0, domain)))
        if card in [None, 0, "error"] or type(card) is not int:
            self.ratioRepeatedCharacterScaledWeight = 1
            return

        setDomain = list(set(domain))
        countRepeated = 0

        for character in setDomain:
            if domain.count(character) > 1:
                countRepeated += 1

        self.ratioRepeatedCharacterScaledWeight = countRepeated / card

    def ratio_consecutive_consonant_scaled_calculation(self):
        """
        Get ratio of consecutive consonants in domain by length of domain
        :return: float between 0 and 1
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")
        replaced = ""
        for i in range(len(domain)):
            if domain[i].isalpha():
                replaced += domain[i]
            else:
                replaced += "a"

        replaced = re.split("[aeiouy]", replaced)

        countConsecutive = 0
        for splitted in replaced:
            if len(splitted) > 1:
                countConsecutive += len(splitted)

        self.ratioConsecutiveConsonantScaledWeight = countConsecutive / len(domain)

    def ratio_consecutive_digit_scaled_calculation(self):
        """
        Get ratio of consecutive digits in domain by length of domain
        :return: float between 0 and 1
        """
        domain = self.hostname
        psl = PublicSuffixList()
        psl.accept_unknown = False
        if domain is None:
            domain = ""
        else:
            try:
                domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]
            except TypeError:
                pass

        domain.replace(".", "")
        replaced = ""
        for i in range(len(domain)):
            if domain[i].isdigit():
                replaced += domain[i]
            else:
                replaced += "a"

        replaced = replaced.split("a")

        countConsecutive = 0
        for splitted in replaced:
            if len(splitted) > 1:
                countConsecutive += len(splitted)

        self.ratioConsecutiveDigitScaledWeight = countConsecutive / len(domain)

    def features_extraction(self, normDict):
        """
        Extract all features and set the values into the attribute weights
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: -1,-1, None or results into queue
        """

        logger.info("Testing : " + self.url)

        self.soup = BeautifulSoup(self.html.decode('utf-8', 'ignore'), features="lxml")

        # testing ip adress
        try:
            self.ip_testing()
        except Exception as e:
            logger.critical(e)
            self.ipWeight = "error"

        # testing length of the url
        try:
            self.length_testing()
        except Exception as e:
            logger.critical(e)
            self.lengthWeight = "error"

        # testing shortener url
        try:
            self.shortener_testing()
        except Exception as e:
            logger.critical(e)
            self.shorteningWeight = "error"

        # testing at symbol
        try:
            self.at_symbol_testing()
        except Exception as e:
            logger.critical(e)
            self.atWeight = "error"

        # testing double slash
        try:
            self.double_slash_testing()
        except Exception as e:
            logger.critical(e)
            self.doubleSlashWeight = "error"

        # testing dash
        try:
            self.dash_testing()
        except Exception as e:
            logger.critical(e)
            self.dashWeight = "error"

        # testing subdomain count
        try:
            self.sub_domain_testing()
        except Exception as e:
            logger.critical(e)
            self.subDomainWeight = "error"

        # testing age of the domain certificate
        try:
            if self.http == "https" and self.certificate is not None:
                self.age_certificate_testing()
            else:
                self.certificateAgeWeight = 1
        except Exception as e:
            logger.critical(e)
            self.certificateAgeWeight = "error"

        # testing expiration date of domain
        try:
            self.expiration_domain_testing()
            if self.expirationWeight == -2:
                return -1
        except Exception as e:
            logger.critical(e)
            self.expirationWeight = "error"
        # testing favicon href
        try:
            self.favicon_testing()
        except Exception as e:
            logger.critical(e)
            self.faviconWeight = "error"

        # testing ports
        try:
            self.port_testing()

            if self.portWeight == -2:
                logger.error("port testing error")
                return -1
        except Exception as e:
            logger.critical(e)
            self.portWeight = "error"

        # testing http token
        try:
            self.http_testing()
        except Exception as e:
            logger.critical(e)
            self.httpWeight = "error"

        # testing request URL
        try:
            self.requested_url_testing()
        except Exception as e:
            logger.critical(e)
            self.requestedWeight = "error"

        # testing anchors
        try:
            self.anchors_testing()
        except Exception as e:
            logger.critical(e)
            self.anchorsWeight = "error"

        # testing tags links
        try:
            self.tags_links_testing()
        except Exception as e:
            logger.critical(e)
            self.tagWeight = "error"

        # testing SFH
        try:
            self.sfh_testing()
        except Exception as e:
            logger.critical(e)
            self.SFHWeight = "error"

        # testing email
        try:
            self.email_testing()
        except Exception as e:
            logger.critical(e)
            self.emailWeight = "error"

        # testing abnormal url
        try:
            self.abnormal_url_testing()
        except Exception as e:
            logger.critical(e)
            self.abnormalWeight = "error"

        # testing forwarding
        try:
            self.forwarding_testing()
        except Exception as e:
            logger.critical(e)
            self.forwardWeight = "error"

        # testing abnormal status bar
        try:
            self.bar_custom_testing()
        except Exception as e:
            logger.critical(e)
            self.barCustomWeight = "error"

        # testing right click disabling
        try:
            self.right_click_testing()
        except Exception as e:
            logger.critical(e)
            self.rightClickWeight = "error"

        # testing popup
        try:
            self.popup_testing()
        except Exception as e:
            logger.critical(e)
            self.popupWeight = "error"

        # testing IFrame
        try:
            self.iframe_testing()
        except Exception as e:
            logger.critical(e)
            self.iFrameWeight = "error"

        # testing domain age
        try:
            self.domain_age_testing()
            if self.domainAgeWeight == -2:
                return -1
        except Exception as e:
            logger.critical(e)
            self.domainAgeWeight = "error"

        # testing DNS record
        try:
            self.dns_record_testing()
        except Exception as e:
            logger.critical(e)
            self.dnsWeight = "error"

        # testing traffic
        try:
            self.traffic_testing()
        except Exception as e:
            logger.critical(e)
            self.trafficWeight = "error"

        # testing page rank
        try:
            self.page_rank_testing()
        except Exception as e:
            logger.critical(e)
            self.pageRankWeight = "error"

        # testo google indexing
        try:
            self.google_index_testing()

            if self.indexingWeight == -2:
                return -2
        except Exception as e:
            logger.critical(e)
            self.indexingWeight = "error"

        # testing links pointing to the webpage
        try:
            self.links_pointing_to_testing()
        except Exception as e:
            logger.critical(e)
            self.linksWeight = "error"

        # testing statistics
        try:
            self.statistic_report_testing()
        except Exception as e:
            logger.critical(e)
            self.statisticWeight = "error"

        # testing subdomain lentgh mean
        try:
            self.sub_domain_length_testing()
        except Exception as e:
            logger.critical(e)
            self.subDomainLengthWeight = "error"

        # testing www
        try:
            self.www_testing()
        except Exception as e:
            logger.critical(e)
            self.wwwWeight = "error"

        # testing valid tld
        try:
            self.valid_tld_testing()
        except Exception as e:
            logger.critical(e)
            self.validTldWeight = "error"

        # testing single character as subdomain
        try:
            self.single_character_sub_domain_testing()
        except Exception as e:
            logger.critical(e)
            self.singleCharacterSubDomainWeight = "error"

        # testing exclusive prefix repetition
        try:
            self.exclusive_prefix_repetition_testing()
        except Exception as e:
            logger.critical(e)
            self.exclusivePrefixRepetitionWeight = "error"

        # testing tld as subdomain
        try:
            self.tld_sub_domain_testing()
        except Exception as e:
            logger.critical(e)
            self.tldSubDomainWeight = "error"

        # testing ratio of digit subdomain
        try:
            self.ratio_digit_sub_domain_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioDigitSubDomainWeight = "error"

        # testing ratio of hexa subdomains
        try:
            self.ratio_hexa_sub_domain_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioHexaSubDomainWeight = "error"

        # testing ratio of underscore
        try:
            self.underscore_testing()
        except Exception as e:
            logger.critical(e)
            self.underscoreWeight = "error"

        # testing digit in domain
        try:
            self.contain_digit_testing()
        except Exception as e:
            logger.critical(e)
            self.containDigitWeight = "error"

        # testing vowel ratio
        try:
            self.vowel_ratio_testing()
        except Exception as e:
            logger.critical(e)
            self.vowelRatioWeight = "error"

        # testing digit ratio
        try:
            self.ratio_digit_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioDigitWeight = "error"

        # testing alphabet cardinality
        try:
            self.alphabet_cardinality_testing()
        except Exception as e:
            logger.critical(e)
            self.alphabetCardinalityWeight = "error"

        # testing ratio of repeated characters
        try:
            self.ratio_repeated_character_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioRepeatedCharacterWeight = "error"

        # testing ratio of consecutive consonants
        try:
            self.ratio_consecutive_consonant_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioConsecutiveConsonantWeight = "error"

        # testing ratio of consecutive digits
        try:
            self.ratio_consecutive_digit_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioConsecutiveDigitWeight = "error"

        try:
            self.length_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.lengthScaledWeight = "error"
        try:
            self.dash_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.dashScaledWeight = "error"
        try:
            self.sub_domain_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.subDomainScaledWeight = "error"
        try:
            self.age_certificate_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.certificateAgeScaledWeight = "error"
        try:
            self.expiration_domain_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.expirationScaledWeight = "error"
        try:
            self.requested_url_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.requestedScaledWeight = "error"
        try:
            self.anchors_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.anchorsScaledWeight = "error"
        try:
            self.tags_links_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.tagScaledWeight = "error"
        try:
            self.sfh_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.SFHScaledWeight = "error"
        try:
            self.popup_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.popupScaledWeight = "error"
        try:
            self.domain_age_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.domainAgeScaledWeight = "error"
        try:
            self.traffic_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.trafficScaledWeight = "error"
        try:
            self.page_rank_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.pageRankScaledWeight = "error"
        try:
            self.links_pointing_to_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.linksScaledWeight = "error"
        try:
            self.sub_domain_length_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.subDomainLengthScaledWeight = "error"
        try:
            self.ratio_digit_sub_domain_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioDigitSubDomainScaledWeight = "error"
        try:
            self.ratio_hexa_sub_domain_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioHexaSubDomainScaledWeight = "error"
        try:
            self.underscore_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.underscoreScaledWeight = "error"
        try:
            self.vowel_ratio_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.vowelRatioScaledWeight = "error"
        try:
            self.ratio_digit_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioDigitScaledWeight = "error"
        try:
            self.alphabet_cardinality_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.alphabetCardinalityScaledWeight = "error"
        try:
            self.ratio_repeated_character_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioRepeatedCharacterScaledWeight = "error"
        try:
            self.ratio_consecutive_consonant_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioConsecutiveConsonantScaledWeight = "error"
        try:
            self.ratio_consecutive_digit_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioConsecutiveDigitScaledWeight = "error"

        self.soup = None

        return self.get_features()

    def features_scaled_calculation(self, normDict):
        """
        Extract all features and set the values into the attribute weights
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return: -1,-1, None or results into queue
        """

        logger.info("Calculate : " + self.url)

        self.soup = BeautifulSoup(self.html.decode('utf-8', 'ignore'), features="lxml")

        # calculation of length of the url
        try:
            self.length_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.lengthScaledWeight = "error"

        # calculation of dash
        try:
            self.dash_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.dashScaledWeight = "error"

        # calculation of subdomain count
        try:
            self.sub_domain_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.subDomainScaledWeight = "error"

        # calculation of age of the domain certificate
        try:
            if self.http == "https" and self.certificate is not None:
                self.age_certificate_scaled_calculation(normDict)
            else:
                self.certificateAgeScaledWeight = 1
        except Exception as e:
            logger.critical(e)
            self.certificateAgeScaledWeight = "error"

        # calculation of expiration date of domain
        try:
            self.expiration_domain_scaled_calculation(normDict)
            if self.expirationScaledWeight == -2:
                return -1
        except Exception as e:
            logger.critical(e)
            self.expirationScaledWeight = "error"

        # calculation of request URL
        try:
            self.requested_url_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.requestedScaledWeight = "error"

        # calculation of anchors
        try:
            self.anchors_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.anchorsScaledWeight = "error"

        # calculation of tags links
        try:
            self.tags_links_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.tagScaledWeight = "error"

        # calculation of SFH
        try:
            self.sfh_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.SFHScaledWeight = "error"

        # calculation of popup
        try:
            self.popup_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.popupScaledWeight = "error"

        # calculation of domain age
        try:
            self.domain_age_scaled_calculation(normDict)
            if self.domainAgeScaledWeight == -2:
                return -1
        except Exception as e:
            logger.critical(e)
            self.domainAgeScaledWeight = "error"

        # calculation of traffic
        try:
            self.traffic_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.trafficScaledWeight = "error"

        # calculation of page rank
        try:
            self.page_rank_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.pageRankScaledWeight = "error"

        # calculation of links pointing to the webpage
        try:
            self.links_pointing_to_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.linksScaledWeight = "error"

        # testing scaled subdomain lentgh mean
        try:
            self.sub_domain_length_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.subDomainLengthScaledWeight = "error"

        # testing scaled ratio of digit subdomain
        try:
            self.ratio_digit_sub_domain_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioDigitSubDomainScaledWeight = "error"

        # testing scaled ratio of hexa subdomains
        try:
            self.ratio_hexa_sub_domain_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioHexaSubDomainScaledWeight = "error"

        # testing scaled ratio of underscore
        try:
            self.underscore_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.underscoreScaledWeight = "error"

        # testing scaled vowel ratio
        try:
            self.vowel_ratio_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.vowelRatioScaledWeight = "error"

        # testing scaled digit ratio
        try:
            self.ratio_digit_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioDigitScaledWeight = "error"

        # testing scaled alphabet cardinality
        try:
            self.alphabet_cardinality_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.alphabetCardinalityScaledWeight = "error"

        # testing scaled ratio of repeated characters
        try:
            self.ratio_repeated_character_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioRepeatedCharacterScaledWeight = "error"

        # testing scaled ratio of consecutive consonants
        try:
            self.ratio_consecutive_consonant_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioConsecutiveConsonantScaledWeight = "error"

        # testing scaled ratio of consecutive digits
        try:
            self.ratio_consecutive_digit_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioConsecutiveDigitScaledWeight = "error"

        self.soup = None

        return self.get_features()

    def get_features(self):
        """
        Get all features
        :return: list
        """
        return ([self.ipWeight, self.lengthWeight, self.shorteningWeight, self.atWeight, self.doubleSlashWeight,
                 self.dashWeight, self.subDomainWeight, self.certificateAgeWeight, self.expirationWeight,
                 self.faviconWeight, self.portWeight, self.httpWeight, self.requestedWeight, self.anchorsWeight,
                 self.tagWeight, self.SFHWeight, self.emailWeight, self.abnormalWeight, self.forwardWeight,
                 self.barCustomWeight, self.rightClickWeight, self.popupWeight, self.iFrameWeight, self.domainAgeWeight,
                 self.dnsWeight, self.trafficWeight, self.pageRankWeight, self.indexingWeight, self.linksWeight,
                 self.statisticWeight, self.subDomainLengthWeight, self.wwwWeight, self.validTldWeight,
                 self.singleCharacterSubDomainWeight, self.exclusivePrefixRepetitionWeight, self.tldSubDomainWeight,
                 self.ratioDigitSubDomainWeight, self.ratioHexaSubDomainWeight, self.underscoreWeight,
                 self.containDigitWeight, self.vowelRatioWeight, self.ratioDigitWeight, self.alphabetCardinalityWeight,
                 self.ratioRepeatedCharacterWeight, self.ratioConsecutiveConsonantWeight,
                 self.ratioConsecutiveDigitWeight])

    def get_scaled_features(self):
        """
        Get all scaled features
        :return: list
        """
        return ([self.ipWeight, self.lengthScaledWeight, self.shorteningWeight, self.atWeight, self.doubleSlashWeight,
                 self.dashScaledWeight, self.subDomainScaledWeight, self.certificateAgeScaledWeight,
                 self.expirationScaledWeight, self.faviconWeight, self.portWeight, self.httpWeight,
                 self.requestedScaledWeight, self.anchorsScaledWeight, self.tagScaledWeight, self.SFHScaledWeight,
                 self.emailWeight, self.abnormalWeight, self.forwardWeight, self.barCustomWeight, self.rightClickWeight,
                 self.popupScaledWeight, self.iFrameWeight, self.domainAgeScaledWeight, self.dnsWeight,
                 self.trafficScaledWeight, self.pageRankScaledWeight, self.indexingWeight, self.linksScaledWeight,
                 self.statisticWeight, self.subDomainLengthScaledWeight, self.wwwWeight, self.validTldWeight,
                 self.singleCharacterSubDomainWeight, self.exclusivePrefixRepetitionWeight, self.tldSubDomainWeight,
                 self.ratioDigitSubDomainScaledWeight, self.ratioHexaSubDomainScaledWeight, self.underscoreScaledWeight,
                 self.containDigitWeight, self.vowelRatioScaledWeight, self.ratioDigitScaledWeight,
                 self.alphabetCardinalityScaledWeight, self.ratioRepeatedCharacterScaledWeight,
                 self.ratioConsecutiveConsonantScaledWeight, self.ratioConsecutiveDigitScaledWeight])

    def set_features(self, features):
        """
        Set the features from a list
        :param features: list
        :return: nothing
        """
        if type(features) is not list or len(features) != 70:
            logger.error("Bad argument for features setter")
            return
        self.ipWeight = features[0]
        self.lengthWeight = features[1]
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
        self.subDomainLengthWeight = features[30]
        self.wwwWeight = features[31]
        self.validTldWeight = features[32]
        self.singleCharacterSubDomainWeight = features[33]
        self.exclusivePrefixRepetitionWeight = features[34]
        self.tldSubDomainWeight = features[35]
        self.ratioDigitSubDomainWeight = features[36]
        self.ratioHexaSubDomainWeight = features[37]
        self.underscoreWeight = features[38]
        self.containDigitWeight = features[39]
        self.vowelRatioWeight = features[40]
        self.ratioDigitWeight = features[41]
        self.alphabetCardinalityWeight = features[42]
        self.ratioRepeatedCharacterWeight = features[43]
        self.ratioConsecutiveConsonantWeight = features[44]
        self.ratioConsecutiveDigitWeight = features[45]
        self.lengthScaledWeight = features[46]
        self.dashScaledWeight = features[47]
        self.subDomainScaledWeight = features[48]
        self.certificateAgeScaledWeight = features[49]
        self.expirationScaledWeight = features[50]
        self.requestedScaledWeight = features[51]
        self.anchorsScaledWeight = features[52]
        self.tagScaledWeight = features[53]
        self.SFHScaledWeight = features[54]
        self.popupScaledWeight = features[55]
        self.domainAgeScaledWeight = features[56]
        self.trafficScaledWeight = features[57]
        self.pageRankScaledWeight = features[58]
        self.linksScaledWeight = features[59]
        self.subDomainLengthScaledWeight = features[60]
        self.ratioDigitSubDomainScaledWeight = features[61]
        self.ratioHexaSubDomainScaledWeight = features[62]
        self.underscoreScaledWeight = features[63]
        self.vowelRatioScaledWeight = features[64]
        self.ratioDigitScaledWeight = features[65]
        self.alphabetCardinalityScaledWeight = features[66]
        self.ratioRepeatedCharacterScaledWeight = features[67]
        self.ratioConsecutiveConsonantScaledWeight = features[68]
        self.ratioConsecutiveDigitScaledWeight = features[69]
        return

    def re_extract_non_request_features(self, normDict):
        """
        Used to re_extract non requested features
        :param normDict: dict (dictonnary which contains all normalizer and scalers for features)
        :return:
        """
        logger.debug("Extraction of {}".format(self.url))

        self.soup = BeautifulSoup(self.html.decode('utf-8', 'ignore'), features="lxml")

        # ---------------------
        #  Normal Weights
        # ---------------------

        # testing ip in url
        try:
            self.ip_testing()
        except Exception as e:
            logger.critical(e)
            self.ipWeight = "error"

        # testing length of the url
        try:
            self.length_testing()
        except Exception as e:
            logger.critical(e)
            self.lengthWeight = "error"

        # # testing shortener url
        try:
            self.shortener_testing()
        except Exception as e:
            logger.critical(e)
            self.shorteningWeight = "error"

        # testing at symbol
        try:
            self.at_symbol_testing()
        except Exception as e:
            logger.critical(e)
            self.atWeight = "error"

        # testing double slash
        try:
            self.double_slash_testing()
        except Exception as e:
            logger.critical(e)
            self.doubleSlashWeight = "error"

        # testing dash
        try:
            self.dash_testing()
        except Exception as e:
            logger.critical(e)
            self.dashWeight = "error"

        # testing subdomain count
        try:
            self.sub_domain_testing()
        except Exception as e:
            logger.critical(e)
            self.subDomainWeight = "error"

        # # testing age of the domain certificate
        try:
            if self.http == "https" and self.certificate is not None:
                self.age_certificate_testing()
            else:
                self.certificateAgeWeight = 1
        except Exception as e:
            logger.critical(e)
            self.certificateAgeWeight = "error"

        # testing expiration date of domain
        try:
            self.expiration_domain_testing()
            if self.expirationWeight == -2:
                return -1
        except Exception as e:
            logger.critical(e)
            self.expirationWeight = "error"
        # testing favicon href
        try:
            self.favicon_testing()
        except Exception as e:
            logger.critical(e)
            self.faviconWeight = "error"

        # testing http token
        try:
            self.http_testing()
        except Exception as e:
            logger.critical(e)
            self.httpWeight = "error"

        # testing request URL
        try:
            self.requested_url_testing()
        except Exception as e:
            logger.critical(e)
            self.requestedWeight = "error"

        # testing anchors
        try:
            self.anchors_testing()
        except Exception as e:
            logger.critical(e)
            self.anchorsWeight = "error"

        # testing tags links
        try:
            self.tags_links_testing()
        except Exception as e:
            logger.critical(e)
            self.tagWeight = "error"

        # # testing SFH
        try:
            self.sfh_testing()
        except Exception as e:
            logger.critical(e)
            self.SFHWeight = "error"

        # testing email
        try:
            self.email_testing()
        except Exception as e:
            logger.critical(e)
            self.emailWeight = "error"

        # testing abnormal url
        try:
            self.abnormal_url_testing()
        except Exception as e:
            logger.critical(e)
            self.abnormalWeight = "error"

        # testing abnormal status bar
        try:
            self.bar_custom_testing()
        except Exception as e:
            logger.critical(e)
            self.barCustomWeight = "error"

        # testing right click disabling
        try:
            self.right_click_testing()
        except Exception as e:
            logger.critical(e)
            self.rightClickWeight = "error"

        # testing popup
        try:
            self.popup_testing()
        except Exception as e:
            logger.critical(e)
            self.popupWeight = "error"

        # # testing IFrame
        try:
            self.iframe_testing()
        except Exception as e:
            logger.critical(e)
            self.iFrameWeight = "error"

        # testing domain age
        try:
            self.domain_age_testing()
            if self.domainAgeWeight == -2:
                return -1
        except Exception as e:
            logger.critical(e)
            self.domainAgeWeight = "error"

        # testing pageRank
        try:
            self.page_rank_testing()
        except Exception as e:
            logger.critical(e)
            self.pageRankWeight = "error"
        # testing traffic
        try:
            self.traffic_testing()
        except Exception as e:
            logger.critical(e)
            self.trafficWeight = "error"

        # testing links pointing to
        try:
            self.links_pointing_to_testing()
        except Exception as e:
            logger.critical(e)
            self.linksWeight = "error"

        # testing subdomain lentgh mean
        try:
            self.sub_domain_length_testing()
        except Exception as e:
            logger.critical(e)
            self.subDomainLengthWeight = "error"

        # # testing www
        try:
            self.www_testing()
        except Exception as e:
            logger.critical(e)
            self.wwwWeight = "error"

        # testing valid tld
        try:
            self.valid_tld_testing()
        except Exception as e:
            logger.critical(e)
            self.validTldWeight = "error"

        # testing single character as subdomain
        try:
            self.single_character_sub_domain_testing()
        except Exception as e:
            logger.critical(e)
            self.singleCharacterSubDomainWeight = "error"

        # testing exclusive prefix repetition
        try:
            self.exclusive_prefix_repetition_testing()
        except Exception as e:
            logger.critical(e)
            self.exclusivePrefixRepetitionWeight = "error"

        # testing tld as subdomain
        try:
            self.tld_sub_domain_testing()
        except Exception as e:
            logger.critical(e)
            self.tldSubDomainWeight = "error"

        # testing ratio of digit subdomain
        try:
            self.ratio_digit_sub_domain_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioDigitSubDomainWeight = "error"

        # testing ratio of hexa subdomains
        try:
            self.ratio_hexa_sub_domain_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioHexaSubDomainWeight = "error"

        # # testing ratio of underscore
        try:
            self.underscore_testing()
        except Exception as e:
            logger.critical(e)
            self.underscoreWeight = "error"

        # testing digit in domain
        try:
            self.contain_digit_testing()
        except Exception as e:
            logger.critical(e)
            self.containDigitWeight = "error"

        # testing vowel ratio
        try:
            self.vowel_ratio_testing()
        except Exception as e:
            logger.critical(e)
            self.vowelRatioWeight = "error"

        # testing digit ratio
        try:
            self.ratio_digit_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioDigitWeight = "error"

        # testing alphabet cardinality
        try:
            self.alphabet_cardinality_testing()
        except Exception as e:
            logger.critical(e)
            self.alphabetCardinalityWeight = "error"

        # testing ratio of repeated characters
        try:
            self.ratio_repeated_character_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioRepeatedCharacterWeight = "error"

        # testing ratio of consecutive consonants
        try:
            self.ratio_consecutive_consonant_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioConsecutiveConsonantWeight = "error"

        # testing ratio of consecutive digits
        try:
            self.ratio_consecutive_digit_testing()
        except Exception as e:
            logger.critical(e)
            self.ratioConsecutiveDigitWeight = "error"

        # ---------------------
        #  Normal Weights
        # ---------------------

        # testing scaled length of the url
        try:
            self.length_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.lengthScaledWeight = "error"

        # testing scaled dash
        try:
            self.dash_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.dashScaledWeight = "error"

        # testing scaled subdomain count
        try:
            self.sub_domain_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.subDomainScaledWeight = "error"

        # testing scaled age of the domain certificate
        try:
            if self.http == "https" and self.certificate is not None:
                self.age_certificate_scaled_calculation(normDict)
            else:
                self.certificateAgeScaledWeight = 1
        except Exception as e:
            logger.critical(e)
            self.certificateAgeScaledWeight = "error"

        # testing scaled expiration date of domain
        try:
            self.expiration_domain_scaled_calculation(normDict)
            if self.expirationScaledWeight == -2:
                return -1
        except Exception as e:
            logger.critical(e)
            self.expirationScaledWeight = "error"

        # testing scaled request URL
        try:
            self.requested_url_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.requestedScaledWeight = "error"

        # testing scaled anchors
        try:
            self.anchors_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.anchorsScaledWeight = "error"

        # testing scaled tags links
        try:
            self.tags_links_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.tagScaledWeight = "error"

        # testing scaled SFH
        try:
            self.sfh_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.SFHScaledWeight = "error"

        # testing scaled popup
        try:
            self.popup_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.popupScaledWeight = "error"

        # testing scaled domain age
        try:
            self.domain_age_scaled_calculation(normDict)
            if self.domainAgeScaledWeight == -2:
                return -1
        except Exception as e:
            logger.critical(e)
            self.domainAgeScaledWeight = "error"

            # testing pageRank
            try:
                self.page_rank_scaled_calculation(normDict)
            except Exception as e:
                logger.critical(e)
                self.pageRankScaledWeight = "error"
            # testing traffic
            try:
                self.traffic_scaled_calculation(normDict)
            except Exception as e:
                logger.critical(e)
                self.trafficScaledWeight = "error"

            # testing links pointing to
            try:
                self.links_pointing_to_scaled_calculation(normDict)
            except Exception as e:
                logger.critical(e)
                self.linksScaledWeight = "error"

        # testing scaled subdomain lentgh mean
        try:
            self.sub_domain_length_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.subDomainLengthScaledWeight = "error"

        # testing scaled ratio of digit subdomain
        try:
            self.ratio_digit_sub_domain_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioDigitSubDomainScaledWeight = "error"

        # testing scaled ratio of hexa subdomains
        try:
            self.ratio_hexa_sub_domain_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioHexaSubDomainScaledWeight = "error"

        # testing scaled ratio of underscore
        try:
            self.underscore_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.underscoreScaledWeight = "error"

        # testing scaled vowel ratio
        try:
            self.vowel_ratio_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.vowelRatioScaledWeight = "error"

        # testing scaled digit ratio
        try:
            self.ratio_digit_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioDigitScaledWeight = "error"

        # testing scaled alphabet cardinality
        try:
            self.alphabet_cardinality_scaled_calculation(normDict)
        except Exception as e:
            logger.critical(e)
            self.alphabetCardinalityScaledWeight = "error"

        # testing scaled ratio of repeated characters
        try:
            self.ratio_repeated_character_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioRepeatedCharacterScaledWeight = "error"

        # testing scaled ratio of consecutive consonants
        try:
            self.ratio_consecutive_consonant_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioConsecutiveConsonantScaledWeight = "error"

        # testing scaled ratio of consecutive digits
        try:
            self.ratio_consecutive_digit_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ratioConsecutiveDigitScaledWeight = "error"

        self.soup = None

        return self


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

    dBase = databaseManage.NormalizationBase("DB/norm.db")
    normDict = {}
    for norm in dBase.session.query(dBase.Normalization).all():
        normDict[norm.feature] = {"data": norm.data, "normalizer": norm.normalizer, "scaler": norm.scaler}

    # First try with all URLs
    count = 1
    begin = begin
    with open(inputFile, newline='', encoding='utf-8') as csvinfile:
        # Load URLs from csv file
        for row in csv.reader(csvinfile, delimiter=',', quotechar='|'):
            logger.info("first round: " + str(count))
            web = web(row[0])
            if count >= begin:
                try:
                    # Extract features
                    results = func_timeout(50, web.features_extraction, kwargs={'normDict': normDict})
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
        web = website(url)

        # Extract features
        try:
            results = func_timeout(90, web.features_extraction, kwargs={'normDict': normDict})
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
