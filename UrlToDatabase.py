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
import pickle
import re
import socket
import ssl
import struct

import dns.resolver
import requests
import socks
from bs4 import BeautifulSoup
from func_timeout import func_timeout, FunctionTimedOut
from myawis import CallAwis
from publicsuffixlist import PublicSuffixList

import ORMmanage
import googleApi
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

PORTS_TO_SCAN = [(21, False), (22, False), (23, False), (80, True), (443, True), (445, False), (1433, False),
                 (1521, False), (3306, False), (3389, False)]

TRUSTED_ISSUERS = ["geotrust", "godaddy", "network solutions", "thawte", "comodo", "doster", "verisign", "symantec",
                   "rapidssl", "digicert", "google", "let's encrypt", "comodo ca limited", "cloudflare", "microsoft"]


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
        if self.whoisDomain is not None:
            self.domain = self.whoisDomain.domain

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

        # PageRank calculus
        try:
            self.pageRank = requests.get("https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=" + self.domain,
                                         headers={"API-OPR": open("api_keys/openPageRank_key.txt").read()}).json()[
                "response"][0]['page_rank_decimal']
        except:
            logger.error("domain pagerank not found")
            self.pageRank = 0

        # Get AWIS Alexa information
        self.amazonAlexa = CallAwis(open("api_keys/awis_acces_id.txt").read(),
                                    open("api_keys/awis_secret_access_key.txt").read()).urlinfo(self.domain)

        ## Weights
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

        ## ScaledWeights
        self.ipScaledWeight = "error"
        self.lengthScaledWeight = "error"
        self.shorteningScaledWeight = "error"
        self.atScaledWeight = "error"
        self.doubleSlashScaledWeight = "error"
        self.dashScaledWeight = "error"
        self.subDomainScaledWeight = "error"
        self.certificateAgeScaledWeight = "error"
        self.expirationScaledWeight = "error"
        self.faviconScaledWeight = "error"
        self.portScaledWeight = "error"
        self.httpScaledWeight = "error"
        self.requestedScaledWeight = "error"
        self.anchorsScaledWeight = "error"
        self.tagScaledWeight = "error"
        self.SFHScaledWeight = "error"
        self.emailScaledWeight = "error"
        self.abnormalScaledWeight = "error"
        self.forwardScaledWeight = "error"
        self.barCustomScaledWeight = "error"
        self.rightClickScaledWeight = "error"
        self.popupScaledWeight = "error"
        self.iFrameScaledWeight = "error"
        self.domainAgeScaledWeight = "error"
        self.dnsScaledWeight = "error"
        self.trafficScaledWeight = "error"
        self.pageRankScaledWeight = "error"
        self.indexingScaledWeight = "error"
        self.linksScaledWeight = "error"
        self.statisticScaledWeight = "error"

        return

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
            self.ipWeight = -1
            return

    def length_testing(self):
        """
        test if url length is <54, between 54 and 75 or over 75
        :return: -1,0 or 1
        """

        if len(self.hostname) <= 14:
            self.lengthWeight = -1
            return
        elif 14 < len(self.hostname) < 19:
            self.lengthWeight = 0
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

        self.shorteningWeight = -1
        return

    def at_symbol_testing(self):
        """
        test if the at symbol is in url
        :return: -1 or 1
        """
        if "@" in self.url:
            self.atWeight = 1
            return
        self.atWeight = -1
        return

    def double_slash_testing(self):
        """
        test if there is double slash in url
        :return: -1 or 1
        """
        if "//" in self.url:
            self.doubleSlashWeight = 1
            return
        self.doubleSlashWeight = -1
        return

    def dash_testing(self):
        """
            test if there is dash in url
            :return: -1 or 1
            """
        if "-" in self.url:
            self.dashWeight = 1
            return
        self.dashWeight = -1
        return

    def sub_domain_testing(self):
        """
        test if there are too many subdomains
        :return: -1,0 or 1
        """
        psl = PublicSuffixList()
        domain = self.hostname
        if domain is None:
            domain = ""
        else:
            domain = domain[:len(domain) - (len(psl.publicsuffix(domain)) + 1)]

        if domain.count('.') <= 1:
            self.subDomainWeight = -1
            return
        elif domain.count('.') == 2:
            self.subDomainWeight = 0
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
                    self.certificateAgeWeight = -1
                    return

        self.certificateAgeWeight = 0
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
                self.expirationWeight = 0
                return

            if delta.days > 330:
                self.expirationWeight = -1
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

        self.faviconWeight = -1
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
            self.portWeight = -1
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

        self.httpWeight = -1
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
                self.requestedWeight = 0
                return

        self.requestedWeight = -1
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
            self.anchorsWeight = -1
            return

        elif externalLinks / totalLink <= 0.67:
            self.anchorsWeight = 0
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
            elif percentage >= 0.17:
                self.tagWeight = 0
                return

        self.tagWeight = -1
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
                self.SFHWeight = 0
                return
        self.SFHWeight = -1
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
        self.emailWeight = -1
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
            self.forwardWeight = -1
            return

        if countForward < 4:
            self.forwardWeight = 0
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
                self.barCustomWeight = 0
                return
        self.barCustomWeight = -1
        return

    def right_click_testing(self):
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

    def popup_testing(self):
        """
        testing if popup with text fields
        :return: -1, 0 or 1
        """
        prompt = re.findall(r"prompt\(", str(self.html)) + re.findall(r"confirm\(", str(self.html)) + re.findall(
            r"alert\(", str(self.html))
        if prompt:
            if len(prompt) > 4:
                self.popupWeight = 1
                return
            if len(prompt) > 2:
                self.popupWeight = 0
                return

        self.popupWeight = -1
        return

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

        self.iFrameWeight = -1
        return

        # if "iframe" in str(soup):
        #     return 1
        #
        # else:
        #     return -1

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
            self.dnsWeight = -1
            return

        self.dnsWeight = 1
        return

    def traffic_testing(self):
        """
        collect the website rank on AWIS database and test if it is not abnormal
        :return: -1,0 or 1
        """
        try:
            soup = BeautifulSoup(self.amazonAlexa, features="lxml")
            rank = int((soup.find("aws:trafficdata").find("aws:rank").contents)[0])
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
            self.trafficWeight = 0
            return

        self.trafficWeight = -1
        return

    def page_rank_testing(self):
        """
        Test the pagerank of the domain
        :return: -1 or 1
        """

        if self.pageRank <= 2:
            self.pageRankWeight = 1
            return
        else:
            self.pageRankWeight = -1
            return

    def google_index_testing(self):
        """
        test if url is indexed by google
        :return: -1 or 1
        """
        index = googleApi.google_search("site:" + self.url)
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
        if countLinks == 0:
            self.linksWeight = 1
            return
        elif countLinks <= 2:
            self.linksWeight = 0
            return

        self.linksWeight = -1
        return

    def statistic_report_testing(self):
        """
        test if the ip address of the domain is in top 50 of www.stopbadware.org
        :return: -1 or 1
        """
        try:
            IPdomain = socket.gethostbyname(self.hostname)
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

    # ---------------------
    #  Scaled weights calculation
    # ---------------------
    def ip_scaled_calculation(self):
        self.ipScaledWeight = (float(self.ipWeight) * 0.5) - 0.5

    def length_scaled_calculation(self):
        Base = ORMmanage.MyBase("DB/toto.db")
        self.lengthScaledWeight = pickle.loads(
            Base.session.query(Base.Scalers).filter(Base.Scalers.features == "url_len").first().content).transform(
            [[len(self.hostname)]])[0][0]
        pass

    def shortener_scaled_calculation(self):
        self.shorteningScaledWeight = (float(self.shorteningWeight) * 0.5) - 0.5

    def at_symbol_scaled_calculation(self):
        self.atScaledWeight = (float(self.atWeight) * 0.5) - 0.5

    def double_slash_scaled_calculation(self):
        self.doubleSlashScaledWeight = (float(self.doubleSlashWeight) * 0.5) - 0.5

    def dash_scaled_calculation(self):
        pass

    def sub_domain_scaled_calculation(self):
        pass

    def age_certificate_scaled_calculation(self):
        pass

    def expiration_domain_scaled_calculation(self):
        pass

    def favicon_scaled_calculation(self):
        self.faviconScaledWeight = (float(self.faviconWeight) * 0.5) - 0.5

    def port_scaled_calculation(self):
        self.portScaledWeight = (float(self.portWeight) * 0.5) - 0.5

    def http_scaled_calculation(self):
        self.httpScaledWeight = (float(self.httpWeight) * 0.5) - 0.5

    def requested_url(self):
        pass

    def anchors_scaled_calculation(self):
        pass

    def tags_links_scaled_calculation(self):
        pass

    def sfh_scaled_calculation(self):
        pass

    def email_scaled_calculation(self):
        self.emailScaledWeight = (float(self.emailWeight) * 0.5) - 0.5

    def abnormal_url_scaled_calculation(self):
        self.abnormalScaledWeight = (float(self.abnormalWeight) * 0.5) - 0.5

    def forwarding_scaled_calculation(self):
        self.forwardScaledWeight = (float(self.forwardWeight) * 0.5) - 0.5

    def bar_custom_scaled_calculation(self):
        self.barCustomScaledWeight = (float(self.barCustomWeight) * 0.5) - 0.5

    def right_click_scaled_calculation(self):
        self.rightClickScaledWeight = (float(self.rightClickWeight) * 0.5) - 0.5

    def popup_scaled_calculation(self):
        pass

    def iframe_scaled_calculation(self):
        self.iFrameScaledWeight = (float(self.iFrameWeight) * 0.5) - 0.5

    def domain_age_scaled_calculation(self):
        pass

    def dns_record_scaled_calculation(self):
        self.dnsScaledWeight = (float(self.dnsWeight) * 0.5) - 0.5

    def traffic_scaled_calculation(self):
        pass

    def page_rank_scaled_calculation(self):
        pass

    def google_index_scaled_calculation(self):
        self.indexingScaledWeight = (float(self.indexingWeight) * 0.5) - 0.5

    def links_pointing_to_scaled_calculation(self):
        pass

    def statistic_report_scaled_calculation(self):
        self.statisticScaledWeight = (float(self.statisticWeight) * 0.5) - 0.5

    def features_extraction(self):
        """
        Extract all features and set the values into the attribute weights
        :return: -1,-1, None or results into queue
        """

        logger.info("Testing : " + self.url)

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
            self.requested_url()
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

        return self.get_features()

    def features_scaled_calculation(self):
        """
        Extract all features and set the values into the attribute weights
        :return: -1,-1, None or results into queue
        """

        logger.info("Calculate : " + self.url)

        # calculation of ip adress
        try:
            self.ip_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.ipScaledWeight = "error"

        # calculation of length of the url
        try:
            self.length_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.lengthScaledWeight = "error"

        # calculation of shortener url
        try:
            self.shortener_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.shorteningScaledWeight = "error"

        # calculation of at symbol
        try:
            self.at_symbol_testing()
        except Exception as e:
            logger.critical(e)
            self.atScaledWeight = "error"

        # calculation of double slash
        try:
            self.double_slash_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.doubleSlashScaledWeight = "error"

        # calculation of dash
        try:
            self.dash_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.dashScaledWeight = "error"

        # calculation of subdomain count
        try:
            self.sub_domain_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.subDomainScaledWeight = "error"

        # calculation of age of the domain certificate
        try:
            if self.http == "https" and self.certificate is not None:
                self.age_certificate_scaled_calculation()
            else:
                self.certificateAgeScaledWeight = 1
        except Exception as e:
            logger.critical(e)
            self.certificateAgeScaledWeight = "error"

        # calculation of expiration date of domain
        try:
            self.expiration_domain_scaled_calculation()
            if self.expirationScaledWeight == -2:
                return -1
        except Exception as e:
            logger.critical(e)
            self.expirationScaledWeight = "error"
        # calculation of favicon href
        try:
            self.favicon_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.faviconScaledWeight = "error"

        # calculation of ports
        try:
            self.port_scaled_calculation()

            if self.portScaledWeight == -2:
                logger.error("port testing error")
                return -1
        except Exception as e:
            logger.critical(e)
            self.portScaledWeight = "error"

        # calculation of http token
        try:
            self.http_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.httpScaledWeight = "error"

        # calculation of request URL
        try:
            self.requested_url()
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
            self.sfh_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.SFHScaledWeight = "error"

        # calculation of email
        try:
            self.email_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.emailScaledWeight = "error"

        # calculation of abnormal url
        try:
            self.abnormal_url_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.abnormalScaledWeight = "error"

        # calculation of forwarding
        try:
            self.forwarding_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.forwardScaledWeight = "error"

        # calculation of abnormal status bar
        try:
            self.bar_custom_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.barCustomScaledWeight = "error"

        # calculation of right click disabling
        try:
            self.right_click_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.rightClickScaledWeight = "error"

        # calculation of popup
        try:
            self.popup_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.popupScaledWeight = "error"

        # calculation of IFrame
        try:
            self.iframe_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.iFrameScaledWeight = "error"

        # calculation of domain age
        try:
            self.domain_age_scaled_calculation()
            if self.domainAgeScaledWeight == -2:
                return -1
        except Exception as e:
            logger.critical(e)
            self.domainAgeScaledWeight = "error"

        # calculation of DNS record
        try:
            self.dns_record_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.dnsScaledWeight = "error"

        # calculation of traffic
        try:
            self.traffic_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.trafficScaledWeight = "error"

        # calculation of page rank
        try:
            self.page_rank_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.pageRankScaledWeight = "error"

        # testo google indexing
        try:
            self.google_index_scaled_calculation()

            if self.indexingScaledWeight == -2:
                return -2
        except Exception as e:
            logger.critical(e)
            self.indexingScaledWeight = "error"

        # calculation of links pointing to the webpage
        try:
            self.links_pointing_to_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.linksScaledWeight = "error"

        # calculation of statistics
        try:
            self.statistic_report_scaled_calculation()
        except Exception as e:
            logger.critical(e)
            self.statisticScaledWeight = "error"

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
                 self.statisticWeight])

    def get_scaled_features(self):
        """
        Get all scaled features
        :return: list
        """
        return ([self.ipScaledWeight, self.lengthScaledWeight, self.shorteningScaledWeight, self.atScaledWeight,
                 self.doubleSlashScaledWeight,
                 self.dashScaledWeight, self.subDomainScaledWeight, self.certificateAgeScaledWeight,
                 self.expirationScaledWeight,
                 self.faviconScaledWeight, self.portScaledWeight, self.httpScaledWeight, self.requestedScaledWeight,
                 self.anchorsScaledWeight,
                 self.tagScaledWeight, self.SFHScaledWeight, self.emailScaledWeight, self.abnormalScaledWeight,
                 self.forwardScaledWeight,
                 self.barCustomScaledWeight, self.rightClickScaledWeight, self.popupScaledWeight,
                 self.iFrameScaledWeight, self.domainAgeScaledWeight,
                 self.dnsScaledWeight, self.trafficScaledWeight, self.pageRankScaledWeight, self.indexingScaledWeight,
                 self.linksScaledWeight,
                 self.statisticScaledWeight])

    def set_features(self, features):
        """
        Set the features from a list
        :param features: list
        :return: nothing
        """
        if type(features) is not list or len(features) != 30:
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
        return

    def set_scaled_features(self, features):
        """
        Set the scaled features from a list
        :param features: list
        :return: nothing
        """
        if type(features) is not list or len(features) != 30:
            logger.error("Bad argument for features setter")
            return
        self.ipScaledWeight = features[0]
        self.lengthScaledWeight = features[1]
        self.shorteningScaledWeight = features[2]
        self.atScaledWeight = features[3]
        self.doubleSlashScaledWeight = features[4]
        self.dashScaledWeight = features[5]
        self.subDomainScaledWeight = features[6]
        self.certificateAgeScaledWeight = features[7]
        self.expirationScaledWeight = features[8]
        self.faviconScaledWeight = features[9]
        self.portScaledWeight = features[10]
        self.httpScaledWeight = features[11]
        self.requestedScaledWeight = features[12]
        self.anchorsScaledWeight = features[13]
        self.tagScaledWeight = features[14]
        self.SFHScaledWeight = features[15]
        self.emailScaledWeight = features[16]
        self.abnormalScaledWeight = features[17]
        self.forwardScaledWeight = features[18]
        self.barCustomScaledWeight = features[19]
        self.rightClickScaledWeight = features[20]
        self.popupScaledWeight = features[21]
        self.iFrameScaledWeight = features[22]
        self.domainAgeScaledWeight = features[23]
        self.dnsScaledWeight = features[24]
        self.trafficScaledWeight = features[25]
        self.pageRankScaledWeight = features[26]
        self.indexingScaledWeight = features[27]
        self.linksScaledWeight = features[28]
        self.statisticScaledWeight = features[29]
        return

    def re_extract_non_request_features(self):
        self.soup = BeautifulSoup(self.html.decode('utf-8', 'ignore'), features="lxml")

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

        # testing http token
        try:
            self.http_testing()
        except Exception as e:
            logger.critical(e)
            self.httpWeight = "error"

        # testing request URL
        try:
            self.requested_url()
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
                    results = func_timeout(50, website.features_extraction)
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
            results = func_timeout(90, website.features_extraction)
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
