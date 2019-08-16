"""
File used as interface with the sqlite3 database
-----------
Generative Adversarial Networks (GAN) research applied to the phishing detection.
University of Gloucestershire
Author : Pierrick ROBIC--BUTEZ
2019
Copyright (c) 2019 Khuzd
"""

import logging
import pickle
from functools import partial
from multiprocessing import Pool

from sqlalchemy import Binary
from sqlalchemy import Column, Integer, String
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import Website

# Import logger
logger = logging.getLogger('phishGan')


class WebsiteBase:
    """
    Class used to get website data from the Sqlite3 database
    """
    Base = declarative_base()

    def __init__(self, path):
        # ---------------------
        #  Define attributes
        # ---------------------
        self.path = path
        self.engine = create_engine('sqlite:///' + self.path)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    class Clean(Base):
        """
        Table for clean URLs from Amazon top 25000
        """
        __tablename__ = 'clean'

        id = Column(Integer, primary_key=True)
        url = Column(String)
        content = Column(Binary)

    class Phish(Base):
        """
        Table for phishing URLs from PhishTank
        """
        __tablename__ = 'phish'

        id = Column(Integer, primary_key=True)
        url = Column(String)
        content = Column(Binary)

    class History(Base):
        """
        Table for URLs from history browsers
        """
        __tablename__ = 'history'

        id = Column(Integer, primary_key=True)
        url = Column(String)
        content = Column(Binary)

    class Normalization(Base):
        """
        Table for Normalization
        """
        __tablename__ = "normalization"
        id = Column(Integer, primary_key=True)
        feature = Column(String)
        data = Column(Binary)
        normalizer = Column(Binary)
        scaler = Column(Binary)

    def create_tables(self):
        """
        Used to create different tables
        :return: nothing
        """
        WebsiteBase.Base.metadata.create_all(self.engine)
        return

    def adding(self, website, table):
        """
        Used to add URL in a table of the database
        :param website: UrlToDatabase.URL
        :param table: str
        :return: nothing
        """
        try:
            adding = self.__getattribute__(table)(url=website.url, content=pickle.dumps(website))
            self.session.add(adding)
            self.session.commit()

        except ConnectionError:
            logger.critical("Please add table {} in the database".format(table))

        return

    def update_class(self):
        """
        Used to update methods of all websites stored in database
        :return:
        """
        for table in self.Base.metadata.tables.keys():
            print("update table {}".format(str(table)))
            if table.lower() != "normalization":

                for result in self.session.query(self.__getattribute__(table.capitalize())).yield_per(500):
                    # Load old wabsite data
                    oldUrl = pickle.loads(result.content)

                    # Create new website with new methods
                    tmp = Website.website(result.url, True)

                    # Load attributes from old to new website
                    tmp.http = oldUrl.http
                    tmp.domain = oldUrl.domain
                    tmp.whoisDomain = oldUrl.whoisDomain
                    tmp.html = oldUrl.html
                    tmp.url = oldUrl.url
                    tmp.hostname = oldUrl.hostname
                    tmp.certificate = oldUrl.certificate
                    tmp.soup = oldUrl.soup
                    tmp.amazonAlexa = oldUrl.amazonAlexa
                    tmp.pageRank = oldUrl.pageRank
                    tmp.redirectCount = oldUrl.redirectCount

                    # Load weights
                    tmp.ipWeight = int(oldUrl.ipWeight)
                    tmp.lengthWeight = int(oldUrl.lengthWeight)
                    tmp.shorteningWeight = int(oldUrl.shorteningWeight)
                    tmp.atWeight = int(oldUrl.atWeight)
                    tmp.doubleSlashWeight = int(oldUrl.doubleSlashWeight)
                    tmp.dashWeight = int(oldUrl.dashWeight)
                    tmp.subDomainWeight = int(oldUrl.subDomainWeight)
                    tmp.certificateAgeWeight = int(oldUrl.certificateAgeWeight)
                    tmp.expirationWeight = int(oldUrl.expirationWeight)
                    tmp.faviconWeight = int(oldUrl.faviconWeight)
                    tmp.portWeight = int(oldUrl.portWeight)
                    tmp.httpWeight = int(oldUrl.httpWeight)
                    tmp.requestedWeight = int(oldUrl.requestedWeight)
                    tmp.anchorsWeight = int(oldUrl.anchorsWeight)
                    tmp.tagWeight = int(oldUrl.tagWeight)
                    tmp.SFHWeight = int(oldUrl.SFHWeight)
                    tmp.emailWeight = int(oldUrl.emailWeight)
                    tmp.abnormalWeight = int(oldUrl.abnormalWeight)
                    tmp.forwardWeight = int(oldUrl.forwardWeight)
                    tmp.barCustomWeight = int(oldUrl.barCustomWeight)
                    tmp.rightClickWeight = int(oldUrl.rightClickWeight)
                    tmp.popupWeight = int(oldUrl.popupWeight)
                    tmp.iFrameWeight = int(oldUrl.iFrameWeight)
                    tmp.domainAgeWeight = int(oldUrl.domainAgeWeight)
                    tmp.dnsWeight = int(oldUrl.dnsWeight)
                    tmp.trafficWeight = int(oldUrl.trafficWeight)
                    tmp.pageRankWeight = int(oldUrl.pageRankWeight)
                    tmp.indexingWeight = int(oldUrl.indexingWeight)
                    tmp.linksWeight = int(oldUrl.linksWeight)
                    tmp.statisticWeight = int(oldUrl.statisticWeight)
                    tmp.subDomainLengthWeight = int(oldUrl.subDomainLengthWeight)
                    tmp.wwwWeight = int(oldUrl.wwwWeight)
                    tmp.validTldWeight = int(oldUrl.validTldWeight)
                    tmp.singleCharacterSubDomainWeight = int(oldUrl.singleCharacterSubDomainWeight)
                    tmp.exclusivePrefixRepetitionWeight = int(oldUrl.exclusivePrefixRepetitionWeight)
                    tmp.tldSubDomainWeight = int(oldUrl.tldSubDomainWeight)
                    tmp.ratioDigitSubDomainWeight = int(oldUrl.ratioDigitSubDomainWeight)
                    tmp.ratioHexaSubDomainWeight = int(oldUrl.ratioHexaSubDomainWeight)
                    tmp.underscoreWeight = int(oldUrl.underscoreWeight)
                    tmp.containDigitWeight = int(oldUrl.containDigitWeight)
                    tmp.vowelRatioWeight = int(oldUrl.vowelRatioWeight)
                    tmp.ratioDigitWeight = int(oldUrl.ratioDigitWeight)
                    tmp.alphabetCardinalityWeight = int(oldUrl.alphabetCardinalityWeight)
                    tmp.ratioRepeatedCharacterWeight = int(oldUrl.ratioRepeatedCharacterWeight)
                    tmp.ratioConsecutiveConsonantWeight = int(oldUrl.ratioConsecutiveConsonantWeight)
                    tmp.ratioConsecutiveDigitWeight = int(oldUrl.ratioConsecutiveDigitWeight)

                    # Load scaled weights
                    tmp.lengthScaledWeight = float(oldUrl.lengthScaledWeight)
                    tmp.dashScaledWeight = float(oldUrl.dashScaledWeight)
                    tmp.subDomainScaledWeight = float(oldUrl.subDomainScaledWeight)
                    tmp.certificateAgeScaledWeight = float(oldUrl.certificateAgeScaledWeight)
                    tmp.expirationScaledWeight = float(oldUrl.expirationScaledWeight)
                    tmp.requestedScaledWeight = float(oldUrl.requestedScaledWeight)
                    tmp.anchorsScaledWeight = float(oldUrl.anchorsScaledWeight)
                    tmp.tagScaledWeight = float(oldUrl.tagScaledWeight)
                    tmp.SFHScaledWeight = float(oldUrl.SFHScaledWeight)
                    tmp.popupScaledWeight = float(oldUrl.popupScaledWeight)
                    tmp.domainAgeScaledWeight = float(oldUrl.domainAgeScaledWeight)
                    tmp.trafficScaledWeight = float(oldUrl.trafficScaledWeight)
                    tmp.pageRankScaledWeight = float(oldUrl.pageRankScaledWeight)
                    tmp.linksScaledWeight = float(oldUrl.linksScaledWeight)
                    tmp.subDomainLengthScaledWeight = float(oldUrl.subDomainLengthScaledWeight)
                    tmp.ratioDigitSubDomainScaledWeight = float(oldUrl.ratioDigitSubDomainScaledWeight)
                    tmp.ratioHexaSubDomainScaledWeight = float(oldUrl.ratioHexaSubDomainScaledWeight)
                    tmp.underscoreScaledWeight = float(oldUrl.underscoreScaledWeight)
                    tmp.vowelRatioScaledWeight = float(oldUrl.vowelRatioScaledWeight)
                    tmp.ratioDigitScaledWeight = float(oldUrl.ratioDigitScaledWeight)
                    tmp.alphabetCardinalityScaledWeight = float(oldUrl.alphabetCardinalityScaledWeight)
                    tmp.ratioRepeatedCharacterScaledWeight = float(oldUrl.ratioRepeatedCharacterScaledWeight)
                    tmp.ratioConsecutiveConsonantScaledWeight = float(oldUrl.ratioConsecutiveConsonantScaledWeight)
                    tmp.ratioConsecutiveDigitScaledWeight = float(oldUrl.ratioConsecutiveDigitScaledWeight)

                    # Replace old website in database by new website
                    result.content = pickle.dumps(tmp)
                    del oldUrl, tmp
                self.session.commit()

        return

    def new_url_analysis(self):
        """
        Used to analyse again all URLs in database
        :return: nothing
        """
        for table in self.Base.metadata.tables.keys():
            if table.lower() != "normalization":
                dBase = NormalizationBase("DB/norm.db")
                normDict = {}
                for norm in dBase.session.query(dBase.Normalization).all():
                    normDict[norm.feature] = {"data": norm.data, "normalizer": norm.normalizer, "scaler": norm.scaler}
                fct = partial(Website.website.re_extract_non_request_features, normDict=normDict)
                for webs in [self.session.query(self.__getattribute__(table.capitalize())).yield_per(1000)[x:x + 500]
                             for x in
                             range(0, self.session.query(self.__getattribute__(table.capitalize())).count(),
                                   500)]:
                    content = []
                    for web in webs:
                        content.append(pickle.loads(web.content))
                    pool = Pool()
                    results = pool.map(fct, content)
                    pool.close()
                    for i in range(len(results)):
                        webs[i].content = pickle.dumps(results[i])
                    self.session.commit()
                    logger.info("500 data from table {} commited".format(str(table)))
                    del pool, results, content, webs
                self.session.commit()
                self.session.expunge_all()
                logger.info("Data loaded from table {} commited".format(str(table)))

                del dBase, normDict, fct

    def __del__(self):
        self.session.close()
        self.Session.close_all()


class NormalizationBase:
    """
    Class used to get normalization data from the Sqlite3 database
    """
    Base = declarative_base()

    def __init__(self, path):
        # ---------------------
        #  Define attributes
        # ---------------------
        self.path = path
        self.engine = create_engine('sqlite:///' + self.path)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    class Normalization(Base):
        """
        Table for Normalization
        """
        __tablename__ = "normalization"
        id = Column(Integer, primary_key=True)
        feature = Column(String)
        data = Column(Binary)
        normalizer = Column(Binary)
        scaler = Column(Binary)

    def create_tables(self):
        """
        Used to create different tables
        :return: nothing
        """
        NormalizationBase.Base.metadata.create_all(self.engine)
        return
