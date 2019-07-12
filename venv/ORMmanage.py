import logging
import pickle

from pathos.pools import ThreadPool
from sqlalchemy import Binary
from sqlalchemy import Column, Integer, String
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import UrlToDatabase

# Import logger
logger = logging.getLogger('main')


class MyBase:
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

    class Scalers(Base):
        """
        Table for scalers
        """
        __tablename__ = "scalers"
        id = Column(Integer, primary_key=True)
        features = Column(String)
        content = Column(Binary)

    def create_tables(self):
        """
        Used to create different tables
        :return: nothing
        """
        MyBase.Base.metadata.create_all(self.engine)
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
            query = self.session.query(self.__getattribute__(table.capitalize())).all()

            for result in query:
                # Load old wabsite data
                oldUrl = pickle.loads(result.content)

                # Create new website with new methods
                tmp = UrlToDatabase.URL(result.url, True)

                # Load attributes from old to new website
                tmp.http = oldUrl.http
                tmp.domain = oldUrl.domain
                tmp.whoisDomain = oldUrl.whoisDomain
                tmp.html = oldUrl.html
                tmp.url = oldUrl.url
                tmp.hostname = oldUrl.hostname
                tmp.certificate = oldUrl.certificate
                tmp.soup = oldUrl.soup

                # Load weights
                tmp.ipWeight = int(oldUrl.ipWeight)
                tmp.lenghtWeight = int(oldUrl.lenghtWeight)
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

                # Load scaled weights
                tmp.ipScaledWeight = float(oldUrl.ipScaledWeight)
                tmp.lenghtScaledWeight = float(oldUrl.lenghtScaledWeight)
                tmp.shorteningScaledWeight = float(oldUrl.shorteningScaledWeight)
                tmp.atScaledWeight = float(oldUrl.atScaledWeight)
                tmp.doubleSlashScaledWeight = float(oldUrl.doubleSlashScaledWeight)
                tmp.dashScaledWeight = float(oldUrl.dashScaledWeight)
                tmp.subDomainScaledWeight = float(oldUrl.subDomainScaledWeight)
                tmp.certificateAgeScaledWeight = float(oldUrl.certificateAgeScaledWeight)
                tmp.expirationScaledWeight = float(oldUrl.expirationScaledWeight)
                tmp.faviconScaledWeight = float(oldUrl.faviconScaledWeight)
                tmp.portScaledWeight = float(oldUrl.portScaledWeight)
                tmp.httpScaledWeight = float(oldUrl.httpScaledWeight)
                tmp.requestedScaledWeight = float(oldUrl.requestedScaledWeight)
                tmp.anchorsScaledWeight = float(oldUrl.anchorsScaledWeight)
                tmp.tagScaledWeight = float(oldUrl.tagScaledWeight)
                tmp.SFHScaledWeight = float(oldUrl.SFHScaledWeight)
                tmp.emailScaledWeight = float(oldUrl.emailScaledWeight)
                tmp.abnormalScaledWeight = float(oldUrl.abnormalScaledWeight)
                tmp.forwardScaledWeight = float(oldUrl.forwardScaledWeight)
                tmp.barCustomScaledWeight = float(oldUrl.barCustomScaledWeight)
                tmp.rightClickScaledWeight = float(oldUrl.rightClickScaledWeight)
                tmp.popupScaledWeight = float(oldUrl.popupScaledWeight)
                tmp.iFrameScaledWeight = float(oldUrl.iFrameScaledWeight)
                tmp.domainAgeScaledWeight = float(oldUrl.domainAgeScaledWeight)
                tmp.dnsScaledWeight = float(oldUrl.dnsScaledWeight)
                tmp.trafficScaledWeight = float(oldUrl.trafficScaledWeight)
                tmp.pageRankScaledWeight = float(oldUrl.pageRankScaledWeight)
                tmp.indexingScaledWeight = float(oldUrl.indexingScaledWeight)
                tmp.linksScaledWeight = float(oldUrl.linksScaledWeight)
                tmp.statisticScaledWeight = float(oldUrl.statisticScaledWeight)

                # Replace old website in database by new website
                result.content = pickle.dumps(tmp)
            self.session.commit()

            del query
        return

    def new_url_analysis(self):
        for table in self.Base.metadata.tables.keys():
            query = self.session.query(self.__getattribute__(table.capitalize())).all()

            # Load old wabsite data
            contents = []
            for result in query:
                contents.append(pickle.loads(result.content))
            logger.info("Data from table {} loaded".format(str(table)))

            ThreadPool().map(UrlToDatabase.URL.re_extract_non_request_features, contents)
            logger.info("Data loaded from table {} transformed".format(str(table)))
            i = 0
            for i in range(len(query)):
                query[i].content = pickle.dumps(contents[i])
            self.session.commit()
            logger.info("Data loaded from table {} commited".format(str(table)))

            del query, contents
