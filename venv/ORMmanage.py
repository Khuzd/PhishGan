import logging
import pickle

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

    def create_tables(self):
        """
        Used to create different tables
        :return: nothing
        """
        MyBase.Base.metadata.create_all(self.engine)
        return

    def adding(self, url, table, extraction):
        """
        Used to add URL in a table of the database
        :param url: str
        :param table: str
        :param extraction: bool
        :return: nothing
        """
        try:
            # Check if URL is not already in the table
            if self.session.query(self.__getattribute__(table)).filter(
                    self.__getattribute__(table).url == url).count() == 0:
                logger.info("adding: " + url)
                website = UrlToDatabase.URL(url)

                # Extract feature if asked
                if extraction:
                    if website.featuresExtraction() is None:
                        adding = self.__getattribute__(table)(url=website.url, content=pickle.dumps(website))
                        self.session.add(adding)
                        self.session.commit()
                else:
                    adding = self.__getattribute__(table)(url=website.url, content=pickle.dumps(website))
                    self.session.add(adding)
                    self.session.commit()
        except AttributeError:
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

                # Load weights
                tmp.ipWeight = oldUrl.ipWeight
                tmp.lenghtWeight = oldUrl.lenghtWeight
                tmp.shorteningWeight = oldUrl.shorteningWeight
                tmp.atWeight = oldUrl.atWeight
                tmp.doubleSlashWeight = oldUrl.doubleSlashWeight
                tmp.dashWeight = oldUrl.dashWeight
                tmp.subDomainWeight = oldUrl.subDomainWeight
                tmp.certificateAgeWeight = oldUrl.certificateAgeWeight
                tmp.expirationWeight = oldUrl.expirationWeight
                tmp.faviconWeight = oldUrl.faviconWeight
                tmp.portWeight = oldUrl.portWeight
                tmp.httpWeight = oldUrl.httpWeight
                tmp.requestedWeight = oldUrl.requestedWeight
                tmp.anchorsWeight = oldUrl.anchorsWeight
                tmp.tagWeight = oldUrl.tagWeight
                tmp.SFHWeight = oldUrl.SFHWeight
                tmp.emailWeight = oldUrl.emailWeight
                tmp.abnormalWeight = oldUrl.abnormalWeight
                tmp.forwardWeight = oldUrl.forwardWeight
                tmp.barCustomWeight = oldUrl.barCustomWeight
                tmp.rightClickWeight = oldUrl.rightClickWeight
                tmp.popupWeight = oldUrl.popupWeight
                tmp.iFrameWeight = oldUrl.iFrameWeight
                tmp.domainAgeWeight = oldUrl.domainAgeWeight
                tmp.dnsWeight = oldUrl.dnsWeight
                tmp.trafficWeight = oldUrl.trafficWeight
                tmp.pageRankWeight = oldUrl.pageRankWeight
                tmp.indexingWeight = oldUrl.indexingWeight
                tmp.linksWeight = oldUrl.linksWeight
                tmp.statisticWeight = oldUrl.statisticWeight

                # Replace old website in database by new website
                result.content = pickle.dumps(tmp)
                self.session.commit()

            del query
        return
