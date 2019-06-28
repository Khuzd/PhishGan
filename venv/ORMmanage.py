import UrlToDatabase
from sqlalchemy import create_engine
from sqlalchemy import Binary
import pickle
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import sessionmaker


class MyBase:
    Base = declarative_base()

    def __init__(self, path):
        self.path = path
        self.engine = create_engine('sqlite:///' + self.path)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    class Clean(Base):
        __tablename__ = 'cleanTest'

        id = Column(Integer, primary_key=True)
        url = Column(String)
        content = Column(Binary)

    class Phish(Base):
        __tablename__ = 'phish'

        id = Column(Integer, primary_key=True)
        url = Column(String)
        content = Column(Binary)

    class History(Base):
        __tablename__ = 'history'

        id = Column(Integer, primary_key=True)
        url = Column(String)
        content = Column(Binary)

    def create_tables(self):
        MyBase.Base.metadata.create_all(self.engine)

    def adding(self, url, table, extraction):
        try:
            if self.session.query(self.__getattribute__(table)).filter(
                    self.__getattribute__(table).url == url).count() == 0:
                print("adding: " + url)
                website = UrlToDatabase.URL(url)

                if extraction:
                    if website.featuresExtraction() == None:
                        adding = self.__getattribute__(table)(url=website.url, content=pickle.dumps(website))
                        self.session.add(adding)
                        self.session.commit()
                else:
                    adding = self.__getattribute__(table)(url=website.url, content=pickle.dumps(website))
                    self.session.add(adding)
                    self.session.commit()
        except AttributeError:
            print("Please add table {} in the database".format(table))

    def update_class(self):
        queryPhish = self.session.query(self.Phish).all
        for result in queryPhish:
            oldUrl = pickle.loads(result.content)

            tmp = UrlToDatabase.URL(result.url, True)

            tmp.http = oldUrl.http
            tmp.domain = oldUrl.domain
            tmp.whoisDomain = oldUrl.whoisDomain
            tmp.html = oldUrl.html
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

            result.content = pickle.dumps(tmp)
            self.session.commit()
        del queryPhish

        queryClean = self.session.query(self.Clean).all
        for result in queryClean:
            oldUrl = pickle.loads(result.content)

            tmp = UrlToDatabase.URL(result.url, True)

            tmp.http = oldUrl.http
            tmp.domain = oldUrl.domain
            tmp.whoisDomain = oldUrl.whoisDomain
            tmp.html = oldUrl.html
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

            result.content = pickle.dumps(tmp)
            self.session.commit()
        del queryClean
