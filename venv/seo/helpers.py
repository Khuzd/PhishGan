# -*- coding: UTF-8 -*-
import requests
from lxml import etree



def get_elements(url, xpath_expr, parser=etree.HTMLParser(recover=True)):
	r = requests.get(
		url,
		headers={
			'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1',
			'Accept-Language': 'ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3',
		}
	)
	xml = etree.fromstring(r.text.encode('utf-8'), parser=parser)
	return xml.xpath(xpath_expr)