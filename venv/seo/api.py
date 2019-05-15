# -*- coding: UTF-8 -*-
import json

import requests
from lxml import etree

from errors import UrlListInputError
from errors import ApiServerError

from decorators import validate_url_schema
from helpers import get_elements



@validate_url_schema
def get_alexa(url):
	rank = None
	request_url = 'http://xml.alexa.com/data?cli=10&dat=nsa&ver=quirk-searchstatus&url=%s' % url
	popularity = get_elements(request_url, '//POPULARITY', parser=etree.XMLParser(encoding='utf-8'))
	if len(popularity):
		rank = int(popularity[0].get('TEXT'))
	return rank



@validate_url_schema
def get_semrush(url):
	semrush = None
	request_url = 'http://seoquake.publicapi.semrush.com/info.php?url=%s' % url
	keywords = get_elements(request_url, '//keywords', parser=etree.XMLParser(encoding='utf-8'))
	if len(keywords):
		semrush = int(keywords[0].text)
	return semrush



@validate_url_schema
def get_tweets(url):
	request_url = 'http://urls.api.twitter.com/1/urls/count.json?url=%s' % url
	r = requests.get(request_url)
	twitter_data = r.json()
	return twitter_data['count']



@validate_url_schema
def get_google_plus(url):
	google_plus_count = None
	request_url = 'https://plusone.google.com/u/0/_/+1/fastbutton?count=true&url=%s' % url
	google_plus_tag = get_elements(request_url, "//div[@id='aggregateCount']")
	if len(google_plus_tag):
		google_plus_count = int(google_plus_tag[0].text.replace(u'\xa0', '').replace('>', ''))
	return google_plus_count



@validate_url_schema
def get_facebook_likes(url):
	likes = None
	request_url = 'http://www.facebook.com/plugins/like.php?layout=button_count&href=%s' % url
	likes_tag = get_elements(request_url, "//span[@class='pluginCountTextDisconnected']")
	if len(likes_tag):
		likes = likes_tag[0].text
	return likes



def get_seomoz_data(url_list, auth_creds, cols='103079215104', round_response=True):
	if len(url_list) > 10:
		raise UrlListInputError(len(url_list))

	data = json.dumps(url_list)
	request_url = 'http://lsapi.seomoz.com/linkscape/url-metrics/?Cols=%s' % cols
	r = requests.post(request_url, data=data, auth=auth_creds)

	if r.status_code != 200:
		raise ApiServerError(r.json['status'], r.json['error_message'])

	seomoz_data = r.json()
	if round_response:
		for item in seomoz_data:
			item['pda'], item['upa'] = round(item['pda']), round(item['upa'])

	return seomoz_data