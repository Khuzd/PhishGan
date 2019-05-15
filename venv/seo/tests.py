# -*- coding: UTF-8 -*-
import unittest
import api
import errors



class TestGetFunctions(unittest.TestCase):
	def setUp(self):
		self.fake_url = 'http://urlneverexists23123.com/'
		self.bad_url = 'htt://httpmissing.com/'
		self.valid_url = 'http://www.google.com/'

		# The URLs without schema will not be accepted because
		# some kinds of API return 0 even if you provide invalid URL.
		# For example "httdgd://example.bad/url" and get_tweets will
		# show you 0. Thats not true cause you can simply have mistake in URL schema
		# and it will return 0, when the real metric is 99 or another.
		# You should always provide URLs with schemas.
		self.valid_url_without_schema = 'www.google.com'


	#def test_red_light(self):
	#	self.assertEqual( '1', '2' )



	def test_schema_validation_bad_url(self):
		with self.assertRaises(errors.InvalidUrlSchema):
			alexa = api.get_alexa(self.bad_url)



	def test_schema_validation_valid_url(self):
		alexa = api.get_alexa(self.valid_url)
		self.assertIsInstance(alexa, int)



	def test_schema_validation_without_schema(self):
		with self.assertRaises(errors.InvalidUrlSchema):
			alexa = api.get_alexa(self.valid_url_without_schema)



	def test_get_alexa_fake_url(self):
		alexa = api.get_alexa(self.fake_url)
		self.assertIsNone(alexa)



	def test_get_alexa_valid_url(self):
		alexa = api.get_alexa(self.valid_url)
		self.assertIsInstance(alexa, int)



	def test_get_alexa_valid_url_without_schema(self):
		with self.assertRaises(errors.InvalidUrlSchema):
			alexa = api.get_alexa(self.valid_url_without_schema)



	def test_get_semrush_fake_url(self):
		semrush = api.get_semrush(self.fake_url)
		self.assertIsNone(semrush)



	def test_get_semrush_valid_url(self):
		semrush = api.get_semrush(self.valid_url)
		self.assertIsInstance(semrush, int)



	def test_get_semrush_valid_url_without_schema(self):
		with self.assertRaises(errors.InvalidUrlSchema):
			semrush = api.get_semrush(self.bad_url)



	# TODO: Describe how twitter can collect tweets about fake URLs
	# Even if we provide fake URL to twitter API it will return
	# valid data, 0 tweets.
	def test_get_tweets_fake_url(self):
		tweets = api.get_tweets(self.fake_url)
		self.assertIsInstance(tweets, int)



	def test_get_tweets_valid_url(self):
		tweets = api.get_tweets(self.valid_url)
		self.assertIsInstance(tweets, int)



	def test_get_google_plus_fake_url(self):
		google_plus_count = api.get_google_plus(self.fake_url)
		self.assertIsInstance(google_plus_count, int)



	def test_get_google_plus_valid_url(self):
		google_plus_count = api.get_google_plus(self.valid_url)
		self.assertIsInstance(google_plus_count, int)



	def test_get_google_plus_valid_url_without_schema(self):
		with self.assertRaises(errors.InvalidUrlSchema):
			google_plus_count = api.get_google_plus(self.valid_url_without_schema)




if __name__ == '__main__':
	unittest.main()