# -*- coding: UTF-8 -*-


class Error(Exception):
	pass


class UrlListInputError(Error):

	def __init__(self, url_count):
		self.url_count = url_count

	def __str__(self):
		return 'Provided %d URLs. Expected 10 or less URLs.' % self.url_count



class ApiServerError(Error):

	def __init__(self, status_code, msg):
		self.status_code = status_code
		self.msg = msg

	def __str__(self):
		return 'Status code: %s - %s' % ( self.status_code, self.msg )



class InvalidUrlSchema(Error):

	def __str__(self):
		return 'Invalid URL schema provided. Expected "http" or "https"'