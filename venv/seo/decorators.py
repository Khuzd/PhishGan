# -*- coding: UTF-8 -*-
from errors import InvalidUrlSchema



def validate_url_schema(function):
	def wrapper(url, *args, **kwargs):
		schema = url.split('://')[0]

		if schema in ['http', 'https']:
			return function(url, *args, **kwargs)
		else:
			raise InvalidUrlSchema()


	return wrapper