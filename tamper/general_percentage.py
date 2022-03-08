#!/usr/bin/env python
# -*- coding:utf-8 -*-

import string

def general_percentage(payload):
	# -- general -- #
	if payload:
		_payload = ""
		i = 0 
		while i < len(payload):
			if payload[i] == '%' and (i<len(payload)-2) and payload[i+1:i+2] in string.hexdigits and payload[i+2:i+3] in string.hexdigits:
				_payload += payload[i:i+3]
				i += 3
			elif payload[i] != ' ':
				_payload += '%%%s'%payload[i]
				i += 1
			else:
				_payload += payload[i]
				i += 1
	return _payload