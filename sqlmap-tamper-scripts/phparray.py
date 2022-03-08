#!/usr/bin/env python

"""
Copyright (c) 2017 Cyberis Ltd (https://www.cyberis.co.uk)
"""

from lib.core.enums import PRIORITY
from phpserialize import *
from base64 import b64encode,b64decode
from collections import Iterable
from urllib import quote_plus,unquote_plus
import shelve

__priority__ = PRIORITY.HIGHEST

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.
    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).
    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
                "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("Invalid default answer: '%s'" % default)

    while True:
        choice = raw_input(question + prompt).lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print("Please respond with 'yes' or 'no' "
                                "(or 'y' or 'n').\n")

def dependencies():
	if query_yes_no("Is the parameter base64 encoded? (Y/n) "):
		shelf = shelve.open("phpObj.txt")
		shelf["encoding"] = "b64"
		shelf.close()
		encodedObj = ''
		encodedObj = raw_input("Enter the encoded serialized array: ")
		decodedObj = b64decode(encodedObj)
		phpObj = loads(decodedObj)
	elif query_yes_no("Is the parameter URL encoded? (Y/n) "):
		shelf = shelve.open("phpObj.txt")
		shelf["encoding"] = "url"
		shelf.close()
		encodedObj = ''
		encodedObj = raw_input("Enter the encoded serialized array: ")
		decodedObj = unquote_plus(encodedObj)
		phpObj = loads(decodedObj)

	count = 0

	print("Select item to inject:")

	for row in phpObj:
		if not isinstance(phpObj[row],str):
			if isinstance(phpObj[row], Iterable):
				for item in phpObj[row]:
					count += 1
					print(str(count) + ". " + phpObj[row][item])

	choice = 0
	while choice == 0:
		try:
			choice = int(raw_input("Selection: "))
		except ValueError:
			choice = 0
		continue

	count = 0
	for row in phpObj:
		if not isinstance(phpObj[row],str):
			if isinstance(phpObj[row], Iterable):
				for item in phpObj[row]:
					count += 1
					if count == choice:
						phpObj[row][item] = "*"

	shelf = shelve.open("phpObj.txt")
	shelf["phpObj"] = phpObj
	shelf.close()	

def tamper(payload, **kwargs):
	shelf = shelve.open("phpObj.txt")
	phpObj = shelf["phpObj"]
	encoding = shelf["encoding"]
	shelf.close()
	for row in phpObj:
		if not isinstance(phpObj[row],str):
			if isinstance(phpObj[row], Iterable):
				for item in phpObj[row]:
					if phpObj[row][item] == "*":
						phpObj[row][item] = payload
	
	if encoding == "url":
		output = quote_plus(dumps(phpObj))
	elif encoding == "b64":
		output = b64encode(dumps(phpObj))
	else:
		output = dumps(phpObj)
	return output