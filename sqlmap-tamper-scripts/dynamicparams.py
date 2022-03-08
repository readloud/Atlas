#!/usr/bin/env python

from lib.core.enums import PRIORITY
from time import time
from hashlib import sha1

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    if payload:
        ts = str(time())[0:10]
        tsHash = sha1(ts).hexdigest()
        uHash = tsHash[:20]
        pHash = tsHash[20:]

        username = 'username' + uHash
        password = 'password' + pHash
        
        payload = ("&%s=%s&%s=" % (username, payload, password))

        # print "-" * 24
        # print payload
        # print "-" * 24

        return payload