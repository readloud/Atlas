#!/usr/bin/env python

"""
Copyright (c) 2019 Matthew Moses
See the file 'LICENSE' for copying permission

[!] legal disclaimer:
Developers assume no liability and are not responsible for any misuse or damage caused by this program.
Use responsibly. Do good.

"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Escapes a char encoded payload

    Tested against:
        * This is just a proof of concept but used for SQL injection against MySQL 5.7.25
          via a GraphQL query

    Notes:
        * Useful when passing a char unicode encoded payload as part of the GraphQL query as a string via a JSON context

    >>> tamper('\u0022')
    '\\u0022'
    """

    retVal = payload

    if payload:
        retVal = retVal.replace("\\", "\\\\")

    return retVal
