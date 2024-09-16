#!/usr/bin/env python3
#
# Helper routines
#

import re
import urllib

from datetime import datetime
from datetime import timedelta

#--------------------------------------------------------------------------

def jotform_date_to_datetime(d):
    # Google is showing three different date formats, depending on how
    # the volumn is formatted (even though they're actually just
    # different representations of the same date).  Shug.  Handle them
    # all.
    result = re.match(r'(\d{4})-(\d{2})-(\d{2}) (\d{1,2}):(\d{2}):(\d{2})', d)
    if result is not None:
        submit_date = datetime(year   = int(result.group(1)),
                               month  = int(result.group(2)),
                               day    = int(result.group(3)),
                               hour   = int(result.group(4)),
                               minute = int(result.group(5)),
                               second = int(result.group(6)))

    else:
        result = re.match(r'(\d{1,2})/(\d{1,2})/(\d{4}) (\d{1,2}):(\d{2}):(\d{2})', d)
        if result:
            submit_date = datetime(year   = int(result.group(3)),
                                   month  = int(result.group(1)),
                                   day    = int(result.group(2)),
                                   hour   = int(result.group(4)),
                                   minute = int(result.group(5)),
                                   second = int(result.group(6)))

        else:
            # According to
            # https://www.ablebits.com/office-addins-blog/2019/08/13/google-sheets-change-date-format/,
            # Google Sheets uses "0" as December 30, 1899.
            submit_date = datetime(month=12, day=30, year=1899)

            delta = timedelta(days=float(d))
            submit_date += delta

    return submit_date

#--------------------------------------------------------------------------

def jotform_text_to_int(val):
    if type(val) is int:
        return val

    val = val.strip()
    val = val.strip('$')
    if val == '':
        return 0

    # Someone actually put in a range.
    # Just take the lower value.
    if '-' in val:
        val = val[0 : val.index('-')]

    # Strip commas
    if ',' in val:
        val = val.replace(',', '')

    # If they put in a floating point value, convert that.
    # Otherwise straight convert as int.
    if '.' in val:
        # Someone actually put in multiple periods.  Just take up to
        # the 2nd period.  Crude, but effective.
        num_found = 0
        for i, c in enumerate(val):
            if c == '.':
                num_found += 1
                if num_found == 2:
                    val = val[:i]
                    break

        val = int(float(val))
    else:
        val = int(val)

    return val

#--------------------------------------------------------------------------

def url_escape(s):
    # JMS Do we need this?
    #return s.replace('\"', '\\"')
    return urllib.parse.quote_plus(s)

def pkey_url(env_id):
    return "' {0}".format(str(env_id).strip())
