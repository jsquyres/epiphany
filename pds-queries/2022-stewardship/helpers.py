#!/usr/bin/env python3
#
# Helper routines
#

import sys
sys.path.insert(0, '../../python')

import re

from datetime import datetime
from datetime import timedelta

#--------------------------------------------------------------------------

# "year" is of the form: f'{stewardship_year - 2000 - 1:02}'
def calculate_family_values(family, year, log=None):
    print(f"JMS Calculating family values: {family['Name']}, year: {year}")
    if 'funds' in family and year in family['funds']:
        funds = family['funds'][year]
    else:
        funds = dict()

    if log:
        log.debug(f"Size of family funds dictionary: {len(funds)}")

    # Calculate 3 values:
    # 1. Pledge amount for CY{year}
    # 2. Total amount given in CY{year} so far
    # 3. Family names
    pledged = 0
    for id, fund in funds.items():
        # We only want fund 1: stewardship contributions
        if id != '1':
            continue

        fund_rate = fund['fund_rate']
        if fund_rate and fund_rate['FDTotal']:
            pledged += int(fund_rate['FDTotal'])

    contributed = 0
    for id, fund in funds.items():
        # We only want fund 1: stewardship contributions
        if id != '1':
            continue

        for item in fund['history']:
            # Not quite sure how this happens, but sometimes the value is None.
            val = item['item']['FEAmt']
            if val is not None:
                contributed += val

    family['calculated'] = {
        "pledged"        : pledged,
        "contributed"    : contributed,
        "household_name" : family['hoh_and_spouse_salutation'],
    }
    print(f"JMS: calculated for family: {family['calculated']}")

#--------------------------------------------------------------------------

def jotform_date_to_datetime(d):
    # Google is showing three different date formats, depending on how
    # the volumn is formatted (even though they're actually just
    # different representations of the same date).  Shug.  Handle them
    # all.
    result = re.match('(\d{4})-(\d{2})-(\d{2}) (\d{1,2}):(\d{2}):(\d{2})', d)
    if result is not None:
        submit_date = datetime(year   = int(result.group(1)),
                               month  = int(result.group(2)),
                               day    = int(result.group(3)),
                               hour   = int(result.group(4)),
                               minute = int(result.group(5)),
                               second = int(result.group(6)))

    else:
        result = re.match('(\d{1,2})/(\d{1,2})/(\d{4}) (\d{1,2}):(\d{2}):(\d{2})', d)
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

def url_escape(s):
    return s.replace('\"', '\\"')

def pkey_url(env_id):
    return "' {0}".format(str(env_id).strip())
