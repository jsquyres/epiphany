#!/usr/bin/env python3

import csv
import json

import constants
import constants_2021

from pprint import pprint

def read_jotform_csv(filename, fieldnames):
    def _make_final_fieldnames(filednames):
        # Some of the field names will be lists.  In those cases, use the first field name in the list.
        final_fieldnames = list()
        final_fieldnames.extend(fieldnames['prelude'])
        for member in fieldnames['members']:
            final_fieldnames.extend(member)
        final_fieldnames.extend(fieldnames['family'])
        final_fieldnames.extend(fieldnames['epilog'])

        return final_fieldnames

    #----------------------------------------------------------------------

    def _read_jotform_data(filename, fieldnames):
        rows = dict()
        with open(filename) as fp:
            csvreader = csv.DictReader(fp, fieldnames=fieldnames)

            for row in csvreader:
                # Skip title row
                if 'Submission' in row['SubmitDate']:
                    continue

                # As of Sep 2021, Google Sheets CSV export sucks. :-(
                # The value of the "Edit Submission" field from Jotform is something
                # like:
                #
                # =HYPERLINK("https://www.jotform.com/edit/50719736733810","Edit Submission")
                #
                # Google Sheet CSV export splits this into 2 fields.  The first one
                # has a column heading of "Edit Submission" (which is what the
                # Jotform-created sheet column heading it) and contains the long number
                # in the URL.  The 2nd one has no column heading, and is just the words
                # "Edit Submission".  :-(  CSV.DictReader therefore puts a value of
                # "Edit Submission" in a dict entry of "None" (because it has no column
                # heading).
                #
                # For our purposes here, just delete the "None" entry from the
                # DictReader.
                if None in row and row[None] == ['Edit Submission']:
                    del row[None]

                rows[row['fid']] = row

        return rows

    #----------------------------------------------------------------------

    final_fieldnames = _make_final_fieldnames(fieldnames)
    jotform_dict = _read_jotform_data(filename, final_fieldnames)

    return jotform_dict

#---------------------------------------------------------------------------

def convert_to_int(val):
    val = val.strip()
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
        val = int(float(val))
    else:
        val = int(val)

    return val

#---------------------------------------------------------------------------

def convert_2022_jotform(jotform):
    out = dict()
    for fid, data in jotform.items():
        participate = False if data['CY2022 participation'].startswith("Because") else True

        pledge = 0
        if participate:
            pledge = convert_to_int(data['CY2022 pledge'])
            if pledge == '':
                pledge = 0

        out[fid] = {
            'participate' : participate,
            'pledge' : pledge,
        }

    return out

#---------------------------------------------------------------------------

def convert_2021_jotform(jotform):
    out = dict()
    for fid, data in jotform.items():
        #print(f"Fid: {fid}, {data}")
        #pprint(data)

        pledge = convert_to_int(data['CY2021 pledge'])
        if pledge == '':
            pledge = 0

        out[fid] = {
            # There was no "I will not participate" checkbox in 2021
            'participate' : True,
            'pledge' : pledge,
        }

    return out

#---------------------------------------------------------------------------

def pledge_comparison_report(this_year_data, last_year_data):
    # Joe to fill in here
    pass

#---------------------------------------------------------------------------

def main():
    this_year_filename = 'ECC 2022 Stewardship Renewal - Form Responses.csv'
    this_year_jotform = read_jotform_csv(this_year_filename,
            constants.jotform_gsheet_columns)
    this_year_data = convert_2022_jotform(this_year_jotform)

    last_year_filename = 'ECC 2021 Stewardship Renewal_ Combined ministry and pledge form - Form Responses.csv'
    last_year_jotform = read_jotform_csv(last_year_filename,
            constants_2021.jotform_gsheet_columns)
    last_year_data = convert_2021_jotform(last_year_jotform)

    pledge_comparison_report(this_year_data, last_year_data)

main()
