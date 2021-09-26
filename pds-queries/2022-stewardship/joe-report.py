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

# Dictionary of totals to be modified by pledge_comparison_report() and then
# accessed / computed upon when creating the CSV
pledge_comparison = {
    "cannot pledge" : { "households" : 0, "dollar impact" : 0, "total of pledges" : 0},
    "reduced pledge" : { "households" : 0, "dollar impact" : 0, "total of pledges" : 0},
    "no change" : { "households" : 0, "dollar impact" : 0, "total of pledges" : 0},
    "new pledge" : { "households" : 0, "dollar impact" : 0, "total of pledges" : 0},
    "increased pledge" : { "households" : 0, "dollar impact" : 0, "total of pledges" : 0}
}

# Converts the pledge_comparison dictionary filled by pledge_comparison_report()
# into a CSV and does some computation on it.
def pledge_report_csv(report_dict, pledge_sum, households):
    filename = "pledge_report.csv"
    with open(filename, "w") as csvfile:
        fieldnames = ["Category", "# of Households", "% of Total Households",
                  "Dollar Impact", "Pledge Total", "% of Total Pledge Sum"]
        report_writer = csv.DictWriter(csvfile, fieldnames = fieldnames)
        report_writer.writeheader()
        for category in report_dict:
            # Variables of stats for this specific category
            cat_households = report_dict[category]["households"]
            cat_households_percent = round((cat_households / households) * 100)
            cat_dollar_impact = report_dict[category]["dollar impact"]
            cat_pledge_sum = report_dict[category]["total of pledges"]
            cat_pledge_percent = round((cat_pledge_sum / pledge_sum) * 100)
            csv_dict = {
                "Category" : category,
                "# of Households" : cat_households,
                "% of Total Households" : cat_households_percent,
                "Dollar Impact" : cat_dollar_impact,
                "Pledge Total" : cat_pledge_sum,
                "% of Total Pledge Sum" : cat_pledge_percent
            }
            report_writer.writerow(csv_dict)
    print(f"Wrote {filename}")

# Compares the dictionaries of pledges from this year to that of last year, and
# outputs a CSV showing a few statistics relating to which category the pledges
# falls into (Can't, Reduced, No Change, New, Increased) and some relevant info
# / analysis on totals and percentages.
def pledge_comparison_report(this_year_pledges, last_year_pledges):
    pledge_total = 0
    households = len(this_year_pledges)
    for fid in this_year_pledges:
        current_pledge = this_year_pledges[fid]["pledge"]
        pledge_total += current_pledge
        # If a family is not found in last_year_pledges, then their FID is not a
        # key, and a KeyError will be raised. This means that they are
        # considered a new pledge. Since a previous pledge of 0 with a current
        # non-zero pledge is also considered "new," then we'll just catch that
        # case later and set the category there.
        key = "pledge"
        previous_pledge = 0
        if fid in last_year_pledges and key in last_year_pledges[fid]:
            previous_pledge = last_year_pledges[fid][key]
        if this_year_pledges[fid]["participate"] == False:
            category = "cannot pledge"
            current_pledge = 0
        elif current_pledge == previous_pledge:
            category = "no change"
        elif previous_pledge == 0 and current_pledge > 0:
            category = "new pledge"
        elif current_pledge > previous_pledge:
            category = "increased pledge"
        elif current_pledge < previous_pledge:
            category = "reduced pledge"
        dollar_impact = current_pledge - previous_pledge
        pledge_comparison[category]["households"] += 1
        pledge_comparison[category]["dollar impact"] += dollar_impact
        pledge_comparison[category]["total of pledges"] += current_pledge
    pledge_report_csv(pledge_comparison, pledge_total, households)

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
