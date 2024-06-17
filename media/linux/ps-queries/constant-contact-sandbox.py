#!/usr/bin/env python3

import os
import re
import sys
import csv
import json
import time
import logging
import httplib2
import logging.handlers
import datetime
import requests
import copy

# We assume that there is a "ecc-python-modules" sym link in this
# directory that points to the directory with ECC.py and friends.
moddir = '../../../python'
if not os.path.exists(moddir):
    print("ERROR: Could not find the ecc-python-modules directory.")
    print("ERROR: Please make a ecc-python-modules sym link and run again.")
    exit(1)
sys.path.insert(0, moddir)

import ECC
import ParishSoftv2 as ParishSoft
import ConstantContact as CC

from oauth2client import tools

from pprint import pprint
from pprint import pformat

# Globals

args = None
log = None

####################################################################
#
# Cross-reference CC contacts to ParishSoft members
#
####################################################################

def find_ps_members(contact, ps_members, log):
    email_address = contact['email_address']['address']

    def _value(contact, field_name):
        if field_name in contact:
            return contact[field_name]
        return ''

    first_name = _value(contact, 'first_name')
    last_name = _value(contact, 'last_name')

    log.debug(f"== Looking for ParishSoft member for {first_name} {last_name} <{email_address}>")

    # CC forces uniqueness of email addresses -- for any given email
    # address, there can only be a single contact with that address.
    # So just search for email address matches in PS members.
    matches = list()
    for member in ps_members.values():
        if member['emailAddress'] == email_address:
            matches.append(member)

    log.debug("FOUND {len(matches)} PS members with email address {email_address}")
    return matches

def link_cc_contacts_to_ps_members(cc_contacts,
                                    ps_members,
                                    log):
    result_key = 'PS MATCH RESULT'

    for contact in cc_contacts:
        if result_key not in contact:
            contact[result_key] = {}
        members = find_ps_members(contact, ps_members, log)
        if members and len(members) > 0:
            contact['ps_member'] = members
            mduids = [ str(m['memberDUID']) for m in members ]
            contact['memberDUID'] = ','.join(mduids)

            contact[result_key]['msg'] = f'searched and found {len(members)} corresponding ParishSoft Member(s)'
            contact[result_key]['action'] = 'add to cc'
        else:
            contact[result_key]['msg'] = 'failed to find a corresponding ParishSoft Member'
            contact[result_key]['action'] = 'delete from cc'

####################################################################

def report_csv(contacts, filename, log):
    fields = ['Email address', 'First name', 'Last name',
              'Matched to ParishSoft Member', 'Active ParishSoft Member',
              'ParishSoft Family DUID', 'In Constant Contact Lists',
              'Constant Contact Status', 'Constant Contact opt-out reason',
              'CC Street address', 'CC City', 'CC State', 'CC Zip']

    with open(filename, 'w', newline='') as fp:
        writer = csv.DictWriter(fp, fieldnames = fields)
        writer.writeheader()
        for contact in contacts:
            # Yes, there are contacts that do not have a first or last
            # name.  Sigh.
            first_name = ''
            if 'first_name' in contact:
                first_name = contact['first_name']
            last_name = ''
            if 'last_name' in contact:
                last_name = contact['last_name']

            familyDUID = None
            matched = 'No'
            active_ps_member = ''
            if 'memberDUID' in contact:
                matched = 'Yes'
                member = contact['ps_member']
                if not ParishSoft.member_is_active(member):
                    active_ps_member = 'No'
                else:
                    active_ps_member = 'Yes'
                if 'family' in member:
                    familyDUID = member['familyDUID']

            cc_status = contact['email_address']['permission_to_send']
            cc_opt_out_reason = ''
            if cc_status == 'unsubscribed':
                okey = 'opt_out_reason'
                if okey in contact['email_address']:
                    cc_opt_out_reason = contact['email_address'][okey]
                else:
                    cc_opt_out_reason = 'Unknown'

            num_cc_lists = len(contact['list_memberships_uuids'])

            cc_street = ''
            cc_city = ''
            cc_state = ''
            cc_zip = ''
            key = 'street_addresses'
            if key in contact and len(contact[key]) > 0:
                def _lookup(contact, key, field):
                    if field in contact[key][0]:
                        return contact[key][0][field]
                    return ''

                cc_street = _lookup(contact, key, 'street').strip()
                cc_city = _lookup(contact, key, 'city')
                cc_state = _lookup(contact, key, 'state')
                cc_zip = _lookup(contact, key, 'postal_code')

            item = {
                'Email address' : contact['email_address']['address'],
                'First name' : first_name,
                'Last name' : last_name,
                'Matched to ParishSoft Member' : matched,
                'Active ParishSoft Member' : active_ps_member,
                'ParishSoft Family DUID'   : familyDUID,
                'In Constant Contact Lists' : num_cc_lists,
                'Constant Contact Status' : cc_status,
                'Constant Contact opt-out reason' : cc_opt_out_reason,
                'CC Street address' : cc_street,
                'CC City' : cc_city,
                'CC State' : cc_state,
                'CC Zip' : cc_zip,
            }

            writer.writerow(item)

####################################################################

# Make CSVs for TJ
def find_no_paired_member_csv(contacts, filename, log):
    no_pair = []
    unsub_no_pair = []
    for contact in contacts:
        if 'ps_member' not in contact:
            if contact['email_address']['permission_to_send'] == 'unsubscribed':
                unsub_no_pair.append(contact)
            else:
                no_pair.append(contact)
    report_csv(no_pair, filename, log)
    report_csv(unsub_no_pair, 'unsubscribed_'+filename, log)


# Make CSVs for TJ
def find_inactive_paired_member_csv(contacts, filename, log):
    inactive_pair = []
    unsub_inactive_pair = []
    for contact in contacts:
        if 'ps_member' not in contact:
            continue
        if not ParishSoft.member_is_active(contact['ps_member']):
            if contact['email_address']['permission_to_send'] == 'unsubscribed':
                unsub_inactive_pair.append(contact)
            else:
                inactive_pair.append(contact)
    report_csv(inactive_pair, filename, log)
    report_csv(unsub_inactive_pair, 'unsubscribed_'+filename, log)

####################################################################

def setup_cli_args():
    tools.argparser.add_argument('--cc-auth-only',
                                default=False,
                                action='store_true',
                                help='Only authorizes to Constant Contact, does not do any work')

    tools.argparser.add_argument('--ps-api-keyfile',
                                 required=True,
                                 help='File containing the ParishSoft API key')

    tools.argparser.add_argument('--ps-cache-dir',
                                 default='datacache',
                                 help='Directory to cache the ParishSoft data')

    tools.argparser.add_argument('--cc-client-id',
                                default='constant-contact-client-id.json',
                                help="File containing the Constant Contact Client ID")

    tools.argparser.add_argument('--cc-access-token',
                                default='constant-contact-access-token.json',
                                help='File containing the Constant Contact access token')

    tools.argparser.add_argument('--dry-run',
                                 action='store_true',
                                 help='Do not actually update the Google Group; just show what would have been done')

    tools.argparser.add_argument('--verbose',
                                 action='store_true',
                                 default=True,
                                 help='If enabled, emit extra status messages during run')

    tools.argparser.add_argument('--debug',
                                 action='store_true',
                                 default=False,
                                 help='If enabled, emit even more extra status messages during run')

    tools.argparser.add_argument('--logfile',
                                 default="log.txt",
                                 help='Store verbose/debug logging to the specified file')

    global args
    args = tools.argparser.parse_args()

    # --dry-run implies --verbose
    if args.dry_run:
        args.verbose = True

    # --debug also implies --verbose
    if args.debug:
        args.verbose = True

    # Read the PS API key
    if not os.path.exists(args.ps_api_keyfile):
        print(f"ERROR: ParishSoft API keyfile does not exist: {args.ps_api_keyfile}")
        exit(1)
    with open(args.ps_api_keyfile) as fp:
        args.api_key = fp.read().strip()

    return args

####################################################################

def main():
    args = setup_cli_args()

    log = ECC.setup_logging(info=args.verbose,
                            debug=args.debug,
                            logfile=args.logfile, rotate = True,
                            slack_token_filename=None)

    log.info("Loading ParishSoft info...")
    families, members, family_workgroups, member_workgroups, ministries = \
        ParishSoft.load_families_and_members(api_key=args.api_key,
                                             active_only=False,
                                             parishioners_only=False,
                                             cache_dir=args.ps_cache_dir,
                                             log=log)

    # Read Constant Contact client ID and token files
    cc_client_id  = CC.load_client_id(args.cc_client_id, log)
    log.debug(f"Got cc_client_id: {cc_client_id}")
    log.debug(f"args.cc_access_token: {args.cc_access_token}")
    cc_access_token = CC.get_access_token(args.cc_access_token, cc_client_id, log)

    if args.cc_auth_only:
        log.info("Only authorizing to Constant Contact; exiting")
        exit(0)

    # Download all data from Constant Contact
    cc_contact_custom_fields = \
        CC.api_get_all(cc_client_id, cc_access_token,
                        'contact_custom_fields', 'custom_fields',
                        log)

    cc_lists = \
        CC.api_get_all(cc_client_id, cc_access_token,
                        'contact_lists', 'lists',
                        log)

    cc_contacts = \
        CC.api_get_all(cc_client_id, cc_access_token,
                        'contacts', 'contacts',
                        log,
                        include='custom_fields,list_memberships,street_addresses')

    # Link various Constant Contact data members together
    CC.link_cc_data(cc_contacts, cc_contact_custom_fields,
                    cc_lists, log)

    # Link Constant Contact Contacts to ParishSoft Members
    link_cc_contacts_to_ps_members(cc_contacts, members, log)

    # Make CSVs for TJ
    #find_no_paired_member_csv(cc_contacts, "cc_with_no_ps_member.csv", log)
    #find_inactive_paired_member_csv(cc_contacts, 'cc_with_inactive_ps_member.csv', log)

if __name__ == '__main__':
    main()
