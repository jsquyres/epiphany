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

def get_synchronizations(cc_lists, ps_member_workgroups,
                         ps_families, ps_members, log):
    ecc = '@epiphanycatholicchurch.org'

    synchronizations = [
        {
            'source ps member wg' : 'Daily Gospel Reflections',
            'target cc list'      : 'SYNC Daily Gospel Reflections',
            'notify'              : f'ps-constantcontact-sync{ecc}',
        },
        {
            'source function'     : frtoan_letter_members_fn,
            'target cc list'      : 'SYNC Fr. Toan initial letter',
            'notify'              : f'ps-constantcontact-sync{ecc}',
        },
    ]

    #----------------------
    # Resolve the sources into lists of PS Members and the targets
    # into CC lists

    def _resolve_ps_member_workgroup(sync):
        key = 'source ps member wg'
        if key not in sync:
            return

        for wg in ps_member_workgroups.values():
            if wg['name'] == sync[key]:
                members = dict()
                for item in wg['membership']:
                    duid = item['py member duid']
                    members[duid] = ps_members[duid]

                log.debug(f'Found: PS Member Workgroup named "{sync[key]}" with {len(members)} PS Members')

                sync['SOURCE PS MEMBERS'] = members
                return

        # If we got here, we didn't find it
        log.error('Did not find a ParishSoft Member Workgroup named "{sync[key]}"')
        log.error("Aborting in despair")
        exit(1)

    def _resolve_python_function(sync):
        key = 'source function'
        if key not in sync:
            return

        members = sync['source function'](ps_families, ps_members, log)
        log.debug(f"Invoked Python function for source PS members, got {len(members)} PS Members")
        sync['SOURCE PS MEMBERS'] = members

    def _resolve_cc_list(sync):
        key = 'target cc list'
        if key not in sync:
            log.error("Did not find \"{key}\" in synchronization")
            log.error(pformat(sync))
            log.error("Aborting in despair")
            exit(1)

        found = False
        for l in cc_lists:
            if l['name'] == sync[key]:
                log.debug(f'Found: CC list named "{sync[key]}"')
                log.debug(pformat(l))
                sync[f'{key} data'] = l
                found = True
                break

        if not found:
            log.error('Did not find a Constant Conact List named "{sync[key]}"')
            log.error("Aborting in despair")
            exit(1)

    #----------------------

    for sync in synchronizations:
        log.debug(f'Resolving synchronization: {sync}')
        _resolve_ps_member_workgroup(sync)
        _resolve_python_function(sync)
        _resolve_cc_list(sync)

    return synchronizations

####################################################################

def frtoan_letter_members_fn(members, families, log):
    log.debug("IN FR TOAN LETTER MEMBER FN")
    return dict()

####################################################################

def set_contact_ps_member_duids(cc_contact, cc_client_id, cc_access_token, log):
    log.info("Setting Contact PS Member DUID custom field values")

    uuid = None
    for field in cc_contact_custom_fields:
        if field['name'] == 'ps_member_duids':
            uuid = field['custom_field_id']

    if uuid is None:
        log.error("Unable to find ps_member_duids contact custom field")
        log.error("Aborting in despair")
        exit(1)

    # Find all PS Member DUIDs for each contact
    for contact in cc_contacts:
        duids = list()
        for duid, member in members.items():
            email = member['emailAddress']

            if email == contact['email_address']['address']:
                duids.append(duid)

        # If we found DUIDs, update the contact via the CC API
        if len(duids) > 0:
            str_duids = [ str(duid) for duid in sorted(duids) ]
            contact['custom_fields'] = [
                {
                    'custom_field_id' : uuid,
                    'value' : ','.join(str_duids),
                },
            ]
            CC.update_contact(contact, cc_client_id, cc_access_token, log)

####################################################################

def delete_contacts_without_ps_duids(contacts, client_id, access_token, log):
    log.info("Deleting CC contacts that have no matching PS Member")

    key = 'PS MEMBER DUIDS'

    contacts_to_delete = [ contact for contact in contacts
                           if key not in contact ]
    # Don't actually delete contacts from CC until all contacts are
    # under Python control
    log.debug(f"Deleting {len(contacts_to_delete)} CC contacts with no PS Member DUIDs")
    log.warning(f"JMS STILL TO WRITE: use CC API to delete contacts with no DUIDs")

    contacts_to_save = [ contact for contact in contacts if key in contact ]
    log.debug(f"Keep {len(contacts_to_save)} CC contacts with PS Member DUIDs")
    return contacts_to_save

####################################################################

def update_contacts_from_ps_members(contacts, client_id, access_token, log):
    log.info("Looking for CC Contacts that need to be updated from PS Member data...")

    # First, look for an update in the email address.  This can get
    # messy: if a contact has multiple DUIDs and only some of them
    # have updated email addresses, we may have to create some new
    # contacts.

    # Take the simple case first: this contact has a single
    # corresponding PS Member.
    key = 'PS MEMBERS'
    for contact in contacts:
        if len(contact[key]) != 1:
            continue

        changes = list()

        # Check to see if we need to update the contact email address
        member = contact[key][0]


        if member['emailAddress'] is None:
            log.error(f'Contact somehow has a PS member email address of NONE')
            log.error(pformat(contact))
            log.error('Aborting in despair')
            exit(1)



        email = member['emailAddress'].lower()
        if contact['email_address']['address'] != email:
            contact['email_address']['address'] = email
            changes.append(f"email address: {contact['email_address']['address']}")

        ps_first = ParishSoft.get_member_preferred_first(member)
        if contact['first_name'] != ps_first:
            contact['first_name'] = ps_first
            changes.append(f"first name: {contact['first_name']}")

        ps_last = member['lastName']
        if contact['last_name'] != ps_last:
            contact['last_name'] = ps_last
            changes.append(f"last name: {contact['last_name']}")

        if len(changes) > 0:
            log.info(f'Updating Contact for PS Member {member["py friendly name FL"]} (DUID {member["memberDUID"]}): {changes}')
            CC.update_contact(contact, client_id, access_token, log)







    # JMS STILL TO WRITE: handle multiple DUIDs


####################################################################

def remove_unsubscribed_contacts(cc_contacts, synchronizations, log):
    log.info("Removing CC-unsubscribed contacts from PS data")

    key1 = 'PS MEMBER DUIDS'
    key2 = 'SOURCE PS MEMBERS'
    for contact in cc_contacts:
        if contact['email_address']['permission_to_send'] != 'unsubscribed':
            continue

        # This person unsubscribed via CC; remove them from synchronizations
        email = contact['email_address']['address']
        if key1 not in contact:
            # If this contact doesn't have a PS member DUID, then by
            # definition, they are not in any PS data structures (such
            # as Member Workgroups).  This shouldn't happen: all CC
            # contacts should have PS Member DUIDs, but we might as
            # well do some defensive programming here.
            continue

        if len(contact[key1]) == 0:
            continue

        duids = contact[key1]
        log.debug(f'Deleting CC unsubscribed PS Members {duids} from all synchronizations')
        for sync in synchronizations:
            for duid in duids:
                if duid in sync[key2]:
                    log.debug(f'Deleting CC unsubscribed PS Member {duid} {sync[key2][duid]["py friendly name FL"]} from synchronization {sync["target cc list"]}')
                    del sync[key2][duid]

####################################################################

def get_union_of_ps_members(synchronizations, log):
    log.info("Computing the union of all source PS members from synchronizations")

    union = dict()
    for sync in synchronizations:
        log.debug(f"- getting PS members for CC list {sync['target cc list']}")
        for duid, member in sync['SOURCE PS MEMBERS'].items():
            union[duid] = member

    log.debug(f"Found a total of {len(union)} PS Members for which we need contacts")
    return union

####################################################################

def find_missing_contacts(contacts, needed_ps_members, log):
    log.info("Finding PS members for which we need to create a CC contact")

    # Make a quick lookup list of DUIDs for which we have contacts
    contact_duids = dict()
    key = 'PS MEMBER DUIDS'
    for contact in contacts:
        if key not in contact:
            continue
        for duid in contact[key]:
            contact_duids[duid] = True

    # Find all Members for which we do not have a contact.
    #
    # Assemble the information first (before actually making CC API
    # calls to make the contacts) because we have to scan all the PS
    # members first to discover all the DUIDs for a given contact.
    contacts_to_create = dict()
    for duid, member in needed_ps_members.items():
        if duid not in contact_duids:
            email = member['emailAddress']
            if email not in contacts_to_create:
                contacts_to_create[email] = {
                    'email' : email,
                    'duids' : list(),
                }
            contacts_to_create[email]['duids'].append(duid)

    # Now that we have all the information, create the corresponding
    # CC contacts
    log.debug("Need to create the following CC contacts")
    log.debug(pformat(contacts_to_create))

def create_missing_contacts(missing_ps_members,
                            cc_client_id, cc_access_token, log):
    # JMS WRITE ME....
    pass

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
    log.info("Loading Constant Contact data...")
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

    #----------------------------------------

    # JMS Really only needed to do this once
    #set_contact_ps_member_duids(cc_contact, cc_client_id, cc_access_token, log)

    # Link Constant Contact Contacts to ParishSoft Members by the
    # ps_member_duids field
    log.info("Linking CC Contacts to PS Members...")
    CC.link_contacts_to_ps_members(cc_contacts, members, log)

    #----------------------------------------

    # Delete contacts that do not have PS Member DUIDs
    cc_contacts = delete_contacts_without_ps_duids(cc_contacts,
                                                   cc_client_id, cc_access_token,
                                                   log)

    # Find CC members that need updates from PS Member data
    update_contacts_from_ps_members(cc_contacts,
                                    cc_client_id, cc_access_token, log)

    # Get the synchronizations we're supposed to do
    synchronizations = get_synchronizations(cc_lists, member_workgroups,
                                            families, members, log)

    # Remove PS Members from synchronizations who explicitly
    # unsubscribed
    remove_unsubscribed_contacts(cc_contacts, synchronizations, log)

    # Get the union of all source PS members from the synchronizations
    all_needed_ps_members = get_union_of_ps_members(synchronizations, log)

    # Find members that do not have corresponding contacts
    missing_ps_members = find_missing_contacts(cc_contacts,
                                               all_needed_ps_members, log)

    # Make any CC Contacts that are needed that do not yet exist
    create_missing_contacts(missing_ps_members,
                            cc_client_id, cc_access_token, log)

if __name__ == '__main__':
    main()
