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

def get_synchronizations(cc_contacts, cc_lists, ps_member_workgroups,
                         ps_members, ps_families, log):
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

        members = sync['source function'](cc_contacts, cc_lists,
                                          ps_member_workgroups,
                                          ps_members, ps_families,
                                          log)
        log.debug(f"Invoked Python function for source PS members, got {len(members)} PS Members")
        sync['SOURCE PS MEMBERS'] = members

    def _resolve_cc_list(sync):
        key = 'target cc list'
        if key not in sync:
            log.error("Did not find \"{key}\" in synchronization")
            log.error(pformat(sync, depth=3))
            log.error("Aborting in despair")
            exit(1)

        found = False
        for l in cc_lists:
            if l['name'] == sync[key]:
                log.debug(f'Found: CC list named "{sync[key]}"')
                log.debug(pformat(l, depth=3))
                sync[f'TARGET CC LIST'] = l
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

# Just for Fr. Toan's letter
def frtoan_letter_members_fn(cc_contacts, cc_lists,
                             member_workgroups, members, families, log):
    log.debug("IN FR TOAN LETTER MEMBER FN")

    # Make a cross-reference list of CC contacts by DUID
    key = 'PS MEMBER DUIDS'
    contacts_by_duid = dict()

    for contact in cc_contacts:
        if key not in contact:
            continue
        for duid in contact[key]:
            contacts_by_duid[duid] = contact

    key = 'emailAddress'
    send_email_members = dict()
    no_email_families = list()

    for family in families.values():
        # This catches both inactive families and families where all
        # members are deceased.
        if not ParishSoft.family_is_active(family):
            continue

        found_member = False
        for member in family['py members']:
            if key not in member:
                continue
            if member[key] is None:
                continue
            if len(member[key]) == 0:
                continue
            if not ParishSoft.member_is_active(member):
                continue

            happy = False
            if not family['sendNoMail']:
                happy = True

            duid = member['memberDUID']
            if duid in contacts_by_duid:
                if contacts_by_duid[duid]['email_address']['permission_to_send'] != 'unsubscribed':
                    happy = True

            if happy:
                send_email_members[duid] = member
                found_member = True

        if not found_member:
            no_email_families.append(family)

    log.debug(f"Found {len(send_email_members)} Member emails we can send Fr. Toan's letter")

    send_usps_families = dict()
    for family in no_email_families:
        # We already know it's an active Family with at least 1 alive
        # Member, and didn't meet the email criteria

        if family['sendNoMail']:
            continue
        if family['primaryAddress1'] and family['primaryCity'] and \
           family['primaryPostalCode'] and family['primaryState']:
            send_usps_families[family['familyDUID']] = family

    log.debug(f"Found {len(send_usps_families)} Families to send USPS mail for Fr. Toan's letter")

    #---------------------------------

    def _write_usps(filename, families):
        fields = ['Family name',
                  'Family DUID',
                  'Street address 1',
                  'Street address 2',
                  'Street address 3',
                  'City', 'State', 'Zip']

        with open(filename, 'w') as fp:
            writer = csv.DictWriter(fp, fieldnames = fields)
            writer.writeheader()

            for duid, family in families.items():
                zip = family['primaryPostalCode']
                if family['primaryZipPlus']:
                    zip += '-' + family['primaryZipPlus']

                item = {
                    'Family name' : f'{family["firstName"]} {family["lastName"]}',
                    'Family DUID' : duid,
                    'Street address 1' : family['primaryAddress1'],
                    'Street address 2' : family['primaryAddress2'],
                    'Street address 3' : family['primaryAddress3'],
                    'City' : family['primaryCity'],
                    'State' : family['primaryState'],
                    'Zip' : zip
                }
                writer.writerow(item)
            log.info(f"Wrote {filename}")

    #---------------------------------

    _write_usps('fr-toan-letter-usps-addresses.csv',
                send_usps_families)

    #---------------------------------

    # Make a list of all Inactive Families where at least one Member
    # is alive
    inactive_families = dict()
    for duid, family in families.items():
        # This catches both inactive families and families where all
        # members are deceased.
        if ParishSoft.family_is_active(family):
            continue

        # So we have to check to make sure there's at least one Member
        # who is not deceased
        keep = False
        for member in family['py members']:
            if member['memberStatus'] != 'Deceased':
                keep = True
        if not keep:
            continue

        if family['sendNoMail']:
            continue
        if family['primaryAddress1'] and family['primaryCity'] and \
           family['primaryPostalCode'] and family['primaryState']:
            inactive_families[duid] = family

    _write_usps('fr-toan-letter-inactive-usps-addresses.csv',
                inactive_families)

    return send_email_members

#-------------------------------------------------

# Just for Fr. Toan's letter
def report_csv(contacts, log):
    filename = 'cc-contacts-raw-data.csv'
    fields = ['Email address', 'First name', 'Last name',
              'Matched to PDS Member', 'Active PDS Member', 'PDS envelope ID',
              'In Constant Contact Lists',
              'Constant Contact Status', 'Constant Contact opt-out reason',
              'CC Street address', 'CC City', 'CC State', 'CC Zip']

    with open(filename, 'w') as fp:
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

            matched = 'No'
            active_pds_member = ''
            pds_env_id = ''
            if 'pds_mid' in contact:
                matched = 'Yes'
                member = contact['pds_member']
                if member['Inactive']:
                    active_pds_member = 'No'
                else:
                    active_pds_member = 'Yes'
                key = 'family'
                if key in member:
                    pds_env_id = "' " + member[key]['ParKey'].strip()

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

                cc_street = _lookup(contact, key, 'street')
                cc_city = _lookup(contact, key, 'city')
                cc_state = _lookup(contact, key, 'state')
                cc_zip = _lookup(contact, key, 'postal_code')

            item = {
                'Email address' : contact['email_address']['address'],
                'First name' : first_name,
                'Last name' : last_name,
                'Matched to PDS Member' : matched,
                'Active PDS Member' : active_pds_member,
                'PDS envelope ID' : pds_env_id,
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

# JMS Really only needed to do this once
# JMS This can now probably be deleted...?
def set_contact_ps_member_duids(cc_contact_custom_fields, cc_contacts,
                                cc_client_id, cc_access_token,
                                members, log):
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

            # SHORT CUT
            # Only do this for contacts that don't already have a DUID set
            found = False
            if 'custom_fields' in contact:
                for cf in contact['custom_fields']:
                    if cf['custom_field_id'] == uuid:
                        # Found it!  We can skip this one
                        found = True
                        break
            if found:
                continue

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






    # JMS WRITE ME
    log.warning(f"JMS STILL TO WRITE: mark contacts in the TO-DO ACTIONS field that they should be deleted")








    contacts_to_save = [ contact for contact in contacts if key in contact ]
    log.debug(f"Keep {len(contacts_to_save)} CC contacts with PS Member DUIDs")
    return contacts_to_save

####################################################################

def update_contacts_from_ps_members(contacts, client_id, access_token, log):
    key1 = 'PS MEMBERS'
    key2 = 'TO-DO ACTIONS'

    def _update_duid(contact, client_id, access_token, log):
        # Check to see if we need to update the contact email address
        member = contact[key1][0]

        if member['emailAddress'] is None:
            log.error(f'Contact somehow has a PS member email address of NONE')
            log.error(pformat(contact))
            log.error('Aborting in despair')
            exit(1)

        email = member['emailAddress']
        if contact['email_address']['address'] != email:
            old = contact['email_address']['address']
            contact['email_address']['address'] = email
            log.info(f"Update contact email address: {old} --> {email}")
            contact[key2]['update'] = True

        # Apparently, CC doesn't like first names with periods in them (!!)
        # E.g., "K.C." will fail to be set at CC.
        ps_first = ParishSoft.get_member_preferred_first(member)
        ps_first = ps_first.replace('.', '').strip()
        if contact['first_name'] != ps_first:
            old = contact['first_name']
            contact['first_name'] = ps_first
            log.info(f"Update contact {email} first name: {old} --> {ps_first}")
            contact[key2]['update'] = True

        ps_last = member['lastName'].strip()
        if contact['last_name'] != ps_last:
            old = contact['last_name']
            contact['last_name'] = ps_last
            log.info(f"Update contact {email} last name: {old} --> {ps_last}")
            contact[key2]['update'] = True

    def _update_duids(contact, client_id, access_token, log):







        # JMS WRITE ME

        # Handle the case where there's multiple DUIDs on this single
        # contact.  Need to handle a bunch of sub-cases: e.g., if one
        # PS member changes email address and the other does not,
        # ... etc.








        pass

    #----------------------------------------

    log.info("Looking for CC Contacts that need to be updated from PS Member data...")

    # First, look for an update in the email address.  This can get
    # messy: if a contact has multiple DUIDs and only some of them
    # have updated email addresses, we may have to create some new
    # contacts.

    # Take the simple case first: this contact has a single
    # corresponding PS Member.
    for contact in contacts:
        if len(contact[key1]) == 1:
            _update_duid(contact, client_id, access_token, log)
        else:
            _update_duids(contact, client_id, access_token, log)

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
                    member = sync[key2][duid]
                    log.debug(f'Deleting CC unsubscribed PS Member {duid} {member["py friendly name FL"]} <{member["emailAddress"]}> from synchronization {sync["target cc list"]}')
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

def create_missing_contacts(contacts, needed_ps_members, log):
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
            # This is a PS member that does not have a corresponding
            # CC contact
            email = member['emailAddress']
            if email not in contacts_to_create:
                contacts_to_create[email] = {
                    'email' : email,
                    'duids' : list(),
                    'ps members' : list(),
                }
            contacts_to_create[email]['duids'].append(duid)
            contacts_to_create[email]['ps members'].append(member)

    # Now that we have all the information, create the corresponding
    # CC contacts
    log.debug(f"Need to create CC contacts for {len(contacts_to_create)} email addresses")
    log.debug(pformat(contacts_to_create.keys()))

    new_contacts = list()
    for email, data in contacts_to_create.items():
        log.debug(f"Creating contact data structure for {email}")
        contact = CC.create_contact_dict(email,
                                         data['duids'],
                                         data['ps members'],
                                         log)
        new_contacts.append(contact)

    return new_contacts

####################################################################

def compute_sync(synchronizations, contacts, log):
    log.info("Resolving PS Members from synchronizations to CC contacts")

    # Make a DUID -> CC contact dictionary for quick lookups
    email_to_contact = dict()
    for contact in contacts:
        email = contact['email_address']['address']
        email_to_contact[email] = contact

    # The SOURCE PS MEMBERS represents the set of PS members that we
    # want in this CC list.  The TARGET CC LIST represents the list of
    # contacts that are already in the list.
    #
    # We need to compute the difference between the two, keeping in
    # mind that there may be multiple PS Members that map to a single
    # CC contact.

    key1 = 'SOURCE PS MEMBERS'
    key2 = 'TARGET CC LIST'
    key3 = 'TO-DO ACTIONS'
    for sync in synchronizations:
        for key in [key1, key2]:
            if key not in sync:
                log.error("Cannot found {key} in synchronization \"{sync['target cc list']}\"")
                log.error("Aborting in despair")
                exit(1)

        # UUID of this list
        list_uuid = sync[key2]['list_id']
        list_name = sync['target cc list']

        emails_of_members = { member['emailAddress'] : member
                              for member in sync[key1].values() }
        emails_of_contacts = { email : contact
                               for email, contact in sync[key2]['CONTACTS'].items() }

        # First, find PS Members who are not in the CC list
        for email, member in emails_of_members.items():
            if email not in emails_of_contacts:
                # Need to add this list UUID to the contact
                # corresponding to the PS member
                log.debug(f"Need to add {email} to {list_name}")
                contact = email_to_contact[email]

                contact['list_memberships'].append(list_uuid)
                contact['LIST MEMBERSHIPS'].append(list_name)
                log.debug(f"Added UUID: {list_uuid}")
                log.debug(f"to list: {contact['list_memberships']}")

                contact[key3]['update'] = True

        # Now find CC contacts who are not in the PS Members
        for email, contact in emails_of_contacts.items():
            if email not in emails_of_members:
                # Need to remove this list UUID from the contact
                # corresponding to this email
                log.debug(f"Need to remove {email} from {list_name}")

                contact['list_memberships'].remove(list_uuid)
                contact['LIST MEMBERSHIPS'].remove(list_name)
                log.debug(f"Removed UUID: {list_uuid}")
                log.debug(f"from list: {contact['list_memberships']}")

                contact[key3]['update unsub'] = True

####################################################################

def perform_cc_actions(cc_contacts, client_id, access_token, log):
    key = 'TO-DO ACTIONS'
    for contact in cc_contacts:
        if len(contact[key]) == 0:
            continue

        actions = contact[key]

        # Check to see what actions are in there
        # - create / update
        # - delete

        if 'delete' in actions:




            # JMS WRITE ME
            pass




        else:
            if 'create' in actions or 'update' in actions:
                # We need to update this contact at CC



                # JMS What to do about contacts that now have an empty
                # list membership?  We can't do a CC API "update" if the
                # list membership is empty.  Figure this out later...
                if len(contact['list_memberships']) == 0:
                    email = contact['email_address']['address']
                    log.error(f"ERROR: Did not delete contact {email} from lists")
                    continue

                CC.create_contact(contact, client_id, access_token, log)

            if 'update ubsub' in actions:
                # The CC.create_contact() function will update a bunch
                # of things, but it can only *add* lists to which a
                # contact is subscribed.  If the contact needs to be
                # removed from lists, we have to make a second call.
                # This isn't necessarily super-efficient -- we could
                # probably add more clever logic here to combine these
                # two into a single call... but there's no real need
                # to.  So let's just have (more or less) clear code.
                #
                # NOTE: We only need to do this to contacts that
                # already existed at CC -- if we just created the
                # contact, then it will have set the exact set of
                # lists that we want already; no need to do anything
                # else.
                CC.update_contact_full(contact, client_id, access_token, log)

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
    log.debug("Downloaded CC contact custom fields")
    log.debug(pformat(cc_contact_custom_fields))

    cc_lists = \
        CC.api_get_all(cc_client_id, cc_access_token,
                       'contact_lists', 'lists',
                       log)
    log.debug("Downloaded CC lists")
    log.debug(pformat(cc_lists))

    cc_contacts = \
        CC.api_get_all(cc_client_id, cc_access_token,
                       'contacts', 'contacts',
                       log,
                       include='custom_fields,list_memberships,street_addresses',
                       # Get all contacts -- even those who have been
                       # deleted.
                       status='all')
    log.debug("Downloaded CC contacts")
    log.debug(pformat(cc_contacts))

    # Link various Constant Contact data members together
    CC.link_cc_data(cc_contacts, cc_contact_custom_fields,
                    cc_lists, log)

    # Make all contact email addresses be lower case
    for contact in cc_contacts:
        contact['email_address']['address'] = \
            contact['email_address']['address'].lower()

    #----------------------------------------

    # JMS Really only needed to do this once
    #set_contact_ps_member_duids(cc_contact_custom_fields, cc_contacts,
    #                            cc_client_id, cc_access_token,
    #                            members, log)

    # Link Constant Contact Contacts to ParishSoft Members by the
    # ps_member_duids field
    log.info("Linking CC Contacts to PS Members...")
    CC.link_contacts_to_ps_members(cc_contacts, members, log)

    #----------------------------------------

    # For all existing contacts, the list of actions is (currently)
    # nothing
    key = 'TO-DO ACTIONS'
    for contact in cc_contacts:
        contact[key] = dict()

    # Delete contacts that do not have PS Member DUIDs
    cc_contacts = delete_contacts_without_ps_duids(cc_contacts,
                                                   cc_client_id, cc_access_token,
                                                   log)

    # Find CC members that need updates from PS Member data
    update_contacts_from_ps_members(cc_contacts,
                                    cc_client_id, cc_access_token, log)

    # Get the synchronizations we're supposed to do
    synchronizations = get_synchronizations(cc_contacts, cc_lists,
                                            member_workgroups,
                                            members, families, log)

    # Remove PS Members from synchronizations who explicitly
    # unsubscribed
    remove_unsubscribed_contacts(cc_contacts, synchronizations, log)

    # Get the union of all source PS members from the synchronizations
    all_needed_ps_members = get_union_of_ps_members(synchronizations, log)

    # Find members that do not have corresponding contacts
    # and make any CC Contacts that are needed that do not yet exist
    new_contacts = create_missing_contacts(cc_contacts,
                                           all_needed_ps_members,
                                           log)

    # These new contacts exist only here in memory -- we did not
    # create them at CC yet.  We know that they're unique and do not
    # exist in our current list of contacts, so add them to our
    # existing cc_contacts list, but mark them as "still need to be
    # created at CC".
    key = 'TO-DO ACTIONS'
    for contact in new_contacts:
        # For the new contacts, we know we need to actually create
        # them at Constant Contact
        contact[key] = { 'create' :  True }
        cc_contacts.append(contact)

    # Now we have contacts (in memory) for every list we need to
    # synchronize.  Resolve all the synchronization PS members to
    # CC contacts.
    compute_sync(synchronizations, cc_contacts, log)

    # JMS Maybe also set TO-DO ACTIONS['delete']=True for all contacts
    # who now have len(list_memberships)==0?

    # We've figured out all the actions we need to take at CC.  Now do
    # all those actions.
    perform_cc_actions(cc_contacts, cc_client_id, cc_access_token, log)

    # JMS Should also send an email to someone notifying them of the
    # actions we performed.


if __name__ == '__main__':
    main()
