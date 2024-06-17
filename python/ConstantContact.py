#!/usr/bin/env python3

import os
import json
import copy
import random
import datetime
import requests

from pprint import pprint
from pprint import pformat

####################################################################
#
# Constant Contact general API
#
####################################################################

def api_headers(client_id, access_token, include=None, limit=None):
    headers = {
        'Authorization' : f'Bearer {access_token["access_token"]}',
        'Cache-Control' : 'no-cache',
    }

    params = dict()
    if include or limit:
        if include:
            params['include'] = include
        if limit:
            params['limit'] = limit

    return headers, params

def api_get_all(client_id, access_token,
                   api_endpoint, json_response_field,
                   log, include=None):
    # CC docs say 500 is the max
    headers, params = api_headers(client_id, access_token,
                                     include=include, limit=500)

    base_url = f"{client_id['endpoints']['api']}/v3/{api_endpoint}"

    log.info(f"Loading all Constant Contact items from endpoint {api_endpoint}")

    items = list()
    url = base_url
    while url:
        log.debug(f"Getting URL: {url}")
        # JMS Need to surround this in a retry
        r = requests.get(url, headers=headers, params=params)
        if r.status_code != 200:
            log.error(f"Got a non-200 GET (all) status: {r.status_code}")
            log.error(r.text)
            exit(1)

        response = json.loads(r.text)
        #pprint(response)
        for item in response[json_response_field]:
            items.append(item)
        log.debug(f"Loaded {len(response[json_response_field])} items")

        url = None
        key = '_links'
        key2 = 'next'
        if key in response and key2 in response[key]:
            url = f"{client_id['endpoints']['api']}{response[key][key2]['href']}"

    log.info(f"Loaded {len(items)} total items")

    return items

def api_get(client_id, access_token, uuid,
               api_endpoint, log, include=None):
    headers, params = api_headers(client_id, access_token,
                                     include=include)

    url = f"{client_id['endpoints']['api']}/v3/{api_endpoint}/{uuid}"
    log.info(f"Loading a single Constant Contact item from endpoint {api_endpoint}")

    log.debug(f"Getting URL: {url}")
    # JMS Need to surround this in a retry
    r = requests.get(url, headers=headers, params=params)
    if r.status_code != 200:
        log.error(f"Got a non-200 GET status: {r.status_code}")
        log.error(r.text)
        exit(1)

    response = json.loads(r.text)
    return response

def api_put(client_id, access_token,
               api_endpoint, body, log):
    headers, params = api_headers(client_id, access_token)
    headers['Content-Type'] = 'application/json'

    url = f"{client_id['endpoints']['api']}/v3/{api_endpoint}"
    log.info(f"Putting a single Constant Contact item to endpoint {api_endpoint}")

    log.debug(f"Putting URL: {url}")
    log.debug(pformat(body))
    r = requests.put(url, headers=headers,
                     data=json.dumps(body))
    if r.status_code != 200:
        log.error(f"Got a non-200 PUT status: {r.status_code}")
        log.error(r.text)
        exit(1)

    response = json.loads(r.text)
    return response

####################################################################
#
# Constant Contact authentication
#
####################################################################

def load_client_id(filename, log):
    with open(filename) as fp:
        client_id = json.load(fp)
        log.info(f"Read Constant Contact client_id file: {filename}")
        log.debug(client_id)
        return client_id

def set_valid_from_to(start, response):
    # The JSON that comes back from CC contains an "expires_in" field,
    # that's just a number of seconds from "now".  So add 2 fields to
    # the response: when "now" is, and when the access token expires.
    seconds = datetime.timedelta(seconds=int(response['expires_in']))
    response['valid from'] = start
    response['valid to'] = start + seconds


# Do the CC OAuth2 login.
#
# As of June 2023, per
# https://developer.constantcontact.com/api_guide/auth_overview.html,
# there are 4 Constant Contact OAuth2 flows available:
#
# 1. "Authorization Code Flow": this flow requires that the user visit
# a web page, authorize themselves to CC, and then CC redirects their
# browser to a URL of our choice where this app should be waiting to
# receive the CC authorization token (e.g., we'd tell CC to redirect
# to a URI of the form "http://localhost/...").  Frankly, I don't
# really want to setup a (temporary) local web server to receive this
# redirect, so we won't use this flow.
#
# 2. "PKCE Flow": this flow assumes that the app is running in a place
# where we can't store the client secret from
# https://app.constantcontact.com/pages/dma/portal/appList; it
# generates a challenge string that the user has to copy/paste into a
# web browser, and then copy-paste the response back into this app for
# verification.  Seems too much trouble.
#
# 3. "Device flow": this flow queries a CC authorization server to
# receive a unique OTP, and then presents a URL for the user to visit
# in their browser with that OTP.  After they authorize with their CC
# account, then the app is free to continue and request a CC
# authorization code.
#
# *** This is the flow we're using ("device flow") ***
#
# 4. "Implicit flow": this is similar to "authorization code flow" in
# that this app would need to setup a temporary local web server to
# receive the CC authorization code.  A key difference, however, is
# that these authorization codes are not refresh-able.  That's a
# deal-breaker for us.
def oauth2_device_flow(client_id, log):
    post_data = {
        "client_id" : client_id['client id'],
        "response type" : "code",

        # The scope should be a space-delimited list of scopes from
        # https://v3.developer.constantcontact.com/api_guide/scopes.html.
        "scope" : 'contact_data offline_access',

        # The CC docs don't describe the "state" param They have one
        # example in the docs that is a string ("235o250eddsdff"), so
        # I'm assuming it can be a random number expressed as a
        # string.
        "state" : random.randrange(4294967296)
    }

    r = requests.post(client_id['endpoints']['auth'],
                      data = post_data)
    response = json.loads(r.text)
    log.debug("CC OAuth2 Device Flow got POST reply:")
    log.debug(pformat(response))

    print(f"\nGo to this URL and authenticate:")
    print(f"   {response['verification_uri_complete']}\n")

    _ = input("Hit enter when you have successfully completed that authorization: ")

    # Record the timestamp before we request the access token
    start = datetime.datetime.utcnow()

    # Now get an access token
    device_code = response['device_code']
    post_data = {
        "client_id" : client_id['client id'],
        'device_code' : device_code,

        # This value is from
        # https://developer.constantcontact.com/api_guide/device_flow.html
        'grant_type' : 'urn:ietf:params:oauth:grant-type:device_code',
    }
    r = requests.post(client_id['endpoints']['token'],
                      data = post_data)

    response = json.loads(r.text)
    log.debug("CC OAuth2 Device Flow got POST reply:")
    log.debug(pformat(response))

    set_valid_from_to(start, response)

    return response

# The Constant Contact OAuth2 refresh process is straightforward: post
# to a the token URL requesting a refresh.
def oauth2_device_flow_refresh(client_id, access_token, log):
    # Record the timestamp before we request the access token
    start = datetime.datetime.utcnow()

    post_data = {
        "client_id" : client_id['client id'],
        "refresh_token" : access_token['refresh_token'],
        # This value is hard-coded from
        # https://developer.constantcontact.com/api_guide/server_flow.html
        'grant_type' : 'refresh_token',
    }

    r = requests.post(client_id['endpoints']['token'],
                      data = post_data)
    response = json.loads(r.text)
    log.debug("CC OAuth2 refresh flow got POST reply:")
    log.debug(pformat(response))

    if 'error' in response:
        log.error(f"Got error back from CC access token refresh: {response['error']} / {response['error_description']}")
        return None

    set_valid_from_to(start, response)

    return response

def save_access_token(filename, access_token, log):
    # The access_token dictionary has 2 datetime.datetime value, which
    # json.dump() won't serialize.  :-( So we have to convert those 2
    # values into strings so that they can be saved to a JSON file.
    data = copy.deepcopy(access_token)

    vfrom = access_token['valid from'].isoformat()
    vto = access_token['valid to'].isoformat()
    data['valid from'] = vfrom
    data['valid to'] = vto

    log.debug(f"Writing Constant Contact access token to {filename}")
    with open(filename, 'w') as fp:
        json.dump(data, fp, sort_keys=True, indent=4)

def load_access_token(filename, log):
    # Convert the date/time strings in the JSON to python
    # datetime.datetime objects, for convenience.
    log.debug(f"Reading Constant Contact access token file {filename}")
    with open(filename) as fp:
        access_token = json.load(fp)

    vfrom = datetime.datetime.fromisoformat(access_token['valid from'])
    vto = datetime.datetime.fromisoformat(access_token['valid to'])

    access_token['valid from'] = vfrom
    access_token['valid to'] = vto
    log.debug(f"Read: {access_token}")

    return access_token

# Load the Constant Contact access token, either from a file, or do
# the Constant Contact OAuth2 authentication and/or refresh flows.
def get_access_token(access_token_filename, client_id, log):
    access_token = None

    # If the user supplied an auth_code file that does not exist, then
    # do the CC OAuth2 flow.
    if not os.path.exists(access_token_filename):
        log.info(f"Constant Contact access token file {access_token_filename} does not exist -- authorizing...")
        access_token = oauth2_device_flow(client_id, log)
        save_access_token(access_token_filename, access_token, log)

    # If the user supplied an auth_code file that exists and has
    # content, read it.
    elif os.path.exists(access_token_filename):
        access_token = load_access_token(access_token_filename, log)

    # If we get here with no access token, error
    if access_token is None:
        log.error("No Constant Contact access token available")
        log.error("Aborting in despair")
        exit(1)

    # Check to ensure that the access token is still valid.
    now = datetime.datetime.utcnow()
    log.debug(f"Valid from: {access_token['valid from']}")
    log.debug(f"Now:        {now}")
    log.debug(f"Valid to:   {access_token['valid to']}")
    if access_token['valid from'] > now:
        log.error("Constant Contact access token is not valid yet (!)")
        log.error("Aborting in despair")
        exit(1)

    elif now > access_token['valid to']:
        log.warning("Constant Contact access token is no longer valid")
        log.debug("Attempting to refresh")

        # Refresh the token
        access_token = oauth2_device_flow_refresh(client_id,
                                                  access_token,
                                                  log)
        if access_token is None:
            log.warning("Unable to refresh Constant Contact access token")
            log.warning("Try manual authorization...")
            access_token = oauth2_device_flow(client_id, log)
            save_access_token(access_token_filename, access_token, log)

        else:
            # If we successfully refreshed, save the refreshed token
            save_access_token(access_token_filename, access_token, log)

    return access_token

####################################################################
#
# Create and updated contacts
#
####################################################################

def _write_contact(contact, client_id, access_token, action, log):
    # Make a list of new custom_fields data: exclude the "NAME" field
    # (we added that -- it's not a CC field)
    new_custom_fields = list()
    for field in contact['custom_fields']:
        value = {
            'custom_field_id' : field['custom_field_id'],
            'value' : field['value'],
        }
        new_custom_fields.append(value)

    # Make a contact data structure to pass to the CC API.
    # We have to include all fields :-(
    body = {
        'update_source' : 'Contact',
        'custom_fields' : new_custom_fields,
    }
    for field in ['first_name',
                  'last_name',
                  'email_address',
                  'job_title',
                  'company_name',
                  'birthday_month',
                  'birthday_day',
                  'anniversary',
                  'street_addresses',
                  'list_memberships']:
        if field in contact:
            body[field] = contact[field]

    # Now put the contact back to Constant Contact
    if action == "update":
        fn = api_put
        endpoint = f'contacts/{contact["contact_id"]}'
    elif action == 'create':
        fn = api_post
        endpoint = 'contacts'
    else:
        log.error(f"Unknown CC contact action: {action}")
        log.error("Aborting in despair")
        exit(1)

    fn(client_id, access_token, endpoint, body, log)

def update_contact(contact, client_id, access_token, log):
    _write_contact(contact, client_id, access_token, "update", log)

def create_contact(contact, client_id, access_token, log):



    # JMS Need to insert PS MEMBER DUIDS field somehow



    _write_contact(contact, client_id, access_token, "create", log)

####################################################################
#
# Cross-reference UUIDs in each contact to real names / objects
#
####################################################################

def link_cc_data(contacts, custom_fields_arg, lists_arg, log):
    # Make dictionaries of the custom fields and lists (by UUID) for
    # quick reference.
    custom_fields = dict()
    for cf in custom_fields_arg:
        custom_fields[cf['custom_field_id']] = cf['name']

    lists = dict()
    for l in lists_arg:
        lists[l['list_id']] = l['name']

    # Now go through each contact and resolve the UUIDs to names /
    # objects.
    for contact in contacts:
        # For the custom fields, just add a "name" field to the
        # existing data structure.
        key = 'custom_fields'
        if key in contact:
            for cf in contact[key]:
                uuid = cf['custom_field_id']
                if uuid in custom_fields:
                    # Use all caps NAME to denote that we put this
                    # data here; it wasn't provided by CC.
                    cf['NAME'] = custom_fields[uuid]

                # Also, for convenience, save that custom field name
                # out on the outter contact data structure (not under
                # 'custom_fields').  This just saves a little code
                # elsewhere (i.e., we can just look for the custom
                # field name, look at all the 'NAME' values in
                # contact['custom_fields'] and then take its
                # corresponding 'value').
                contact[custom_fields[uuid]] = cf['value']

        # For list memberships, CC gives us a list of UUIDs.  Save the
        # names in LIST MEMBERSHIPS, for human readability.
        key = 'list_memberships'
        key2 = 'LIST MEMBERSHIPS'
        if key in contact:
            contact[key2] = list()
            for uuid in contact[key]:
                if uuid in lists:
                    contact[key2].append(lists[uuid])

# Using the "PS MEMBER DUIDS" custom field on the CC Contact, link in
# all relevant PS Members
def link_contacts_to_ps_members(contacts, ps_members, log):
    key = 'ps_member_duids'
    for contact in contacts:
        if key not in contact:
            continue

        # The value of this field will be a comma-delimited list of
        # Member DUIDs (because one email may map back to mutliple PS
        # Members).
        #
        # Be safe in trying to convert the Member DUID list, just in
        # case the custom field got corrupted / is not an integer
        # (since technically this field is modifiable by humans via
        # the Constant Contact GUI).
        mduids = list()
        for val in contact[key].split(','):
            try:
                mduid = int(val)
                mduids.append(mduid)
            except:
                # Just skip it
                log.warning(f"Found non-integer Member DUID in Contact {contact['first_name']} {contact['last_name']} <{contact['email_address']['address']}> {key} field: {contact[key]}")

        found_mduids = list()
        found_members = list()
        for mduid in mduids:
            if mduid in ps_members:
                found_mduids.append(mduid)
                found_members.append(ps_members[mduid])

        # Set the list of found PS Members on the contact.
        # Also re-set the list of Member DUIDs to be a) integers (not
        # strings) and b) only valid Member DUIDs.
        if len(found_members) > 0:
            contact['PS MEMBER DUIDS'] = found_mduids
            contact['PS MEMBERS'] = found_members
