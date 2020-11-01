#!/usr/bin/env python
#
# You need all the Python packages in requirements.txt.
#
# You probably want to use a Python virtual environment for this project.
# For example:
#
# $ virtualenv --python=PYTHON_TO_USE DIR
# $ . ./DIR/bin/activate
# $ pip install `cat requirements.txt`
#
# I typically use the latest Python I have installed, and a directory that
# implies that version number.  For example:
#
# $ virtualenv --python=python3.8 py38
#
# Google Calendar events documentation:
# https://developers.google.com/calendar/v3/reference/events?hl=en_US
#

import sys
sys.path.insert(0, '../../../python')

import ECC
import Google
import GoogleAuth

import datetime

from oauth2client import tools
from datetimerange import DateTimeRange

default_app_json  = 'gcalendar-reservations-client-id.json'
default_user_json = 'user-credentials.json'

verbose = True
debug   = False
logfile = None

# dictionary of calendars that we're checking for events on
calendars = [
    {
        "name"      : "Test calendar #1",
        "id"        : 'c_bj96menjelb4pecracnninf45k@group.calendar.google.com',
        "conflicts" : True,
    },
#    {
#        "name"      : "Test calendar #2",
#        "id"        : 'c_ncm1ib261lp6c02i46mors4isc@group.calendar.google.com',
#        "conflicts" : False,
#    },
#    {
#        "name"      : "Epiphany Events",
#        "id"        : "churchofepiphany.com_9gueg54raienol399o0jtdgmpg@group.calendar.google.com",
#        "conflicts" : False,
#    },
#    {
#       "name" : "Musicians calendar",
#       "id" : "churchofepiphany.com_ga4018ieg7n3q71ihs1ovjo9c0@group.calendar.google.com",
#    },
#    {
#       "name" : "Area E (CC)",
#       "id" : "churchofepiphany.com_2d3336353235303639373131@resource.calendar.google.com",
#    },
#    {
#       "name" : "Area F (CC)",
#       "id" : "churchofepiphany.com_2d3336333531363533393538@resource.calendar.google.com",
#    },
#    {
#       "name" : "Area G (CC)",
#       "id" : "churchofepiphany.com_2d33363137333031353534@resource.calendar.google.com",
#    },
#    {
#       "name" : "Area H (CC)"
#       "id" : "churchofepiphany.com_2d33353938373132352d343735@resource.calendar.google.com"
#    },
#    {
#       "name" : "Area I (CC)",
#       "id" : "churchofepiphany.com_2d33353739373832333731@resource.calendar.google.com",
#    },
#    {
#       "name" : "Area J (CC)",
#       "id" : "churchofepiphany.com_2d333535383831322d32@resource.calendar.google.com",
#    },
#    {
#       "name" : "Area K (CC)",
#       "id" : "churchofepiphany.com_2d3335333231363832383335@resource.calendar.google.com",
#    },
#    {
#       "name" : "Area L (CC)",
#       "id" : "churchofepiphany.com_2d3335313431363234383230@resource.calendar.google.com",
#    },
#    {
#       "name" : "Chapel (WC)",
#       "id" : "churchofepiphany.com_2d3431353233343734323336@resource.calendar.google.com",
#    },
#    {
#       "name" : "Coffee Bar Room (CC)",
#       "id" : "churchofepiphany.com_2d38343237303931342d373732@resource.calendar.google.com",
#    },
#    {
#       "name" : "Connector table 1",
#       "id" : "churchofepiphany.com_2d3538323334323031353338@resource.calendar.google.com",
#    },
#    {
#       "name" : "Connector table 2",
#       "id" : "churchofepiphany.com_2d3538313436353238373034@resource.calendar.google.com",
#    },
#    {
#       "name" : "Connector table 3",
#       "id" : "churchofepiphany.com_2d3538303631303232333033@resource.calendar.google.com",
#    },
#    {
#       "name" : "Dining Room (EH)",
#       "id" : "churchofepiphany.com_34373539303436353836@resource.calendar.google.com",
#    },
#    {
#       "name" : "Kitchen (CC)",
#       "id" : "churchofepiphany.com_34383131343230342d333531@resource.calendar.google.com",
#    },
#    {
#       "name" : "Kitchen (EH)",
#       "id" : "churchofepiphany.com_2d36363539313732302d343738@resource.calendar.google.com",
#    },
#    {
#       "name" : "Library (CC)"",
#       "id" : "churchofepiphany.com_2d3131393638363634343630@resource.calendar.google.com",
#    },
#    {
#       "name" : "Lighthouse",
#       "id" : "churchofepiphany.com_2d38303937383836353134@resource.calendar.google.com",
#    },
#    {
#       "name" : "Living Room (EH)",
#       "id" : "churchofepiphany.com_37313933333139382d323530@resource.calendar.google.com",
#    },
#    {
#       "name" : "Media cart and projector",
#       "id" : "churchofepiphany.com_2d37353236313138352d373236@resource.calendar.google.com",
#    },
#    {
#       "name" : "Narthex Gathering Area (WC)",
#       "id" : "churchofepiphany.com_3334313632303539343135@resource.calendar.google.com",
#    },
#    {
#       "name" : "Nursery (CC)",
#       "id" : "churchofepiphany.com_2d353231343439392d34@resource.calendar.google.com",
#    },
#    {
#       "name" : "Projector screen (large)",
#       "id" : "churchofepiphany.com_2d39343734383435352d323039@resource.calendar.google.com",
#    },
#    {
#       "name" : "Projector screen (small)",
#       "id" : "churchofepiphany.com_2d37313836393635372d313838@resource.calendar.google.com",
#    },
#    {
#       "name" : "Quiet Room (WC)",
#       "id" : "churchofepiphany.com_2d36343734343332342d353333@resource.calendar.google.com",
#    },
#    {
#       "name" : "Worship Space",
#       "id" : "churchofepiphany.com_33363131333030322d363435@resource.calendar.google.com",
#    }
]

# List of the domains from which the calendar will accept events; will decline events from all others
acceptable_domains = {
    'epiphanycatholicchurch.org',
    'churchofepiphany.com',
}

####################################################################
#
# Setup functions
#
####################################################################

def setup_cli_args():
    global default_app_json
    tools.argparser.add_argument('--app-id',
                                 default=default_app_json,
                                 help='Filename containing Google application credentials')
    global default_user_json
    tools.argparser.add_argument('--user-credentials',
                                 default=default_user_json,
                                 help='Filename containing Google user credentials')

    global verbose
    tools.argparser.add_argument('--verbose',
                                 action='store_true',
                                 default=verbose,
                                 help='If enabled, emit extra status messages during run')
    global debug
    tools.argparser.add_argument('--debug',
                                 action='store_true',
                                 default=debug,
                                 help='If enabled, emit even more extra status messages during run')
    global logfile
    tools.argparser.add_argument('--logfile',
                                 default=logfile,
                                 help='Store verbose/debug logging to the specified file')

    tools.argparser.add_argument('--dry-run',
                                 action='store_true',
                                 help='Runs through the program without modifying any data')

    global args
    args = tools.argparser.parse_args()

    # --debug implies --verbose
    if args.debug:
        args.verbose = True

    return args

####################################################################

# Accept or decline an event
def _respond_to_event(google, calendar, event, response, reason, log):
    if reason:
        reason = f'because {reason}'

    response_body =   {
            "attendees" : [
                {
                    "email"          : calendar['id'],
                    "responseStatus" : response,
                },
            ],
        }

    if args.dry_run:
        log.info(f"DRY RUN: would have {response} event {event['summary']} (ID: {event['id']}) {reason}")
    else:
        google.events().patch(
            calendarId  = calendar['id'],
            eventId     = event['id'],
            sendUpdates = "all",
            body        = response_body,
        ).execute()
        log.info(f"Successfully {response} event {event['summary']} (ID: {event['id']})")

def decline_event(google, calendar, event, reason, log):
    _respond_to_event(google, calendar, event, 'declined', reason, log)

def accept_event(google, calendar, event, log):
    _respond_to_event(google, calendar, event, 'accepted', '', log)

#-------------------------------------------------------------------

# Return True if a given calendar event requires a response, False otherwise
def needs_response(calendar, event, log):
    if "attendees" in event:
        for attendee in event["attendees"]:
            if attendee["email"] == calendar['id']:
                if attendee["responseStatus"] == "needsAction":
                    log.debug(f"Event {event['id']} on calendar {calendar['name']} requires a response")
                    return True

    return False

#-------------------------------------------------------------------

one_second = datetime.timedelta(seconds=1)

def calculate_event_responses(google, calendar, pending_events, accepted_events, log):
    def _add_dtr(event):
        start = datetime.datetime.fromisoformat(event['start']['dateTime']) + one_second
        end   = datetime.datetime.fromisoformat(event['end']['dateTime']) - one_second
        event[key] = DateTimeRange(start, end)

    key = "_DateTimeRange"

    # First, make a dictionary indexed by event create date (so that we can
    # sort by the event create date)
    sortable_pending_events = dict()
    for event in pending_events:
        _add_dtr(event)
        sortable_pending_events[event['created']] = event

    # Now make a DateTimeRange for each all_events
    for event in accepted_events:
        _add_dtr(event)

    # Iterate through the events that require a response in the order
    # in which they were created (i.e., give priority to those who made
    # their events first)
    for create_timestamp in sorted(sortable_pending_events):
        # The event_index is the "created" time
        event = sortable_pending_events[create_timestamp]

        log.debug(f"Checking for conflicts with event {event['summary']} (ID: {event['id']})")
        # Does this event have any conflicts with already-accepted events?

        # JMS There's probably a more efficient way than comparing to
        # every single event in accepted_events.
        conflicting_event = None
        for accepted_event in accepted_events:
            log.debug(f"Checking accepted {accepted_event['id']} vs. event {event['id']}")
            if event[key].is_intersection(accepted_event[key]):
                conflicting_event = accepted_event
                log.debug(f"CONFLICT: {accepted_event['id']} vs. event {event['id']}")
                break

        # Did we find at least one conflicting event?
        if conflicting_event:
            reason = f"conflicts with {conflicting_event['summary']} (ID: {conflicting_event['id']})"
            log.info(f"Event {event['summary']} (ID: {event['id']}) {reason}")
            decline_event(google, calendar, event, reason, log)
        else:
            accept_event(google, calendar, event, log)

            # JMS It might be better to insert this event in the
            # accepted list in sorted order (i.e., might be able to be
            # more efficient in another loop...?)
            accepted_events.append(event)

#-------------------------------------------------------------------

# Construct three lists:
#
# 1. Rejectable events: events requiring a response that do not have
#    organizers in allowable domains
# 2. Pending events: events requiring a response that have an
#    organizer in an allowable domain
# 3. Accepted events: all other events (i.e., those that are already
#    accepted)
def categorize_events(calendar, all_events, log):
    rejectable_events = list()
    pending_events    = list()
    accepted_events   = list()

    for event in all_events:
        if not needs_response(calendar, event, log):
            accepted_events.append(event)
            continue

        # JMS What is the difference between the creator and the organizer?
        organizer_email  = event["organizer"]["email"]
        organizer_domain = organizer_email.split('@')[1]
        id = event["id"]

        if organizer_domain in acceptable_domains:
            pending_events.append(event)
        else:
            rejectable_events.append(event)

    return rejectable_events, pending_events, accepted_events

#-------------------------------------------------------------------

# Load all the events from a Google Calendar
def load_calendar_events(google, calendar, log):
    events = list()

    log.debug(f"Loading calendar {calendar['name']}")

    i = 1
    page_token = None
    while True:
        # Makes the call to the api to return a list of upcoming events
        result = google.events().list(calendarId=calendar['id'],
                                    singleEvents=True,
                                    pageToken=page_token,
                                    maxResults=2500,
                                    fields='items,nextPageToken',
                                    orderBy='startTime').execute()
        log.debug(f"Loaded page {i} of calendar {calendar['name']}")
        i += 1

        page_events = result.get('items', [])
        if not page_events or len(page_events) == 0:
            break

        events.extend(page_events)

        # Continues to process events if there are more to process
        page_token = result.get('nextPageToken')
        if not page_token:
            break

    # Did we get any events?
    return events if len(events) > 0 else None

#-------------------------------------------------------------------

# Process all the events in a calendar
def process_calendar(google, calendar, log):

    log.info(f"Processing calendar {calendar['name']} (ID: {calendar['id']})")

    all_events = load_calendar_events(google, calendar, log)

    if not all_events:
        log.info(f"Calendar {calendar['name']} is empty / skipping")
        return

    rejectable_events, pending_events, accepted_events = categorize_events(calendar, all_events, log)

    for event in rejectable_events:
        decline_event(google, calendar, event, "Organizer not in allowable domain", log)

    if len(pending_events) > 0:
        calculate_event_responses(google, calendar, pending_events, accepted_events, log)

####################################################################

def main():
    args = setup_cli_args()

    log = ECC.setup_logging(info=args.verbose,
                            debug=args.debug,
                            logfile=args.logfile)

    apis = {
        'calendar': { 'scope'       : Google.scopes['calendar'],
                      'api_name'    : 'calendar',
                      'api_version' : 'v3' },
    }
    services = GoogleAuth.service_oauth_login(apis,
                                              app_json=args.app_id,
                                              user_json=args.user_credentials)
    calendar_service = services['calendar']

    for calendar in calendars:
        process_calendar(calendar_service, calendar, log)

    log.info(f"Finished responding to upcoming events")

if __name__ == '__main__':
    main()
