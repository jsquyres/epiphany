#!/usr/bin/env python3

import io
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

script_dir = os.path.dirname(os.path.abspath(__file__))
moddir = os.path.join(script_dir, 'ecc-python-modules')
if not os.path.exists(moddir):
    moddir = os.path.join(os.getcwd(), 'ecc-python-modules')
if not os.path.exists(moddir):
    parent_moddir = os.path.join(os.path.dirname(os.getcwd()), 'ecc-python-modules')
    if os.path.exists(parent_moddir):
        moddir = parent_moddir
    else:
        print("ERROR: Could not find the ecc-python-modules directory.")
        print("ERROR: Please make a ecc-python-modules sym link and run again.")
        exit(1)

# On MS Windows, git checks out sym links as a plain file containing the
# target path.  Keep the same compatibility behavior as the music analyzer.
if os.path.isfile(moddir):
    with open(moddir) as fp:
        symlink_dir = fp.readlines()
    moddir = os.path.join(script_dir, symlink_dir[0].strip())

sys.path.insert(0, moddir)

import ECC
import Google
import GoogleAuth
from oauth2client import tools
from google.api_core import retry
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload

args = None
log = None

gapp_id = 'client_id.json'
guser_cred_file = 'user-credentials.json'
verbose = True
debug = False
logfile = "log.txt"

DISCOVERY_CACHE_VERSION = 1
ANALYSIS_OUTPUT_VERSION = 2
BATCH_STATE_VERSION = 1
BATCH_STATE_FILENAME = "openai-analysis-batches.json"
BATCH_INPUT_DIRNAME = "batch-inputs"
BATCH_ENDPOINT = "/v1/responses"
BATCH_COMPLETION_WINDOW = "24h"

DRIVE_FILE_FIELDS = (
    "id, name, mimeType, webViewLink, parents, modifiedTime, driveId, "
    "trashed, fileExtension, md5Checksum, size"
)

MIME_PDF = "application/pdf"
MIME_GOOGLE_DOC = "application/vnd.google-apps.document"
MIME_MS_WORD = "application/msword"
MIME_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
MIME_DOCM = "application/vnd.ms-word.document.macroEnabled.12"

FILE_KIND_GOOGLE_DOC = "google_doc"
FILE_KIND_PDF = "pdf"
FILE_KIND_DOCX = "docx"
FILE_KIND_DOC = "doc"

FILE_KIND_RANK = {
    FILE_KIND_GOOGLE_DOC: 0,
    FILE_KIND_PDF: 1,
    FILE_KIND_DOCX: 2,
    FILE_KIND_DOC: 3,
}

DOWNLOAD_EXTENSIONS = {
    FILE_KIND_GOOGLE_DOC: ".pdf",
    FILE_KIND_PDF: ".pdf",
    FILE_KIND_DOCX: ".docx",
    FILE_KIND_DOC: ".doc",
}

GOOGLE_DOC_EXPORT_MIME = MIME_PDF

SKIP_FOLDER_NAMES = {
    "adl info",
    "for live stream",
    "seat reservation info",
}

LIVESTREAM_RE = re.compile(r"live[\s_-]*stream|livestream", re.IGNORECASE)

BATCH_SKIP_FILE_STATUSES = {
    "submitted",
    "completed",
    "not_liturgy_plan",
    "permanent_error",
}
PERMANENT_GOOGLE_DRIVE_DOWNLOAD_REASONS = {
    "exportSizeLimitExceeded",
    "fileNotDownloadable",
}
BATCH_TERMINAL_STATUSES = {
    "completed",
    "failed",
    "expired",
    "cancelled",
}
FAILURE_REPORT_STATUSES = {
    "permanent_error",
    "retryable_error",
    "failed",
    "expired",
    "cancelled",
    "stale",
}

LITURGY_PLAN_ANALYSIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "is_liturgy_plan": {
            "type": "boolean",
            "description": "True only when this file is a plan/playbook for a specific Catholic liturgy, Mass, or service."
        },
        "document_title": {
            "type": ["string", "null"],
            "description": "The title visible in the document, or null if unavailable."
        },
        "not_liturgy_plan_reason": {
            "type": ["string", "null"],
            "description": "Short reason when is_liturgy_plan is false, otherwise null."
        },
        "entries": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "entry_title": {
                        "type": ["string", "null"],
                        "description": "A concise title for this weekend/service entry, such as 19th Sunday in Ordinary Time."
                    },
                    "liturgy_date": {
                        "type": ["string", "null"],
                        "description": "Primary date in YYYY-MM-DD format. For weekend plans, use the Sunday date."
                    },
                    "liturgy_dates": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "All explicit dates for this entry in YYYY-MM-DD format, including Saturday and Sunday dates when both are present."
                    },
                    "date_scope": {
                        "type": "string",
                        "enum": ["single_service", "weekend", "multi_day_service", "unknown"],
                        "description": "Whether this entry describes one service, a weekend of Saturday/Sunday Masses, another multi-day service, or an unknown date grouping."
                    },
                    "service_type": {
                        "type": ["string", "null"],
                        "description": "Mass, funeral, wedding, confirmation, prayer service, or another concise service type when evident."
                    },
                    "liturgical_season": {
                        "type": ["string", "null"],
                        "description": "Catholic liturgical season, such as Advent, Christmas, Lent, Easter, or Ordinary Time."
                    },
                    "liturgical_cycle": {
                        "type": ["string", "null"],
                        "enum": ["A", "B", "C", None],
                        "description": "Catholic Sunday lectionary cycle A, B, or C when present."
                    },
                    "presider": {
                        "type": ["string", "null"],
                        "description": "The presider/priest when found."
                    },
                    "first_reading": {
                        "type": ["string", "null"],
                        "description": "The first reading citation or description when found."
                    },
                    "second_reading": {
                        "type": ["string", "null"],
                        "description": "The second reading citation or description when found."
                    },
                    "gospel": {
                        "type": ["string", "null"],
                        "description": "The gospel citation or description when found."
                    },
                    "petitions_response": {
                        "type": ["string", "null"],
                        "description": "The response used for prayers of the faithful/petitions when found."
                    },
                    "planning_team": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Names of the planning team members for this entry."
                    },
                    "music": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "action": {
                                    "type": ["string", "null"],
                                    "description": "The liturgical action accompanied by music, such as Entrance Song or Communion Song."
                                },
                                "song_title": {
                                    "type": ["string", "null"],
                                    "description": "The song title stripped of verse/instrumental/livestream notes when possible."
                                },
                                "raw_entry": {
                                    "type": ["string", "null"],
                                    "description": "The concise source line or entry from which this music item was extracted."
                                },
                                "notes": {
                                    "type": ["string", "null"],
                                    "description": "Short non-title performance notes when they are useful, otherwise null."
                                },
                            },
                            "required": ["action", "song_title", "raw_entry", "notes"],
                        },
                        "description": "Every music item in this entry, including multiple songs for the same action as separate items."
                    },
                    "other_metadata": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "key": {"type": "string"},
                                "value": {"type": ["string", "null"]},
                            },
                            "required": ["key", "value"],
                        },
                        "description": "Other obvious key/value metadata relevant to this entry. Do not include paragraphs."
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": "Confidence in this entry extraction."
                    },
                },
                "required": [
                    "entry_title",
                    "liturgy_date",
                    "liturgy_dates",
                    "date_scope",
                    "service_type",
                    "liturgical_season",
                    "liturgical_cycle",
                    "presider",
                    "first_reading",
                    "second_reading",
                    "gospel",
                    "petitions_response",
                    "planning_team",
                    "music",
                    "other_metadata",
                    "confidence",
                ],
            },
            "description": "One item per weekend or single non-weekend service found in the file."
        },
    },
    "required": [
        "is_liturgy_plan",
        "document_title",
        "not_liturgy_plan_reason",
        "entries",
    ],
}

LITURGY_PLAN_ANALYSIS_PROMPT = """Analyze the attached file from Epiphany Catholic Church.

Expected outcome: return structured metadata for downstream statistical analysis.

First decide whether the file is a plan/playbook for a specific Catholic Mass,
liturgy, or service at Epiphany Catholic Church, previously known as Church of
the Epiphany. These files usually describe the execution flow for a specific
service or weekend of services, including music, readings, presider, petitions,
planning team, and other concise key/value details.

Do not classify a broad seasonal planning document, meeting notes document, or
general "Liturgy Planning" document as a liturgy plan unless it clearly refers
to a specific liturgy/service date or weekend.

If the file is not a liturgy plan, set is_liturgy_plan to false, explain why in
not_liturgy_plan_reason, and set entries to an empty array.

If the file is a liturgy plan:
- Set is_liturgy_plan to true and return one entries item per distinct
  weekend or single non-weekend service found in the file.
- A normal Saturday/Sunday weekend plan with one Saturday evening Mass and
  Sunday morning Masses is one entries item, not three. Use the Sunday date as
  liturgy_date and include the Saturday and Sunday dates in liturgy_dates when
  both are explicit.
- If one file covers several weekends, return several entries items: one per
  weekend, each with that weekend's liturgy_date, readings, music, presider,
  planning team, and other concise metadata.
- If one file covers several standalone non-weekend services, return one
  entries item per service.
- Do not aggregate dates, readings, music, or metadata from different weekends
  or standalone services into one entries item.
- Extract only concise key/value metadata. Do not return paragraphs of
  instructions, call-to-worship text, petition paragraphs, images, or long
  preparation notes.
- Return each entry's liturgy_date as YYYY-MM-DD when the date can be
  determined.
- Extract liturgical season, lectionary cycle A/B/C, presider, first reading,
  second reading, gospel, petitions response, planning team members, and other
  obvious concise metadata for each entry.
- Extract every music item. Music rows may be marked with Unicode musical-note
  symbols such as U+266A, but may also appear without them.
- For music rows like "Entrance Song: Gather Your People", action is "Entrance
  Song" and song_title is "Gather Your People".
- Strip short performance notes that are not part of a title, such as verse
  numbers, livestream directions, "when we eat", bilingual refrain details, or
  instrumental-only directions. Put short useful notes in notes when helpful.
- If one action lists multiple song titles, create one music object per song
  using the same action. Do not discard the second title.
- Keep titles that are part of the song name. When uncertain whether text is a
  title or a note, keep it in song_title and use notes only for clearly
  non-title details.

Use null for missing scalar values and empty arrays when no entries are found.
Return only data supported by the file.
"""


def parse_timestamp(timestamp):
    if isinstance(timestamp, datetime):
        dt = timestamp
    else:
        text = timestamp.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        dt = datetime.fromisoformat(text)

    if dt.tzinfo is None:
        dt = dt.astimezone()

    return dt.astimezone(timezone.utc)


def utc_timestamp(timestamp=None):
    if timestamp is None:
        dt = datetime.now(timezone.utc)
    else:
        dt = parse_timestamp(timestamp)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def local_timestamp(timestamp):
    local_dt = parse_timestamp(timestamp).astimezone()
    return f"{local_dt.isoformat(timespec='seconds')} ({local_dt.tzname()})"


def local_timestamp_or_unknown(timestamp):
    if not timestamp:
        return "unknown"
    try:
        return local_timestamp(timestamp)
    except Exception:
        return str(timestamp)


def normalize_analysis_timestamp(data):
    changed = False
    cached_at = data.get('cached_at_utc') or data.get('cached_at')
    if cached_at:
        normalized = utc_timestamp(cached_at)
        if data.get('cached_at_utc') != normalized:
            data['cached_at_utc'] = normalized
            changed = True
    if 'cached_at' in data:
        del data['cached_at']
        changed = True
    return changed


def normalize_cli_option_names(parser):
    for action in parser._actions:
        new_option_strings = []
        changed = False

        for option_string in action.option_strings:
            new_option_string = option_string.replace("_", "-")
            new_option_strings.append(new_option_string)
            if new_option_string != option_string:
                parser._option_string_actions.pop(option_string, None)
                changed = True

        if changed:
            action.option_strings = new_option_strings
            for option_string in new_option_strings:
                parser._option_string_actions[option_string] = action


def setup_cli_args():
    normalize_cli_option_names(tools.argparser)

    tools.argparser.add_argument('-h', '--help',
                                 action='help',
                                 help='Show this help message and exit')
    tools.argparser.add_argument('--google-drive-root-url',
                                 help='The root-level Google Drive URL to start indexing')
    tools.argparser.add_argument('--output',
                                 default='liturgy-plan-analysis.json',
                                 help='Output JSON file name')
    tools.argparser.add_argument('--failures-output',
                                 default='failures.json',
                                 help='Output JSON file for batch analysis failures')
    tools.argparser.add_argument('--google-drive-cache',
                                 default='google-drive-cache.json',
                                 help='JSON file to store/load Google Drive discovery results')
    tools.argparser.add_argument('--skip-discovery',
                                 action='store_true',
                                 help='Skip Google Drive discovery and load from cache instead')
    tools.argparser.add_argument('--skip-analysis',
                                 action='store_true',
                                 help='Perform discovery and save to cache, but skip analysis')

    analysis_mode = tools.argparser.add_mutually_exclusive_group()
    analysis_mode.add_argument('--submit-analysis-batch',
                               action='store_true',
                               help='Submit unanalyzed files to the OpenAI Batch API and exit')
    analysis_mode.add_argument('--collect-analysis-batch',
                               action='store_true',
                               help='Collect completed OpenAI batch results and generate JSON')

    tools.argparser.add_argument('--limit',
                                 type=int,
                                 help='Maximum number of selected files to analyze after discovery')
    tools.argparser.add_argument('--analysis-batch-size',
                                 type=int,
                                 default=500,
                                 help='Maximum number of files to submit in one OpenAI analysis batch')
    tools.argparser.add_argument('--retry-analysis-error-codes',
                                 metavar='CODES',
                                 help='Comma-delimited OpenAI error codes/reasons/statuses to retry')
    tools.argparser.add_argument('--allow-concurrent-analysis-batches',
                                 action='store_true',
                                 help='Allow submitting a new OpenAI analysis batch while previous batches are uncollected')
    tools.argparser.add_argument('--state-dir',
                                 default='analysis-results',
                                 help='Directory to store/load individual analysis results')
    tools.argparser.add_argument('--model',
                                 default='gpt-5.4-mini',
                                 help='OpenAI model to use for analysis')
    tools.argparser.add_argument('--reasoning-effort',
                                 choices=['none', 'low', 'medium', 'high', 'xhigh'],
                                 default='medium',
                                 help='Reasoning effort for GPT-5-series models')
    tools.argparser.add_argument('--pdf-detail',
                                 choices=['low', 'high'],
                                 default='high',
                                 help='PDF rendering detail to send to OpenAI for PDFs and exported Google Docs')

    global gapp_id
    tools.argparser.add_argument('--app-id',
                                 default=gapp_id,
                                 help='Filename containing Google application credentials')
    global guser_cred_file
    tools.argparser.add_argument('--user-credentials',
                                 default=guser_cred_file,
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

    global args
    args = tools.argparser.parse_args()

    if args.skip_analysis and (args.submit_analysis_batch or args.collect_analysis_batch):
        tools.argparser.error("--skip-analysis cannot be combined with batch analysis modes")
    if args.analysis_batch_size <= 0:
        tools.argparser.error("--analysis-batch-size must be greater than 0")

    if args.debug:
        args.verbose = True
    args.retry_analysis_error_codes = parse_comma_delimited_values(args.retry_analysis_error_codes)

    return args


def parse_comma_delimited_values(text):
    if not text:
        return set()
    return {
        value.strip().casefold()
        for value in text.split(',')
        if value.strip()
    }


def extract_folder_id(url):
    match = re.search(r'folders/([a-zA-Z0-9_-]+)', url)
    if match:
        return match.group(1)
    match = re.search(r'id=([a-zA-Z0-9_-]+)', url)
    if match:
        return match.group(1)
    return url


def format_folder_for_log(folder_id, folder_name=None):
    if folder_name:
        return f"{folder_name} ({folder_id})"
    return folder_id


def name_matches_livestream(name):
    return bool(name and LIVESTREAM_RE.search(name))


def normalized_name(name):
    return re.sub(r"\s+", " ", (name or "").strip()).casefold()


def should_skip_drive_folder(file):
    folder_name = file.get('name')
    if name_matches_livestream(folder_name):
        return True
    return normalized_name(folder_name) in SKIP_FOLDER_NAMES


def should_skip_drive_file(file):
    return name_matches_livestream(file.get('name'))


def file_extension_from_name(name):
    _, ext = os.path.splitext(name or "")
    return ext.casefold().lstrip(".")


def detect_file_kind(file):
    mime_type = file.get('mimeType')
    if mime_type == MIME_GOOGLE_DOC:
        return FILE_KIND_GOOGLE_DOC
    if mime_type == MIME_PDF:
        return FILE_KIND_PDF
    if mime_type == MIME_DOCX or mime_type == MIME_DOCM:
        return FILE_KIND_DOCX
    if mime_type == MIME_MS_WORD:
        return FILE_KIND_DOC

    extension = (file.get('fileExtension') or file_extension_from_name(file.get('name'))).casefold()
    if extension == 'pdf':
        return FILE_KIND_PDF
    if extension == 'docx' or extension == 'docm':
        return FILE_KIND_DOCX
    if extension == 'doc':
        return FILE_KIND_DOC
    return None


def is_supported_liturgy_file(file):
    if should_skip_drive_file(file):
        return False
    return detect_file_kind(file) is not None


def strip_document_suffix(name):
    base = (name or "").strip()
    for suffix in (".pdf", ".docx", ".docm", ".doc"):
        if base.casefold().endswith(suffix):
            base = base[:-len(suffix)]
            break
    return re.sub(r"\s+", " ", base).strip()


def duplicate_base_name(file):
    return strip_document_suffix(file.get('name')).casefold()


def duplicate_group_key(file, root_id):
    parent_id = (file.get('parents') or [root_id])[0]
    return f"{parent_id}:{duplicate_base_name(file)}"


def get_source_modified_time_utc(file):
    modified_time = file.get('modified_time_utc')
    if not modified_time:
        return None
    return utc_timestamp(modified_time)


def normalize_drive_file(file, root_id):
    file_kind = detect_file_kind(file)
    item = {
        'id': file['id'],
        'name': file.get('name'),
        'mimeType': file.get('mimeType'),
        'file_kind': file_kind,
        'webViewLink': file.get('webViewLink'),
        'parents': file.get('parents', []),
        'driveId': file.get('driveId'),
        'trashed': file.get('trashed', False),
        'fileExtension': file.get('fileExtension'),
        'md5Checksum': file.get('md5Checksum'),
        'size': file.get('size'),
    }

    if file.get('modifiedTime'):
        item['modified_time_utc'] = utc_timestamp(file['modifiedTime'])

    parent_id = item.get('parents', [root_id])[0]
    item['parentFolderLink'] = f"https://drive.google.com/drive/folders/{parent_id}"
    item['duplicate_base_name'] = duplicate_base_name(item)
    item['duplicate_group_key'] = duplicate_group_key(item, root_id)
    item['analysis_rank'] = FILE_KIND_RANK.get(file_kind, 99)

    return {key: value for key, value in item.items() if value is not None}


def create_google_drive_cache(root_id, root_url=None):
    return {
        'schema_version': DISCOVERY_CACHE_VERSION,
        'root_id': root_id,
        'root_url': root_url,
        'drive_id': None,
        'change_page_token': None,
        'generated_at_utc': utc_timestamp(),
        'updated_at_utc': utc_timestamp(),
        'folders': {},
        'files': {},
        'duplicate_groups': {},
    }


def cache_contains_parent(cache, file):
    return any(parent in cache['folders'] for parent in file.get('parents', []))


def add_folder_to_cache(cache, file):
    cache['folders'][file['id']] = {
        'id': file['id'],
        'name': file.get('name'),
        'mimeType': file.get('mimeType'),
        'webViewLink': file.get('webViewLink'),
        'parents': file.get('parents', []),
        'driveId': file.get('driveId'),
        'trashed': file.get('trashed', False),
        **({'modified_time_utc': utc_timestamp(file['modifiedTime'])} if file.get('modifiedTime') else {}),
    }
    if file['id'] == cache['root_id']:
        cache['drive_id'] = file.get('driveId')


def add_liturgy_file_to_cache(cache, file):
    item = normalize_drive_file(file, cache['root_id'])
    cache['files'][item['id']] = item


def remove_folder_subtree_from_cache(cache, folder_id):
    removed_folders = {folder_id}

    changed = True
    while changed:
        changed = False
        for cached_folder_id, folder in list(cache['folders'].items()):
            if cached_folder_id in removed_folders:
                continue
            if any(parent in removed_folders for parent in folder.get('parents', [])):
                removed_folders.add(cached_folder_id)
                changed = True

    for cached_folder_id in removed_folders:
        if cached_folder_id != cache['root_id']:
            cache['folders'].pop(cached_folder_id, None)

    for file_id, file in list(cache['files'].items()):
        if any(parent in removed_folders for parent in file.get('parents', [])):
            cache['files'].pop(file_id, None)


def prune_cache_to_root(cache):
    reachable = {cache['root_id']}
    changed = True

    while changed:
        changed = False
        for folder_id, folder in cache['folders'].items():
            if folder_id in reachable:
                continue
            if any(parent in reachable for parent in folder.get('parents', [])):
                reachable.add(folder_id)
                changed = True

    for folder_id in list(cache['folders'].keys()):
        if folder_id not in reachable:
            cache['folders'].pop(folder_id, None)

    for file_id, file in list(cache['files'].items()):
        if not any(parent in reachable for parent in file.get('parents', [])):
            cache['files'].pop(file_id, None)


def choose_duplicate_group_file(files):
    return sorted(
        files,
        key=lambda item: (
            FILE_KIND_RANK.get(item.get('file_kind'), 99),
            -(parse_timestamp(item.get('modified_time_utc')).timestamp()
              if item.get('modified_time_utc') else 0),
            item.get('name') or '',
            item.get('id') or '',
        )
    )[0]


def rebuild_duplicate_groups(cache):
    groups = {}
    for file in cache.get('files', {}).values():
        group_key = file.get('duplicate_group_key') or duplicate_group_key(file, cache['root_id'])
        groups.setdefault(group_key, []).append(file)

    duplicate_groups = {}
    for group_key, files in groups.items():
        selected = choose_duplicate_group_file(files)
        duplicate_groups[group_key] = {
            'duplicate_group_key': group_key,
            'duplicate_base_name': selected.get('duplicate_base_name'),
            'selected_file_id': selected['id'],
            'file_ids': sorted(file['id'] for file in files),
            'file_count': len(files),
            'file_kinds': sorted({file.get('file_kind') for file in files if file.get('file_kind')}),
            'selection_order': ['google_doc', 'pdf', 'docx', 'doc'],
        }

    cache['duplicate_groups'] = duplicate_groups
    return cache


@retry.Retry(predicate=Google.retry_errors)
def list_files_in_folder(service, folder_id, folder_name=None):
    try:
        query = f"'{folder_id}' in parents and trashed = false"
        files = []
        page_token = None
        folder_label = format_folder_for_log(folder_id, folder_name)

        while True:
            httpref = service.files().list(
                q=query,
                fields=f"nextPageToken, files({DRIVE_FILE_FIELDS})",
                pageSize=1000,
                pageToken=page_token,
                supportsAllDrives=True,
                includeItemsFromAllDrives=True
            )
            log.debug(f"Executing Google API call: Listing files in folder {folder_label}")
            results = Google.call_api(httpref, log)
            if not results:
                return files

            files.extend(results.get('files', []))
            page_token = results.get('nextPageToken')
            if not page_token:
                return files
    except Exception as e:
        log.warning(f"Could not list files in folder {format_folder_for_log(folder_id, folder_name)}: {e}")
        return []


@retry.Retry(predicate=Google.retry_errors)
def get_file_metadata(service, file_id):
    httpref = service.files().get(
        fileId=file_id,
        fields=DRIVE_FILE_FIELDS,
        supportsAllDrives=True
    )
    return Google.call_api(httpref, log)


@retry.Retry(predicate=Google.retry_errors)
def get_start_page_token(service, drive_id=None):
    kwargs = {'supportsAllDrives': True}
    if drive_id:
        kwargs['driveId'] = drive_id

    httpref = service.changes().getStartPageToken(**kwargs)
    results = Google.call_api(httpref, log)
    return results.get('startPageToken') if results else None


def scan_folder_tree(service, folder_id, cache, folder_name=None):
    files = list_files_in_folder(service, folder_id, folder_name)
    for file in files:
        if file.get('mimeType') == Google.mime_types['folder']:
            if should_skip_drive_folder(file):
                log.info(f"Skipping Google Drive folder {format_folder_for_log(file['id'], file.get('name'))}")
                remove_folder_subtree_from_cache(cache, file['id'])
                continue
            add_folder_to_cache(cache, file)
            scan_folder_tree(service, file['id'], cache, file.get('name'))
        elif is_supported_liturgy_file(file):
            add_liturgy_file_to_cache(cache, file)


def full_drive_discovery(service, root_id, root_url=None):
    log.info(f"Performing full Google Drive discovery from folder ID: {root_id}...")
    cache = create_google_drive_cache(root_id, root_url)

    root = get_file_metadata(service, root_id)
    if not root:
        raise RuntimeError(f"Could not read root folder metadata for {root_id}")
    add_folder_to_cache(cache, root)

    scan_folder_tree(service, root_id, cache, root.get('name'))
    cache['change_page_token'] = get_start_page_token(service, cache.get('drive_id'))
    cache['updated_at_utc'] = utc_timestamp()
    return rebuild_duplicate_groups(cache)


def remove_changed_item_from_cache(cache, file_id):
    if file_id in cache['folders']:
        remove_folder_subtree_from_cache(cache, file_id)
    cache['files'].pop(file_id, None)


def apply_file_change_to_cache(service, cache, file):
    file_id = file['id']

    if file.get('trashed'):
        remove_changed_item_from_cache(cache, file_id)
        return

    mime_type = file.get('mimeType')

    if mime_type == Google.mime_types['folder']:
        if should_skip_drive_folder(file):
            log.info(f"Skipping Google Drive folder {format_folder_for_log(file_id, file.get('name'))}")
            remove_folder_subtree_from_cache(cache, file_id)
            return

        was_tracked = file_id in cache['folders']
        is_root = file_id == cache['root_id']
        is_in_tree = is_root or cache_contains_parent(cache, file)

        if is_in_tree:
            add_folder_to_cache(cache, file)
            if not was_tracked:
                scan_folder_tree(service, file_id, cache, file.get('name'))
        elif was_tracked:
            remove_folder_subtree_from_cache(cache, file_id)
        return

    if is_supported_liturgy_file(file):
        if cache_contains_parent(cache, file):
            add_liturgy_file_to_cache(cache, file)
        else:
            cache['files'].pop(file_id, None)
        return

    cache['files'].pop(file_id, None)


def list_drive_changes_page(service, page_token, drive_id=None):
    kwargs = {
        'pageToken': page_token,
        'fields': f"newStartPageToken,nextPageToken,changes(fileId,removed,file({DRIVE_FILE_FIELDS}))",
        'pageSize': 1000,
        'spaces': 'drive',
        'supportsAllDrives': True,
        'includeItemsFromAllDrives': True,
    }
    if drive_id:
        kwargs['driveId'] = drive_id

    httpref = service.changes().list(**kwargs)
    return Google.call_api(httpref, log)


def refresh_google_drive_cache(service, cache):
    page_token = cache.get('change_page_token')
    if not page_token:
        log.info("Google Drive cache has no change token; full discovery is required.")
        return None

    changes_seen = 0
    log.info("Refreshing Google Drive cache from Drive change log...")

    while page_token:
        try:
            results = list_drive_changes_page(service, page_token, cache.get('drive_id'))
        except HttpError as e:
            if e.resp.status == 410:
                log.info("Google Drive change token expired; full discovery is required.")
                return None
            raise

        if not results:
            return None

        for change in results.get('changes', []):
            changes_seen += 1
            file_id = change.get('fileId')
            if not file_id:
                continue

            if change.get('removed'):
                remove_changed_item_from_cache(cache, file_id)
                continue

            file = change.get('file')
            if file:
                apply_file_change_to_cache(service, cache, file)
            else:
                remove_changed_item_from_cache(cache, file_id)

        page_token = results.get('nextPageToken')
        if results.get('newStartPageToken'):
            cache['change_page_token'] = results['newStartPageToken']

    prune_cache_to_root(cache)
    rebuild_duplicate_groups(cache)
    cache['updated_at_utc'] = utc_timestamp()
    log.info(f"Applied {changes_seen} Google Drive changes from change log.")
    return cache


def save_google_drive_cache(cache, cache_file):
    rebuild_duplicate_groups(cache)
    cache['schema_version'] = DISCOVERY_CACHE_VERSION
    cache['updated_at_utc'] = utc_timestamp()
    log.info(
        f"Saving Google Drive cache to {cache_file} "
        f"({len(cache.get('folders', {}))} folders, "
        f"{len(cache.get('files', {}))} files, "
        f"{len(cache.get('duplicate_groups', {}))} selected groups)..."
    )

    cache_dir = os.path.dirname(os.path.abspath(cache_file))
    os.makedirs(cache_dir, exist_ok=True)
    tmp_cache_file = f"{cache_file}.tmp"
    with open(tmp_cache_file, 'w') as f:
        json.dump(cache, f, indent=2, sort_keys=True)
    os.replace(tmp_cache_file, cache_file)


def load_google_drive_cache(cache_file):
    log.info(f"Loading Google Drive cache from {cache_file}...")
    with open(cache_file, 'r') as f:
        cache = json.load(f)

    if not isinstance(cache, dict):
        raise ValueError("Google Drive cache must be a JSON object")
    if cache.get('schema_version') != DISCOVERY_CACHE_VERSION:
        raise ValueError(
            f"Unsupported Google Drive cache schema version: {cache.get('schema_version')}"
        )
    cache.setdefault('files', {})
    cache.setdefault('duplicate_groups', {})
    rebuild_duplicate_groups(cache)
    return cache


def get_selected_files_from_cache(cache):
    selected_file_ids = {
        group.get('selected_file_id')
        for group in cache.get('duplicate_groups', {}).values()
        if group.get('selected_file_id')
    }
    selected = []
    for file_id in selected_file_ids:
        file = cache.get('files', {}).get(file_id)
        if not file:
            continue
        group = cache.get('duplicate_groups', {}).get(file.get('duplicate_group_key'), {})
        item = dict(file)
        item['duplicate_file_ids'] = group.get('file_ids', [file_id])
        item['duplicate_file_count'] = group.get('file_count', 1)
        item['duplicate_file_kinds'] = group.get('file_kinds', [file.get('file_kind')])
        selected.append(item)
    return sort_files_for_analysis(selected)


def sort_files_for_analysis(files):
    return sorted(
        files,
        key=lambda file: ((file.get('name') or '').casefold(), file.get('id') or '')
    )


def safe_local_filename(name):
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "file").strip("._")
    return base or "file"


def google_drive_download_error(exc):
    error = {
        'type': 'google_drive_download_error',
        'message': str(exc),
    }

    if isinstance(exc, HttpError):
        status = getattr(getattr(exc, 'resp', None), 'status', None)
        if status is not None:
            error['status_code'] = status

        content = getattr(exc, 'content', None)
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='replace')

        if content:
            error['response_content'] = content
            try:
                details = json.loads(content)
                api_error = details.get('error') if isinstance(details, dict) else None
                if isinstance(api_error, dict):
                    error['api_message'] = api_error.get('message')
                    errors = api_error.get('errors')
                    if isinstance(errors, list) and errors:
                        first = errors[0]
                        if isinstance(first, dict):
                            error['code'] = first.get('reason')
                            error['domain'] = first.get('domain')
                            error['location'] = first.get('location')
                            error['location_type'] = first.get('locationType')
            except Exception:
                pass

    return error


def download_failure_status(error):
    if error_code(error) in PERMANENT_GOOGLE_DRIVE_DOWNLOAD_REASONS:
        return 'permanent_error'
    return 'retryable_error'


def is_permanent_google_drive_download_failure(cached_data):
    return (
        cached_data.get('analysis_status') == 'permanent_error'
        and (cached_data.get('analysis_error') or {}).get('type') == 'google_drive_download_error'
        and error_code(cached_data.get('analysis_error')) in PERMANENT_GOOGLE_DRIVE_DOWNLOAD_REASONS
    )


@retry.Retry(predicate=Google.retry_errors)
def download_file_for_analysis(service, file):
    file_id = file['id']
    file_kind = file.get('file_kind')
    ext = DOWNLOAD_EXTENSIONS.get(file_kind, "")
    local_path = f"/tmp/{file_id}-{uuid.uuid4().hex[:8]}{ext}"

    try:
        if file_kind == FILE_KIND_GOOGLE_DOC:
            httpref = service.files().export_media(
                fileId=file_id,
                mimeType=GOOGLE_DOC_EXPORT_MIME
            )
            analysis_file_type = "exported_pdf"
            uploaded_mime_type = GOOGLE_DOC_EXPORT_MIME
        else:
            httpref = service.files().get_media(fileId=file_id, supportsAllDrives=True)
            analysis_file_type = file_kind
            uploaded_mime_type = file.get('mimeType')

        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, httpref)
        done = False
        while done is False:
            status, done = downloader.next_chunk()
        fh.seek(0)

        with open(local_path, "wb") as f:
            f.write(fh.read())

        return {
            'path': local_path,
            'analysis_file_type': analysis_file_type,
            'uploaded_mime_type': uploaded_mime_type,
        }
    except Exception as e:
        log.error(f"Error downloading file {file_id} ({file.get('name')}): {e}")
        return {
            'error': google_drive_download_error(e),
        }


def input_file_content(openai_file_id, analysis_file_type):
    content = {
        "type": "input_file",
        "file_id": openai_file_id,
    }
    if analysis_file_type in (FILE_KIND_PDF, "exported_pdf"):
        content["detail"] = args.pdf_detail
    return content


def build_openai_response_body(openai_file_id, analysis_file_type=None):
    body = {
        "model": args.model,
        "input": [
            {
                "role": "user",
                "content": [
                    input_file_content(openai_file_id, analysis_file_type),
                    {"type": "input_text", "text": LITURGY_PLAN_ANALYSIS_PROMPT},
                ]
            }
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "liturgy_plan_analysis",
                "description": "Structured metadata extracted from a possible Catholic liturgy plan.",
                "schema": LITURGY_PLAN_ANALYSIS_SCHEMA,
                "strict": True,
            }
        },
    }
    if args.reasoning_effort:
        body["reasoning"] = {"effort": args.reasoning_effort}
    return body


def extract_response_output_text(response_body):
    if not isinstance(response_body, dict):
        return None

    output_text = response_body.get("output_text")
    if isinstance(output_text, str):
        return output_text

    parts = []
    for output in response_body.get("output") or []:
        if not isinstance(output, dict):
            continue
        for content in output.get("content") or []:
            if not isinstance(content, dict):
                continue
            if content.get("type") in ("output_text", "text"):
                text = content.get("text")
                if isinstance(text, str):
                    parts.append(text)

    if parts:
        return "\n".join(parts)
    return None


def get_openai_file_text(client, file_id):
    response = client.files.content(file_id)
    text = getattr(response, "text", None)
    if callable(text):
        return text()
    if isinstance(text, str):
        return text

    content = getattr(response, "content", None)
    if isinstance(content, bytes):
        return content.decode("utf-8")
    if isinstance(content, str):
        return content

    return str(response)


def get_object_value(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def serialize_openai_value(value):
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return value


def exception_to_error(error):
    body = serialize_openai_value(getattr(error, "body", None))
    payload = {
        'message': str(error),
        'type': error.__class__.__name__,
        'status_code': getattr(error, "status_code", None),
        'code': getattr(error, "code", None),
        'body': body,
    }
    return {key: value for key, value in payload.items() if value is not None}


def incomplete_response_error(response_body):
    if not isinstance(response_body, dict):
        return None
    if response_body.get('status') != 'incomplete':
        return None

    return {
        'message': 'OpenAI response was incomplete',
        'response_status': response_body.get('status'),
        'incomplete_details': response_body.get('incomplete_details'),
    }


def analyze_file(client, prepared_file):
    if not prepared_file:
        return None, {'message': 'No local file was prepared for analysis'}

    max_retries = 10
    retry_delay = 30

    for attempt in range(max_retries):
        openai_file = None
        try:
            log.info(f"Uploading {prepared_file['path']} to OpenAI...")
            with open(prepared_file['path'], "rb") as f:
                openai_file = client.files.create(
                    file=f,
                    purpose="user_data"
                )

            response = client.responses.create(
                **build_openai_response_body(
                    openai_file.id,
                    prepared_file.get('analysis_file_type'),
                )
            )
            response_body = serialize_openai_value(response)
            incomplete_error = incomplete_response_error(response_body)
            if incomplete_error:
                return None, incomplete_error

            output_text = extract_response_output_text(response_body)
            if not output_text and hasattr(response, "output_text"):
                output_text = response.output_text
            if not output_text:
                return None, {'message': 'No output text found in OpenAI response'}

            return json.loads(output_text), None
        except Exception as e:
            error = exception_to_error(e)
            if is_retryable_analysis_error(error) and attempt + 1 < max_retries:
                log.warning(
                    f"OpenAI API retryable error. Retrying in {retry_delay}s... "
                    f"(Attempt {attempt + 1}/{max_retries}): {e}"
                )
                time.sleep(retry_delay)
                retry_delay *= 1.5
                continue
            log.error(f"Error analyzing file with OpenAI: {e}")
            return None, error
        finally:
            if openai_file:
                try:
                    client.files.delete(openai_file.id)
                except Exception as e:
                    log.warning(f"Could not delete OpenAI file {openai_file.id}: {e}")

    return None, {'message': f"Failed after {max_retries} attempts"}


def get_cached_analysis(file_id, state_dir):
    cache_path = os.path.join(state_dir, f"{file_id}.json")
    if os.path.exists(cache_path):
        with open(cache_path, 'r') as f:
            data = json.load(f)
        if normalize_analysis_timestamp(data):
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2, sort_keys=True)
        return data
    return None


def get_error_object(error):
    if not isinstance(error, dict):
        return {}
    body = error.get('body')
    if isinstance(body, dict) and isinstance(body.get('error'), dict):
        return body['error']
    return error


def error_code(error):
    obj = get_error_object(error)
    return obj.get('code') if isinstance(obj, dict) else None


def error_message(error):
    obj = get_error_object(error)
    if isinstance(obj, dict):
        return obj.get('message') or obj.get('details')
    return str(error) if error is not None else None


def error_status_code(error):
    if isinstance(error, dict):
        return error.get('status_code')
    return None


def incomplete_response_reason(error):
    details = error.get('incomplete_details') if isinstance(error, dict) else None
    return details.get('reason') if isinstance(details, dict) else None


def is_retryable_incomplete_response(error):
    return incomplete_response_reason(error) in ('content_filter', 'max_output_tokens')


def analysis_error_key(error):
    reason = incomplete_response_reason(error)
    if reason:
        return f"incomplete:{reason}"

    code = error_code(error)
    if code:
        return f"openai:{code}"

    message = error_message(error) or ''
    if 'Could not parse model JSON output' in message:
        return 'local:parse_error'
    if 'No output text found' in message:
        return 'local:missing_output_text'

    error_type = error.get('type') if isinstance(error, dict) else None
    if error_type:
        return f"local:{str(error_type).casefold()}"

    status_code = error_status_code(error)
    if status_code:
        return f"http:{status_code}"

    return 'unknown'


def analysis_error_summary(error):
    return {
        'error_key': analysis_error_key(error),
        'status_code': error_status_code(error),
        'error_code': error_code(error),
        'incomplete_reason': incomplete_response_reason(error),
        'message': error_message(error),
    }


def analysis_error_filter_values(error):
    values = {analysis_error_key(error).casefold()}

    code = error_code(error)
    if code:
        values.add(str(code).casefold())

    reason = incomplete_response_reason(error)
    if reason:
        values.add(str(reason).casefold())

    status_code = error_status_code(error)
    if status_code is not None:
        values.add(str(status_code).casefold())

    return values


def error_matches_retry_filter(error):
    if not args.retry_analysis_error_codes:
        return True
    if not error:
        return False
    return bool(args.retry_analysis_error_codes & analysis_error_filter_values(error))


def is_retryable_analysis_error(error):
    code = error_code(error)
    message = error_message(error) or ''
    status_code = error_status_code(error)

    if is_retryable_incomplete_response(error):
        return True
    if status_code == 429 or code == 'rate_limit_exceeded':
        return True
    if code in ('server_error', 'temporarily_unavailable'):
        return True
    if 'Could not parse model JSON output' in message:
        return True
    if 'No output text found' in message:
        return True
    if isinstance(error, dict) and error.get('type') and not code and not status_code:
        return True
    return False


def cached_analysis_blocks_resubmission(cached_data):
    analysis_status = cached_data.get('analysis_status')
    analysis_error = cached_data.get('analysis_error')

    if analysis_status in ('failed', 'retryable_error'):
        return False
    if analysis_error and is_retryable_analysis_error(analysis_error):
        return False
    return True


def is_cached_analysis_fresh(cached_data, file, match_analysis_strategy=True):
    if not cached_data:
        return False
    if not cached_analysis_blocks_resubmission(cached_data):
        return False

    if match_analysis_strategy and not is_permanent_google_drive_download_failure(cached_data):
        cached_model = cached_data.get('analysis_model')
        if cached_model and cached_model != args.model:
            return False

        cached_pdf_detail = cached_data.get('pdf_detail')
        if cached_pdf_detail and cached_pdf_detail != args.pdf_detail:
            return False

        cached_reasoning_effort = cached_data.get('reasoning_effort')
        if cached_reasoning_effort and cached_reasoning_effort != args.reasoning_effort:
            return False

    drive_mod_time_utc = get_source_modified_time_utc(file)
    if not drive_mod_time_utc:
        raise ValueError("File metadata does not include modified_time_utc")

    source_mod_time_utc = cached_data.get('source_modified_time_utc')
    if source_mod_time_utc:
        return utc_timestamp(source_mod_time_utc) == drive_mod_time_utc

    cached_at_utc = cached_data.get('cached_at_utc')
    if not cached_at_utc:
        return False

    return parse_timestamp(cached_at_utc) >= parse_timestamp(drive_mod_time_utc)


def cached_analysis_reanalysis_reason(cached_data, file):
    if not cached_data:
        return "No cached analysis found."

    analysis_status = cached_data.get('analysis_status')
    analysis_error = cached_data.get('analysis_error')
    if analysis_status in ('failed', 'retryable_error'):
        return f"Cached analysis status is {analysis_status}."
    if analysis_error and is_retryable_analysis_error(analysis_error):
        return f"Cached analysis error is retryable ({analysis_error_key(analysis_error)})."

    cached_model = cached_data.get('analysis_model')
    if cached_model and cached_model != args.model:
        return f"Cached analysis used model {cached_model}; requested model is {args.model}."

    cached_pdf_detail = cached_data.get('pdf_detail')
    if cached_pdf_detail and cached_pdf_detail != args.pdf_detail:
        return f"Cached analysis used PDF detail {cached_pdf_detail}; requested PDF detail is {args.pdf_detail}."

    cached_reasoning_effort = cached_data.get('reasoning_effort')
    if cached_reasoning_effort and cached_reasoning_effort != args.reasoning_effort:
        return (
            f"Cached analysis used reasoning effort {cached_reasoning_effort}; "
            f"requested reasoning effort is {args.reasoning_effort}."
        )

    drive_mod_time_utc = get_source_modified_time_utc(file)
    source_mod_time_utc = cached_data.get('source_modified_time_utc')
    if source_mod_time_utc and drive_mod_time_utc:
        return (
            "Cache source modified timestamp differs from Drive file "
            f"(cached source {local_timestamp_or_unknown(source_mod_time_utc)}; "
            f"Drive modified {local_timestamp_or_unknown(drive_mod_time_utc)})."
        )

    cached_at_utc = cached_data.get('cached_at_utc')
    if not cached_at_utc:
        return "Cached analysis has no cached_at_utc timestamp."

    return (
        "Cache is older than Drive file "
        f"(cached {local_timestamp_or_unknown(cached_at_utc)}; "
        f"Drive modified {local_timestamp_or_unknown(drive_mod_time_utc)})."
    )


def source_snapshot(file):
    return {
        'drive_file_id': file['id'],
        'drive_modified_time_utc': get_source_modified_time_utc(file),
        'name': file.get('name'),
        'file_kind': file.get('file_kind'),
        'mimeType': file.get('mimeType'),
        'file_link': file.get('webViewLink'),
        'folder_link': file.get('parentFolderLink'),
        'duplicate_group_key': file.get('duplicate_group_key'),
        'duplicate_base_name': file.get('duplicate_base_name'),
        'duplicate_file_ids': file.get('duplicate_file_ids', [file['id']]),
        'duplicate_file_count': file.get('duplicate_file_count', 1),
        'duplicate_file_kinds': file.get('duplicate_file_kinds', [file.get('file_kind')]),
        'model': args.model,
        'pdf_detail': args.pdf_detail,
        'reasoning_effort': args.reasoning_effort,
    }


def save_cached_analysis(file_id, data, state_dir, file=None):
    os.makedirs(state_dir, exist_ok=True)

    cache_path = os.path.join(state_dir, f"{file_id}.json")
    data['cached_at_utc'] = utc_timestamp()
    data.pop('cached_at', None)
    if file:
        source_modified_time_utc = get_source_modified_time_utc(file)
        if source_modified_time_utc:
            data['source_modified_time_utc'] = source_modified_time_utc
        data['source'] = source_snapshot(file)
    data['analysis_model'] = args.model
    data['pdf_detail'] = args.pdf_detail
    data['reasoning_effort'] = args.reasoning_effort
    with open(cache_path, 'w') as f:
        json.dump(data, f, indent=2, sort_keys=True)


def save_failed_analysis(file_id, error, state_dir, file, status):
    data = {
        'is_liturgy_plan': False,
        'document_title': None,
        'not_liturgy_plan_reason': None,
        'entries': [],
        'analysis_status': status,
        'analysis_error': error,
    }
    save_cached_analysis(file_id, data, state_dir, file)


def analysis_payload(data):
    return {
        key: data.get(key)
        for key in LITURGY_PLAN_ANALYSIS_SCHEMA['properties'].keys()
    }


def flattened_entry_payload(file_analysis, entry):
    payload = {
        'is_liturgy_plan': file_analysis.get('is_liturgy_plan'),
        'document_title': file_analysis.get('document_title'),
        'not_liturgy_plan_reason': file_analysis.get('not_liturgy_plan_reason'),
    }
    payload.update(entry or {})
    return payload


def record_for_cached_analysis(file, cached_data, file_analysis):
    return {
        'source': source_snapshot(file),
        'analysis': file_analysis,
        'analysis_status': cached_data.get('analysis_status', 'completed'),
        'analysis_error': cached_data.get('analysis_error'),
        'cached_at_utc': cached_data.get('cached_at_utc'),
    }


def records_for_cached_analysis(file, cached_data):
    file_analysis = analysis_payload(cached_data)
    if (
        cached_data.get('analysis_error')
        or cached_data.get('analysis_status') in ('failed', 'retryable_error', 'permanent_error')
        or file_analysis.get('is_liturgy_plan') is not True
    ):
        return [record_for_cached_analysis(file, cached_data, file_analysis)]

    entries = file_analysis.get('entries') or []
    if not entries:
        log.warning(f"Cached analysis for {file['name']} ({file['id']}) is a liturgy plan with no entries.")
        return [record_for_cached_analysis(file, cached_data, file_analysis)]

    records = []
    for entry_index, entry in enumerate(entries, start=1):
        source = source_snapshot(file)
        source['entry_index'] = entry_index
        source['entry_count'] = len(entries)
        source['source_entry_id'] = f"{file['id']}:{entry_index}"
        records.append({
            'source': source,
            'analysis': flattened_entry_payload(file_analysis, entry),
            'analysis_status': cached_data.get('analysis_status', 'completed'),
            'analysis_error': cached_data.get('analysis_error'),
            'cached_at_utc': cached_data.get('cached_at_utc'),
        })

    return records


def build_records_from_cached_analysis(found_files, match_analysis_strategy=True):
    records = []
    for file in found_files:
        file_id = file['id']
        cached_data = get_cached_analysis(file_id, args.state_dir)
        if not cached_data:
            continue
        try:
            if not is_cached_analysis_fresh(
                cached_data,
                file,
                match_analysis_strategy=match_analysis_strategy,
            ):
                log.info(f"Skipping stale cached analysis for {file['name']} ({file_id})")
                continue
        except Exception as e:
            log.warning(f"Skipping cached analysis for {file['name']} ({file_id}): {e}")
            continue

        records.extend(records_for_cached_analysis(file, cached_data))
    return sort_output_records(records)


def sort_output_records(records):
    return sorted(
        records,
        key=lambda record: (
            record.get('analysis', {}).get('liturgy_date') or '',
            (record.get('analysis', {}).get('entry_title') or '').casefold(),
            (record.get('analysis', {}).get('document_title') or '').casefold(),
            (record.get('source', {}).get('name') or '').casefold(),
            record.get('source', {}).get('entry_index') or 0,
            record.get('source', {}).get('drive_file_id') or '',
        )
    )


def generate_json_output(records, output_file):
    failed_records = [
        record
        for record in records
        if record.get('analysis_error')
        or record.get('analysis_status') in ('failed', 'retryable_error', 'permanent_error')
    ]
    plans = [
        record
        for record in records
        if record not in failed_records
        and record.get('analysis', {}).get('is_liturgy_plan') is True
    ]
    non_plans = [
        record
        for record in records
        if record not in failed_records
        and record.get('analysis', {}).get('is_liturgy_plan') is not True
    ]
    music_entry_count = sum(
        len(record.get('analysis', {}).get('music') or [])
        for record in plans
    )

    payload = {
        'schema_version': ANALYSIS_OUTPUT_VERSION,
        'generated_at_utc': utc_timestamp(),
        'analysis_model': args.model,
        'reasoning_effort': args.reasoning_effort,
        'pdf_detail': args.pdf_detail,
        'record_count': len(records),
        'liturgy_plan_count': len(plans),
        'source_file_count': len({
            record.get('source', {}).get('drive_file_id')
            for record in records
            if record.get('source', {}).get('drive_file_id')
        }),
        'liturgy_plan_source_file_count': len({
            record.get('source', {}).get('drive_file_id')
            for record in plans
            if record.get('source', {}).get('drive_file_id')
        }),
        'non_liturgy_file_count': len(non_plans),
        'failed_file_count': len(failed_records),
        'music_entry_count': music_entry_count,
        'plans': sort_output_records(plans),
        'non_liturgy_files': sort_output_records(non_plans),
        'failed_files': sort_output_records(failed_records),
    }

    output_dir = os.path.dirname(os.path.abspath(output_file))
    os.makedirs(output_dir, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def get_batch_state_path(state_dir):
    return os.path.join(state_dir, BATCH_STATE_FILENAME)


def create_batch_state():
    return {
        'schema_version': BATCH_STATE_VERSION,
        'generated_at_utc': utc_timestamp(),
        'updated_at_utc': utc_timestamp(),
        'files': {},
        'file_error_history': {},
        'batches': {},
    }


def build_file_error_history_entry(request, status, error):
    entry = {
        'drive_file_id': request.get('drive_file_id'),
        'drive_modified_time_utc': request.get('drive_modified_time_utc'),
        'name': request.get('name'),
        'file_kind': request.get('file_kind'),
        'file_link': request.get('file_link'),
        'folder_link': request.get('folder_link'),
        'model': request.get('model'),
        'pdf_detail': request.get('pdf_detail'),
        'reasoning_effort': request.get('reasoning_effort'),
        'batch_id': request.get('batch_id'),
        'custom_id': request.get('custom_id'),
        'status': status,
        'submitted_at_utc': request.get('submitted_at_utc'),
        'completed_at_utc': request.get('completed_at_utc'),
        'recorded_at_utc': utc_timestamp(),
        'error': error,
    }
    entry.update(analysis_error_summary(error))
    return entry


def record_file_error_history(batch_state, request, status, error):
    if not error or status not in FAILURE_REPORT_STATUSES:
        return False

    drive_file_id = request.get('drive_file_id')
    custom_id = request.get('custom_id')
    if not drive_file_id or not custom_id:
        return False

    histories = batch_state.setdefault('file_error_history', {})
    history = histories.setdefault(drive_file_id, [])
    entry = build_file_error_history_entry(request, status, error)

    for index, existing in enumerate(history):
        if existing.get('custom_id') == custom_id:
            entry['recorded_at_utc'] = existing.get('recorded_at_utc') or entry['recorded_at_utc']
            if existing == entry:
                return False
            history[index] = entry
            return True

    history.append(entry)
    history.sort(key=lambda item: (item.get('completed_at_utc') or '', item.get('custom_id') or ''))
    return True


def normalize_batch_state_statuses(state):
    changed = False

    for batch_record in state.get('batches', {}).values():
        for request in batch_record.get('requests', {}).values():
            if (
                request.get('status') in ('failed', 'permanent_error')
                and request.get('error')
                and is_retryable_analysis_error(request.get('error'))
            ):
                request['status'] = 'retryable_error'
                changed = True

                current_record = state.get('files', {}).get(request.get('drive_file_id'))
                if current_record and current_record.get('custom_id') == request.get('custom_id'):
                    current_record['status'] = 'retryable_error'

    return changed


def rebuild_file_error_history_from_requests(state):
    changed = False
    state.setdefault('file_error_history', {})

    for batch_id, batch_record in state.get('batches', {}).items():
        for request in batch_record.get('requests', {}).values():
            status = request.get('status')
            error = request.get('error')
            if status not in FAILURE_REPORT_STATUSES or not error:
                continue
            if not request.get('batch_id'):
                request['batch_id'] = batch_id
            if record_file_error_history(state, request, status, error):
                changed = True

    return changed


def load_batch_state(state_dir):
    state_path = get_batch_state_path(state_dir)
    if not os.path.exists(state_path):
        return create_batch_state()

    log.info(f"Loading OpenAI batch state from {state_path}...")
    with open(state_path, 'r') as f:
        state = json.load(f)

    if not isinstance(state, dict):
        raise ValueError("OpenAI batch state must be a JSON object")
    if state.get('schema_version') != BATCH_STATE_VERSION:
        raise ValueError(
            f"Unsupported OpenAI batch state schema version: {state.get('schema_version')}"
        )

    state.setdefault('files', {})
    state.setdefault('file_error_history', {})
    state.setdefault('batches', {})
    changed = False
    if normalize_batch_state_statuses(state):
        log.info("Normalized retryable statuses in OpenAI batch state.")
        changed = True
    if rebuild_file_error_history_from_requests(state):
        log.info("Updated OpenAI batch error history from recorded requests.")
        changed = True
    if changed:
        save_batch_state(state, state_dir)
    return state


def save_batch_state(state, state_dir):
    os.makedirs(state_dir, exist_ok=True)
    state['schema_version'] = BATCH_STATE_VERSION
    state['updated_at_utc'] = utc_timestamp()
    state_path = get_batch_state_path(state_dir)
    tmp_state_path = f"{state_path}.tmp"
    with open(tmp_state_path, 'w') as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp_state_path, state_path)


def compact_utc_timestamp_for_filename():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def batch_file_record_matches_file(record, file):
    if not record:
        return False
    if record.get('drive_modified_time_utc') != get_source_modified_time_utc(file):
        return False
    if record.get('model') != args.model:
        return False
    if record.get('pdf_detail') != args.pdf_detail:
        return False
    if record.get('reasoning_effort') != args.reasoning_effort:
        return False
    return True


def batch_file_record_source_matches_file(record, file):
    if not record:
        return False
    return record.get('drive_modified_time_utc') == get_source_modified_time_utc(file)


def batch_file_record_should_skip_submission(record, file):
    if not batch_file_record_matches_file(record, file):
        return False
    if record.get('error') and is_retryable_analysis_error(record.get('error')):
        return False
    return record.get('status') in BATCH_SKIP_FILE_STATUSES


def iter_batch_error_records_for_file(batch_state, file):
    file_id = file['id']
    seen_custom_ids = set()

    current_record = batch_state.get('files', {}).get(file_id)
    if current_record and batch_file_record_source_matches_file(current_record, file):
        seen_custom_ids.add(current_record.get('custom_id'))
        yield current_record

    for record in batch_state.get('file_error_history', {}).get(file_id, []):
        if not batch_file_record_source_matches_file(record, file):
            continue
        custom_id = record.get('custom_id')
        if custom_id in seen_custom_ids:
            continue
        seen_custom_ids.add(custom_id)
        yield record

    for batch_record in batch_state.get('batches', {}).values():
        for request in batch_record.get('requests', {}).values():
            if request.get('drive_file_id') != file_id:
                continue
            if not batch_file_record_source_matches_file(request, file):
                continue
            custom_id = request.get('custom_id')
            if custom_id in seen_custom_ids:
                continue
            seen_custom_ids.add(custom_id)
            yield request


def file_matches_retry_error_filter(file, cached_data, batch_state):
    if not args.retry_analysis_error_codes:
        return True

    if cached_data and error_matches_retry_filter(cached_data.get('analysis_error')):
        return True

    for record in iter_batch_error_records_for_file(batch_state, file):
        if error_matches_retry_filter(record.get('error')):
            return True

    return False


def choose_files_for_batch_submission(found_files, batch_state):
    candidates = []
    skipped_cached = 0
    skipped_submitted = 0
    skipped_answered = 0
    skipped_retry_filter = 0

    for file in found_files:
        file_id = file['id']
        cached_data = get_cached_analysis(file_id, args.state_dir)
        if cached_data:
            try:
                if is_cached_analysis_fresh(cached_data, file):
                    skipped_cached += 1
                    continue
            except Exception as e:
                log.warning(f"Could not evaluate cached analysis for {file['name']} ({file_id}): {e}")

        if not file_matches_retry_error_filter(file, cached_data, batch_state):
            skipped_retry_filter += 1
            continue

        file_record = batch_state.get('files', {}).get(file_id)
        if batch_file_record_should_skip_submission(file_record, file):
            if file_record.get('status') == 'submitted':
                skipped_submitted += 1
            else:
                skipped_answered += 1
            continue

        candidates.append(file)

    log.info(
        f"Batch submission candidates: {len(candidates)} "
        f"(fresh cache: {skipped_cached}; already submitted: {skipped_submitted}; "
        f"already answered: {skipped_answered}; retry filter: {skipped_retry_filter})"
    )
    return candidates


def get_uncollected_analysis_batches(batch_state):
    return [
        batch_record
        for batch_record in batch_state.get('batches', {}).values()
        if not batch_record.get('collected_at_utc')
    ]


def delete_openai_file(client, file_id, description):
    if not file_id:
        return True
    try:
        client.files.delete(file_id)
        return True
    except Exception as e:
        log.warning(f"Could not delete OpenAI {description} file {file_id}: {e}")
        return False


def update_current_file_record_from_request(batch_state, request, updates):
    drive_file_id = request.get('drive_file_id')
    current_record = batch_state.get('files', {}).get(drive_file_id)
    if not current_record:
        return
    if current_record.get('custom_id') != request.get('custom_id'):
        return
    current_record.update(updates)


def delete_uploaded_file_for_request(client, batch_state, request):
    if request.get('openai_file_deleted_at_utc'):
        return
    openai_file_id = request.get('openai_file_id')
    if delete_openai_file(client, openai_file_id, "analysis source"):
        updates = {'openai_file_deleted_at_utc': utc_timestamp()}
        request.update(updates)
        update_current_file_record_from_request(batch_state, request, updates)


def mark_batch_request(batch_state, request, status, error=None):
    updates = {
        'status': status,
        'completed_at_utc': utc_timestamp(),
    }
    if error:
        updates['error'] = error
    else:
        request.pop('error', None)

    request.update(updates)
    update_current_file_record_from_request(batch_state, request, updates)
    record_file_error_history(batch_state, request, status, error)


def write_batch_input_file(requests):
    batch_input_dir = os.path.join(args.state_dir, BATCH_INPUT_DIRNAME)
    os.makedirs(batch_input_dir, exist_ok=True)
    filename = f"{compact_utc_timestamp_for_filename()}-{uuid.uuid4().hex[:8]}-analysis.jsonl"
    path = os.path.join(batch_input_dir, filename)

    with open(path, 'w') as f:
        for request in requests:
            f.write(json.dumps(request, separators=(',', ':')))
            f.write("\n")

    return path


def submit_analysis_batch(client, service, found_files):
    try:
        batch_state = load_batch_state(args.state_dir)
    except Exception as e:
        log.error(f"Could not load OpenAI batch state: {e}")
        return False

    uncollected_batches = get_uncollected_analysis_batches(batch_state)
    if uncollected_batches and not args.allow_concurrent_analysis_batches:
        batch_ids = ', '.join(
            batch_record.get('batch_id') or '<unknown>'
            for batch_record in uncollected_batches
        )
        log.warning(
            "Not submitting a new OpenAI batch because previous batches are not collected: "
            f"{batch_ids}. Run --collect-analysis-batch first, or use "
            "--allow-concurrent-analysis-batches."
        )
        return True

    candidates = choose_files_for_batch_submission(found_files, batch_state)
    if not candidates:
        log.info("No files need batch submission.")
        return True
    if len(candidates) > args.analysis_batch_size:
        log.info(
            f"Limiting this OpenAI batch submission to {args.analysis_batch_size} "
            f"of {len(candidates)} outstanding files."
        )
        candidates = candidates[:args.analysis_batch_size]

    submitted_at_utc = utc_timestamp()
    batch_requests = []
    file_records = []
    batch_input_file = None
    created_batch_id = None

    for analysis_index, file in enumerate(candidates, start=1):
        file_id = file['id']
        log.info(
            f"Preparing batch request ({analysis_index} of {len(candidates)}): "
            f"{file['name']} ({file_id})..."
        )
        prepared_file = None
        openai_file = None
        try:
            prepared_file = download_file_for_analysis(service, file)
            if not prepared_file or prepared_file.get('error'):
                error = (prepared_file or {}).get('error') or {
                    'type': 'google_drive_download_error',
                    'message': 'No local file was prepared for analysis',
                }
                status = download_failure_status(error)
                save_failed_analysis(file_id, error, args.state_dir, file, status)
                log.warning(
                    f"Skipping {file['name']} ({file_id}); download/export failed "
                    f"with {status}."
                )
                continue

            log.info(f"Uploading {prepared_file['path']} to OpenAI for batch analysis...")
            with open(prepared_file['path'], "rb") as f:
                openai_file = client.files.create(
                    file=f,
                    purpose="user_data"
                )

            custom_id = f"{file_id}-{uuid.uuid4().hex[:8]}"
            file_record = source_snapshot(file)
            file_record.update({
                'custom_id': custom_id,
                'openai_file_id': openai_file.id,
                'status': 'submitted',
                'submitted_at_utc': submitted_at_utc,
                'analysis_file_type': prepared_file.get('analysis_file_type'),
                'uploaded_mime_type': prepared_file.get('uploaded_mime_type'),
            })
            file_records.append(file_record)
            batch_requests.append({
                'custom_id': custom_id,
                'method': 'POST',
                'url': BATCH_ENDPOINT,
                'body': build_openai_response_body(
                    openai_file.id,
                    prepared_file.get('analysis_file_type'),
                ),
            })
        except Exception as e:
            log.error(f"Could not prepare batch request for {file['name']} ({file_id}): {e}")
            if openai_file:
                delete_openai_file(client, openai_file.id, "analysis source")
        finally:
            if prepared_file and prepared_file.get('path') and os.path.exists(prepared_file['path']):
                os.remove(prepared_file['path'])

    if not batch_requests:
        log.info("No batch requests were prepared successfully.")
        return False

    try:
        batch_input_path = write_batch_input_file(batch_requests)
        log.info(f"Uploading OpenAI batch input file {batch_input_path}...")
        with open(batch_input_path, "rb") as f:
            batch_input_file = client.files.create(
                file=f,
                purpose="batch"
            )

        log.info(f"Submitting OpenAI batch with {len(batch_requests)} requests...")
        batch = client.batches.create(
            input_file_id=batch_input_file.id,
            endpoint=BATCH_ENDPOINT,
            completion_window=BATCH_COMPLETION_WINDOW,
            metadata={
                'source': 'index_liturgy_plans.py',
                'model': args.model,
                'pdf_detail': args.pdf_detail,
                'reasoning_effort': args.reasoning_effort,
            },
        )

        batch_id = get_object_value(batch, 'id')
        if not batch_id:
            raise RuntimeError("OpenAI batch creation did not return a batch id")
        created_batch_id = batch_id
        batch_status = get_object_value(batch, 'status')
        request_map = {}
        for file_record in file_records:
            file_record['batch_id'] = batch_id
            batch_state['files'][file_record['drive_file_id']] = dict(file_record)
            request_map[file_record['custom_id']] = dict(file_record)

        batch_state['batches'][batch_id] = {
            'batch_id': batch_id,
            'input_file_id': batch_input_file.id,
            'endpoint': BATCH_ENDPOINT,
            'completion_window': BATCH_COMPLETION_WINDOW,
            'status': batch_status,
            'submitted_at_utc': submitted_at_utc,
            'model': args.model,
            'pdf_detail': args.pdf_detail,
            'reasoning_effort': args.reasoning_effort,
            'request_count': len(batch_requests),
            'requests': request_map,
        }
        save_batch_state(batch_state, args.state_dir)
        log.info(
            f"Submitted OpenAI batch {batch_id} with {len(batch_requests)} requests. "
            "Run again with --collect-analysis-batch to retrieve completed results."
        )
        return True
    except Exception as e:
        log.error(f"Could not submit OpenAI batch: {e}")
        if created_batch_id:
            log.error(
                f"OpenAI batch {created_batch_id} may have been created, so uploaded files were left in place."
            )
        else:
            for file_record in file_records:
                delete_openai_file(client, file_record.get('openai_file_id'), "analysis source")
            if batch_input_file:
                delete_openai_file(client, batch_input_file.id, "batch input")
        return False


def iter_jsonl(text):
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            yield line_number, json.loads(line)
        except Exception as e:
            log.warning(f"Could not parse JSONL line {line_number}: {e}")


def result_line_error(result):
    error = result.get('error')
    if error:
        return error

    response = result.get('response') or {}
    status_code = response.get('status_code')
    try:
        numeric_status_code = int(status_code) if status_code is not None else None
    except Exception:
        numeric_status_code = None
    if numeric_status_code and numeric_status_code >= 400:
        return {
            'status_code': status_code,
            'body': response.get('body'),
        }

    return None


def mark_retryable_batch_request(batch_state, request, error):
    mark_batch_request(batch_state, request, 'retryable_error', error)


def file_from_batch_request(request):
    return {
        'id': request.get('drive_file_id'),
        'name': request.get('name'),
        'file_kind': request.get('file_kind'),
        'mimeType': request.get('mimeType'),
        'webViewLink': request.get('file_link'),
        'parentFolderLink': request.get('folder_link'),
        'modified_time_utc': request.get('drive_modified_time_utc'),
        'duplicate_group_key': request.get('duplicate_group_key'),
        'duplicate_base_name': request.get('duplicate_base_name'),
        'duplicate_file_ids': request.get('duplicate_file_ids', [request.get('drive_file_id')]),
        'duplicate_file_count': request.get('duplicate_file_count', 1),
        'duplicate_file_kinds': request.get('duplicate_file_kinds', [request.get('file_kind')]),
    }


def process_batch_result_line(client, batch_state, batch_record, file_by_id, result):
    custom_id = result.get('custom_id')
    if not custom_id:
        log.warning("Batch result is missing custom_id; skipping.")
        return

    request = batch_record.get('requests', {}).get(custom_id)
    if not request:
        log.warning(f"Batch result custom_id {custom_id} was not found in local batch state; skipping.")
        return

    drive_file_id = request.get('drive_file_id')
    current_file = file_by_id.get(drive_file_id)
    if current_file:
        current_mod_time_utc = get_source_modified_time_utc(current_file)
        if request.get('drive_modified_time_utc') != current_mod_time_utc:
            log.info(
                f"Batch result for {request.get('name')} ({drive_file_id}) is stale "
                f"(submitted Drive modified {local_timestamp_or_unknown(request.get('drive_modified_time_utc'))}; "
                f"current Drive modified {local_timestamp_or_unknown(current_mod_time_utc)})."
            )
            mark_batch_request(batch_state, request, 'stale')
            delete_uploaded_file_for_request(client, batch_state, request)
            return
        cache_file = current_file
    else:
        cache_file = file_from_batch_request(request)

    error = result_line_error(result)
    if error:
        log.warning(f"Batch request failed for {request.get('name')} ({drive_file_id}): {error}")
        if is_retryable_analysis_error(error):
            mark_retryable_batch_request(batch_state, request, error)
        else:
            save_failed_analysis(drive_file_id, error, args.state_dir, cache_file, 'permanent_error')
            mark_batch_request(batch_state, request, 'permanent_error', error)
        delete_uploaded_file_for_request(client, batch_state, request)
        return

    response = result.get('response') or {}
    body = response.get('body')
    incomplete_error = incomplete_response_error(body)
    if incomplete_error:
        log.warning(
            f"Batch response incomplete for {request.get('name')} ({drive_file_id}): "
            f"{incomplete_error}"
        )
        if is_retryable_incomplete_response(incomplete_error):
            mark_retryable_batch_request(batch_state, request, incomplete_error)
        else:
            save_failed_analysis(drive_file_id, incomplete_error, args.state_dir, cache_file, 'failed')
            mark_batch_request(batch_state, request, 'failed', incomplete_error)
        delete_uploaded_file_for_request(client, batch_state, request)
        return

    output_text = extract_response_output_text(body)
    if not output_text:
        error = {'message': 'No output text found in OpenAI batch response'}
        log.warning(f"Batch request returned no output text for {request.get('name')} ({drive_file_id})")
        mark_retryable_batch_request(batch_state, request, error)
        delete_uploaded_file_for_request(client, batch_state, request)
        return

    try:
        data = json.loads(output_text)
    except Exception as e:
        error = {
            'message': 'Could not parse model JSON output',
            'details': str(e),
        }
        log.warning(f"Could not parse model output for {request.get('name')} ({drive_file_id}): {e}")
        mark_retryable_batch_request(batch_state, request, error)
        delete_uploaded_file_for_request(client, batch_state, request)
        return

    save_cached_analysis(drive_file_id, data, args.state_dir, cache_file)
    status = 'not_liturgy_plan' if data.get('is_liturgy_plan') is False else 'completed'
    mark_batch_request(batch_state, request, status)
    delete_uploaded_file_for_request(client, batch_state, request)


def mark_unfinished_batch_requests(client, batch_state, batch_record, status):
    terminal_request_statuses = (
        'completed',
        'not_liturgy_plan',
        'permanent_error',
        'failed',
        'stale',
    )
    for request in batch_record.get('requests', {}).values():
        if request.get('status') in terminal_request_statuses:
            continue
        mark_batch_request(batch_state, request, status, {'message': f'Batch ended with status {status}'})
        delete_uploaded_file_for_request(client, batch_state, request)


def update_batch_record_from_openai(batch_record, batch):
    batch_record['status'] = get_object_value(batch, 'status')
    batch_record['output_file_id'] = get_object_value(batch, 'output_file_id')
    batch_record['error_file_id'] = get_object_value(batch, 'error_file_id')
    request_counts = serialize_openai_value(get_object_value(batch, 'request_counts'))
    if request_counts is not None:
        batch_record['request_counts'] = request_counts
    usage = serialize_openai_value(get_object_value(batch, 'usage'))
    if usage is not None:
        batch_record['usage'] = usage


def collect_analysis_batches(client, found_files):
    try:
        batch_state = load_batch_state(args.state_dir)
    except Exception as e:
        log.error(f"Could not load OpenAI batch state: {e}")
        return None

    if not batch_state.get('batches'):
        log.info("No OpenAI batches are recorded in local state.")
        generate_failures_json(batch_state, args.failures_output)
        return build_records_from_cached_analysis(
            found_files,
            match_analysis_strategy=not bool(args.retry_analysis_error_codes),
        )

    file_by_id = {file['id']: file for file in found_files}
    for batch_id, batch_record in sorted(batch_state.get('batches', {}).items()):
        if batch_record.get('collected_at_utc'):
            log.info(
                f"OpenAI batch {batch_id} was already collected at "
                f"{local_timestamp_or_unknown(batch_record['collected_at_utc'])}."
            )
            continue

        try:
            log.info(f"Checking OpenAI batch {batch_id}...")
            batch = client.batches.retrieve(batch_id)
            update_batch_record_from_openai(batch_record, batch)
        except Exception as e:
            log.error(f"Could not retrieve OpenAI batch {batch_id}: {e}")
            continue

        status = batch_record.get('status')
        request_counts = batch_record.get('request_counts')
        if request_counts:
            log.info(f"OpenAI batch {batch_id} status: {status}; request counts: {request_counts}")
        else:
            log.info(f"OpenAI batch {batch_id} status: {status}")

        output_file_id = batch_record.get('output_file_id')
        error_file_id = batch_record.get('error_file_id')

        if status not in BATCH_TERMINAL_STATUSES:
            continue

        processing_failed = False
        if output_file_id:
            try:
                output_text = get_openai_file_text(client, output_file_id)
                for _, result in iter_jsonl(output_text):
                    process_batch_result_line(client, batch_state, batch_record, file_by_id, result)
            except Exception as e:
                processing_failed = True
                log.error(f"Could not process output file for OpenAI batch {batch_id}: {e}")

        if error_file_id:
            try:
                error_text = get_openai_file_text(client, error_file_id)
                for _, result in iter_jsonl(error_text):
                    process_batch_result_line(client, batch_state, batch_record, file_by_id, result)
            except Exception as e:
                processing_failed = True
                log.error(f"Could not process error file for OpenAI batch {batch_id}: {e}")

        if processing_failed:
            log.warning(f"OpenAI batch {batch_id} was not marked collected; retry collection later.")
            save_batch_state(batch_state, args.state_dir)
            continue

        if status != 'completed':
            mark_unfinished_batch_requests(client, batch_state, batch_record, status)
        elif not output_file_id:
            mark_unfinished_batch_requests(client, batch_state, batch_record, 'failed')

        batch_record['collected_at_utc'] = utc_timestamp()
        save_batch_state(batch_state, args.state_dir)

    save_batch_state(batch_state, args.state_dir)
    generate_failures_json(batch_state, args.failures_output)
    return build_records_from_cached_analysis(
        found_files,
        match_analysis_strategy=not bool(args.retry_analysis_error_codes),
    )


def collect_failure_records(batch_state):
    failures = []
    current_files = batch_state.get('files', {})
    for batch_id, batch_record in sorted(batch_state.get('batches', {}).items()):
        for request in batch_record.get('requests', {}).values():
            status = request.get('status')
            if status not in FAILURE_REPORT_STATUSES:
                continue
            current_record = current_files.get(request.get('drive_file_id'))
            if current_record and current_record.get('custom_id') != request.get('custom_id'):
                continue

            record = dict(request)
            record['batch_id'] = request.get('batch_id') or batch_id
            record['batch_status'] = batch_record.get('status')
            record['batch_submitted_at_utc'] = batch_record.get('submitted_at_utc')
            record['batch_collected_at_utc'] = batch_record.get('collected_at_utc')
            record['request_counts'] = batch_record.get('request_counts')
            record['error_summary'] = analysis_error_summary(record.get('error'))
            record['error_history'] = get_file_error_history(batch_state, request.get('drive_file_id'))
            failures.append(record)

    return sorted(
        failures,
        key=lambda record: (
            record.get('status') or '',
            (record.get('name') or '').casefold(),
            record.get('drive_file_id') or '',
        )
    )


def get_file_error_history(batch_state, drive_file_id):
    history = batch_state.get('file_error_history', {}).get(drive_file_id, [])
    return sorted(
        history,
        key=lambda entry: (
            entry.get('completed_at_utc') or '',
            entry.get('submitted_at_utc') or '',
            entry.get('custom_id') or '',
        )
    )


def generate_failures_json(batch_state, output_file):
    failures = collect_failure_records(batch_state)
    status_counts = {}
    for failure in failures:
        status = failure.get('status') or 'unknown'
        status_counts[status] = status_counts.get(status, 0) + 1

    payload = {
        'schema_version': 1,
        'generated_at_utc': utc_timestamp(),
        'total_failures': len(failures),
        'total_affected_files': len({
            failure.get('drive_file_id')
            for failure in failures
            if failure.get('drive_file_id')
        }),
        'status_counts': status_counts,
        'failures': failures,
    }

    log.info(f"Generating batch failure report: {output_file}...")
    output_dir = os.path.dirname(os.path.abspath(output_file))
    os.makedirs(output_dir, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def get_openai_client():
    if OpenAI is None:
        log.error("Error: the openai Python package is not installed. Run: pip install -r requirements.txt")
        return None

    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        log.error("Error: OPENAI_API_KEY environment variable not set.")
        return None
    return OpenAI(api_key=api_key)


def get_drive_service(phase_label):
    apis = {
        'drive': {
            'scope': Google.scopes['drive'],
            'api_name': 'drive',
            'api_version': 'v3',
        },
    }
    try:
        services = GoogleAuth.service_oauth_login(apis,
                                                  app_json=args.app_id,
                                                  user_json=args.user_credentials,
                                                  log=log)
        return services['drive']
    except Exception as e:
        log.error(f"Authentication failed for {phase_label}: {e}")
        return None


def discover_or_load_files():
    found_files = []

    if not args.skip_discovery:
        if not args.google_drive_root_url:
            log.error("Error: --google-drive-root-url is required for discovery (unless --skip-discovery is used).")
            return None

        service = get_drive_service("discovery")
        if not service:
            return None

        root_id = extract_folder_id(args.google_drive_root_url)
        cache = None
        if os.path.exists(args.google_drive_cache):
            try:
                cache = load_google_drive_cache(args.google_drive_cache)
                if cache.get('root_id') != root_id:
                    log.info(
                        "Existing Google Drive cache is for a different root folder; "
                        "performing full discovery."
                    )
                    cache = None
            except Exception as e:
                log.warning(f"Could not use Google Drive cache {args.google_drive_cache}: {e}")

        if cache:
            cache = refresh_google_drive_cache(service, cache)

        if not cache:
            cache = full_drive_discovery(service, root_id, args.google_drive_root_url)

        save_google_drive_cache(cache, args.google_drive_cache)
        found_files = get_selected_files_from_cache(cache)
    else:
        if not os.path.exists(args.google_drive_cache):
            log.error(f"Error: Google Drive cache file {args.google_drive_cache} not found. Cannot skip discovery.")
            return None
        try:
            cache = load_google_drive_cache(args.google_drive_cache)
        except Exception as e:
            log.error(f"Error: Could not load Google Drive cache file {args.google_drive_cache}: {e}")
            return None
        found_files = get_selected_files_from_cache(cache)

    if args.limit and len(found_files) > args.limit:
        log.info(f"Limiting analysis to the first {args.limit} selected files (original count: {len(found_files)})")
        found_files = found_files[:args.limit]

    return found_files


def run_synchronous_analysis(client, service, found_files):
    retry_filter_batch_state = create_batch_state()
    if args.retry_analysis_error_codes:
        try:
            retry_filter_batch_state = load_batch_state(args.state_dir)
        except Exception as e:
            log.error(f"Could not load OpenAI batch state for --retry-analysis-error-codes: {e}")
            return None

    log.info(f"Starting analysis of {len(found_files)} selected files...")
    skipped_retry_filter = 0

    for analysis_index, file in enumerate(found_files, start=1):
        file_id = file['id']
        log.info(f"Processing ({analysis_index} of {len(found_files)}): {file['name']} ({file_id})...")

        cached_data = get_cached_analysis(file_id, args.state_dir)
        use_cache = False

        if args.retry_analysis_error_codes and not file_matches_retry_error_filter(
            file,
            cached_data,
            retry_filter_batch_state,
        ):
            skipped_retry_filter += 1
            continue

        if cached_data:
            try:
                drive_mod_time_utc = get_source_modified_time_utc(file)
                if is_cached_analysis_fresh(cached_data, file):
                    log.info(
                        "  Using cached analysis results "
                        f"(cached {local_timestamp_or_unknown(cached_data.get('cached_at_utc'))}; "
                        f"Drive modified {local_timestamp_or_unknown(drive_mod_time_utc)})"
                    )
                    use_cache = True
                else:
                    log.info(
                        "  Re-analyzing because "
                        f"{cached_analysis_reanalysis_reason(cached_data, file)}"
                    )
            except Exception as e:
                log.warning(f"  Error comparing timestamps for {file_id}: {e}")

        if use_cache:
            continue

        prepared_file = download_file_for_analysis(service, file)
        if prepared_file and prepared_file.get('error'):
            error = prepared_file.get('error')
            data = None
        else:
            data, error = analyze_file(client, prepared_file)
        if prepared_file and prepared_file.get('path') and os.path.exists(prepared_file['path']):
            os.remove(prepared_file['path'])

        if data is not None:
            save_cached_analysis(file_id, data, args.state_dir, file)
        elif error:
            if error.get('type') == 'google_drive_download_error':
                status = download_failure_status(error)
            else:
                status = 'retryable_error' if is_retryable_analysis_error(error) else 'permanent_error'
            save_failed_analysis(file_id, error, args.state_dir, file, status)

    if args.retry_analysis_error_codes:
        log.info(
            f"Skipped {skipped_retry_filter} files that did not match "
            "--retry-analysis-error-codes."
        )

    return build_records_from_cached_analysis(
        found_files,
        match_analysis_strategy=not bool(args.retry_analysis_error_codes),
    )


def main():
    global args, log
    args = setup_cli_args()

    log = ECC.setup_logging(info=args.verbose,
                            debug=args.debug,
                            logfile=args.logfile,
                            rotate=True)

    found_files = discover_or_load_files()
    if found_files is None:
        return

    if args.skip_analysis:
        log.info("Skipping analysis as requested.")
        log.info("Done!")
        return

    client = get_openai_client()
    if not client:
        return

    if args.submit_analysis_batch:
        service = get_drive_service("batch submission")
        if not service:
            return
        if not submit_analysis_batch(client, service, found_files):
            return
        log.info("Done!")
        return

    if args.collect_analysis_batch:
        log.info("Collecting OpenAI batch analysis results...")
        records = collect_analysis_batches(client, found_files)
        if records is None:
            return
        log.info(f"Generating JSON output: {args.output}...")
        generate_json_output(records, args.output)
        log.info("Done!")
        return

    service = get_drive_service("analysis phase")
    if not service:
        return

    records = run_synchronous_analysis(client, service, found_files)
    if records is None:
        return

    log.info(f"Generating JSON output: {args.output}...")
    generate_json_output(records, args.output)
    log.info("Done!")


if __name__ == '__main__':
    main()
