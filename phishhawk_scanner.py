"""
PhishHawk – Advanced Phishing Analysis Tool
Author: Ebrahim Aref – Cyber Security Engineer @ Sunrun

A Python-based tool for scanning emails and URLs to detect potential phishing threats.
"""
import os
import re
import requests
from email import policy
from email.message import EmailMessage # Explicit import for type hinting if needed
from email.parser import BytesParser
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
import whois
import dns.resolver
import ssl
import socket
from bs4 import BeautifulSoup
# Import the tabulate function with an alias to avoid potential name conflicts
from tabulate import tabulate as tabulate_func
import logging
import hashlib
import time
from datetime import datetime, timezone, timedelta # Import timedelta
import json
import base64
import ipaddress
import math # For entropy calculation

# --- Configuration ---

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='phishhawk.log'
)
logger = logging.getLogger('phishhawk')

# Color codes for terminal output
RED, GREEN, YELLOW, END = '\033[91m', '\033[1;32m', '\033[93m', '\033[0m'

# --- API Key Management (IMPORTANT SECURITY IMPROVEMENT) ---
# Load API keys from environment variables.
# DO NOT HARDCODE KEYS HERE. Set them in your system environment.
# Example (Linux/macOS): export VIRUSTOTAL_API_KEY='your_vt_key'
# Example (Windows): set VIRUSTOTAL_API_KEY=your_vt_key
# API
VIRUSTOTAL_API_KEY = ""
ABUSEIPDB_API_KEY = ""
GOOGLE_SAFE_BROWSING_API_KEY = ""
IPQS_API_KEY = ""

# Check if required API keys are set
REQUIRED_KEYS = {
    "VirusTotal": VIRUSTOTAL_API_KEY,
    "AbuseIPDB": ABUSEIPDB_API_KEY,
    "Google Safe Browsing": GOOGLE_SAFE_BROWSING_API_KEY,
    "IPQS": IPQS_API_KEY
}
missing_keys = [name for name, key in REQUIRED_KEYS.items() if not key]
if missing_keys:
    logger.warning(f"Missing API keys for: {', '.join(missing_keys)}. Corresponding checks will be skipped or may fail.")
    print(f"{YELLOW}Warning: Missing API keys for: {', '.join(missing_keys)}. Set environment variables.{END}")

# Whitelists
WHITELISTED_SENDERS = ["linkedin.com", "google.com", "microsoft.com", "medium.com"]
WHITELISTED_URLS = ["linkedin.com", "google.com", "microsoft.com", "medium.com", "docs.google.com"]

# Common phishing keywords
PHISHING_KEYWORDS = [
    'account', 'alert', 'authenticate', 'bank', 'click', 'confirm', 'credit',
    'debit', 'expire', 'login', 'password', 'pay', 'purchase', 'secure',
    'update', 'urgent', 'verify', 'wallet', 'warning', 'unusual', 'activity',
    'action required', 'suspended', 'locked', 'compromised', 'identity'
]

# Cache directory
CACHE_DIR = os.path.join(os.getcwd(), '.cache')
os.makedirs(CACHE_DIR, exist_ok=True)

# --- Helper Functions ---

def runPEnv():
    """Clears the screen and prints the banner."""
    os.system('cls' if os.name == 'nt' else 'clear') # Clear screen for Windows/Linux/Mac
    print(f'''
{GREEN}__________.__    .__       .__  ________          __                 __
\______   \  |__ |__| _____|__| \______ \   _____/  |_  ____   _____/  |_  ___________
 |     ___/  |  \|  |/  ___/  |  |    |  \_/ __ \   __\/ __ \_/ ___\   __\/  _ \_  __ \
 |    |   |   Y  \  |\___ \|  |  |    `   \  ___/|  | \  ___/\  \___|  | (  <_> )  | \/
 |____|   |___|  /__/____  >__| /_______  /\___  >__|  \___  >\___  >__|  \____/|__|
               \/        \/             \/     \/          \/     \/
                                                                                   {END}

                [ {RED}PhishHawk  {END}|{RED}   Unmasking phishing  {END}]
                [ {YELLOW}Ebrahim Aref – Cyber Security Engineer @ Sunrun{END} ]
''')

def colorize_value(value, threshold=None):
    """Applies color coding to output values based on type and threshold."""
    if isinstance(value, str):
        val_lower = value.lower()
        if any(s in val_lower for s in ['none', 'fail', 'not found', 'error', 'phishing', 'suspicious', 'misaligned', 'malicious']):
            return f"{RED}{value}{END}"
        elif any(s in val_lower for s in ['legitimate', 'pass', 'safe', 'aligned', 'clean']):
            return f"{GREEN}{value}{END}"
        elif any(s in val_lower for s in ['unknown', 'pending', 'neutral', 'potentially', 'likely']):
            return f"{YELLOW}{value}{END}"
    elif isinstance(value, (int, float)) and threshold is not None:
        # Color numbers red if they meet or exceed the threshold
        if value >= threshold:
            return f"{RED}{value}{END}"
        else:
            # Optionally color 'good' numbers green, or leave default
            # return f"{GREEN}{value}{END}"
            pass # Keep default color for non-bad numbers
    return f"{value}" # Default no color

def get_cache_path(request_type, key):
    """Generates a cache file path based on request type and key using SHA256."""
    # Use SHA256 for better hash distribution than MD5
    cache_key = hashlib.sha256(f"{request_type}:{key}".encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{cache_key}.json")

def get_from_cache(request_type, key, max_age=3600):
    """Retrieves data from cache if it exists and is not expired."""
    cache_path = get_cache_path(request_type, key)
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
                if time.time() - cache_data.get('timestamp', 0) < max_age:
                    logger.info(f"Cache hit for {request_type}: {key[:20]}...")
                    return cache_data.get('data')
                else:
                    logger.info(f"Cache expired for {request_type}: {key[:20]}...")
        except json.JSONDecodeError:
            logger.error(f"Cache JSON decode error for {cache_path}. Ignoring cache.")
        except Exception as e:
            logger.error(f"Cache read error for {cache_path}: {e}")
    return None

# Modified function signature to accept max_age for caching errors too
def save_to_cache(request_type, key, data, max_age=None):
    """Saves data to the cache. Allows specifying max_age for error caching."""
    cache_path = get_cache_path(request_type, key)
    try:
        payload = {'timestamp': time.time(), 'data': data}
        # Note: max_age is used by get_from_cache, not directly stored here,
        # but passing it allows caching errors for a shorter duration if needed.
        with open(cache_path, 'w') as f:
            json.dump(payload, f)
        logger.info(f"Saved to cache for {request_type}: {key[:20]}...")
    except IOError as e:
         logger.error(f"Cache file write error for {cache_path}: {e}")
    except Exception as e:
        logger.error(f"Cache write error for {cache_path}: {e}")


def api_request(url, method='get', headers=None, params=None, data=None, json_data=None, timeout=20):
    """Makes an API request with improved error handling."""
    try:
        if method.lower() == 'get':
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
        elif method.lower() == 'post':
            response = requests.post(url, headers=headers, params=params, data=data, json=json_data, timeout=timeout)
        else:
            logger.error(f"Unsupported HTTP method: {method}")
            return {"error": f"Unsupported HTTP method: {method}"}

        # Raise exceptions for bad status codes (4xx or 5xx)
        response.raise_for_status()

        # Handle successful responses (e.g., 204 No Content) that might not have JSON
        if response.status_code == 204:
            return {} # Return empty dict for No Content
        # Handle cases where response might be empty but status is 200 OK
        if not response.content:
             return {}

        return response.json()

    except requests.exceptions.Timeout:
        logger.error(f"API request timed out: {url}")
        return {"error": "Request timed out"}
    except requests.exceptions.ConnectionError as e:
        logger.error(f"API connection error for {url}: {e}")
        return {"error": f"Connection error: {e}"}
    except requests.exceptions.HTTPError as e:
        # Log specific HTTP errors (e.g., 401 Unauthorized, 404 Not Found)
        logger.warning(f"API HTTP error for {url}: {response.status_code} {response.reason}. Response: {response.text[:200]}")
        return {"error": f"HTTP {response.status_code} {response.reason}", "status_code": response.status_code}
    except requests.exceptions.RequestException as e:
        # Catch other general request exceptions
        logger.error(f"API request error for {url}: {e}")
        return {"error": f"Request error: {e}"}
    except json.JSONDecodeError as e:
        logger.error(f"API JSON decode error for {url}. Response: {response.text[:200]}")
        return {"error": f"JSON decode error: {e}"}
    except Exception as e: # Catch any other unexpected errors
        logger.exception(f"Unexpected API request error for {url}: {e}") # Log traceback
        return {"error": f"Unexpected error: {str(e)}"}


# --- Reputation Check Functions (VirusTotal, AbuseIPDB, etc.) ---

def check_virustotal(api_type, identifier):
    """Generic function to check VirusTotal for domain, IP, or URL."""
    if not VIRUSTOTAL_API_KEY:
        # Return error but don't log excessively if key is known to be missing
        # logger.warning("VirusTotal API key not configured, skipping check.")
        return {"error": "VirusTotal API key not configured"}

    cache_key = identifier
    request_identifier = identifier # Keep original for logging/errors

    # Use URL hash for URL checks to keep cache key consistent and handle encoding
    if api_type == 'urls':
        # VirusTotal API v3 requires the URL to be base64 URL-safe encoded
        # Use SHA256 hash of the original URL for the cache key
        cache_key = hashlib.sha256(identifier.encode()).hexdigest()
        # Encode the identifier (URL) for the API call
        try:
            request_identifier = base64.urlsafe_b64encode(identifier.encode()).decode().strip('=')
        except Exception as e:
             logger.error(f"Base64 encoding failed for VT URL check: {identifier} - {e}")
             return {"error": "URL Base64 encoding failed"}


    cache_result = get_from_cache(f'vt_{api_type}', cache_key)
    if cache_result:
        return cache_result

    url = f"https://www.virustotal.com/api/v3/{api_type}/{request_identifier}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"}
    result = api_request(url, headers=headers)

    # Handle cases where VT might return 404 for non-existent resources
    # Also handle potential VT errors like quota exceeded (429) or invalid argument (400)
    if result.get("error"):
        status_code = result.get("status_code")
        if status_code == 404:
            logger.info(f"VirusTotal: Resource not found for {api_type} {identifier[:30]}...")
            not_found_data = {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0}, "not_found": True}
            save_to_cache(f'vt_{api_type}', cache_key, not_found_data)
            return not_found_data
        elif status_code == 400: # Handle invalid domain/URL format errors from VT
             logger.warning(f"VirusTotal returned 400 Bad Request for {api_type} {identifier[:30]}. Likely invalid format. Error: {result.get('error')}")
             # Cache this specific error briefly
             save_to_cache(f'vt_{api_type}', cache_key, result, max_age=300)
             return result
        elif status_code == 429:
             logger.warning(f"VirusTotal API quota exceeded for {api_type}. Caching error briefly.")
             save_to_cache(f'vt_{api_type}', cache_key, result, max_age=900) # Cache quota error for 15 mins
             return result
        else:
             # Cache other errors briefly
             logger.warning(f"VirusTotal API error for {api_type} {identifier[:30]}: {result.get('error')}")
             save_to_cache(f'vt_{api_type}', cache_key, result, max_age=300) # Cache errors for 5 mins
             return result


    if 'data' in result: # Check if 'data' key exists for successful responses
        data = result.get("data", {}).get("attributes", {})
        # Extract relevant stats for consistent caching
        stats = data.get("last_analysis_stats", {})
        relevant_data = {
            "last_analysis_stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            },
             "reputation": data.get("reputation"), # Domain/IP reputation score
             "last_analysis_date": data.get("last_analysis_date"),
             "total_votes": data.get("total_votes"), # Community score
             "whois": data.get("whois") # Include WHOIS if available from VT
        }
        save_to_cache(f'vt_{api_type}', cache_key, relevant_data)
        return relevant_data
    else:
         # Handle cases where API returns 200 OK but no 'data' (shouldn't happen often with VT)
         logger.warning(f"VirusTotal returned 200 OK but no 'data' field for {api_type} {identifier[:30]}. Response: {result}")
         # Cache this unexpected state briefly
         no_data_error = {"error": "API returned OK but no data field"}
         save_to_cache(f'vt_{api_type}', cache_key, no_data_error, max_age=300)
         return no_data_error

def check_virustotal_domain(domain):
    return check_virustotal('domains', domain)

def check_virustotal_url(url_to_check):
    return check_virustotal('urls', url_to_check)

def check_virustotal_ip(ip_address):
    return check_virustotal('ip_addresses', ip_address)

def get_whois_info(domain):
    """Gets WHOIS information for a domain, handling potential errors and date formats."""
    cache_result = get_from_cache('whois', domain)
    if cache_result:
        return cache_result

    try:
        # Add timeout to whois query using socket's default timeout
        # socket.setdefaulttimeout(10) # Set global timeout (might affect other sockets)
        # Note: python-whois doesn't directly support timeout parameter easily across lookups.
        # Relying on the default or system socket timeout.

        logger.debug(f"Performing WHOIS lookup for: {domain}")
        domain_info = whois.whois(domain)

        # Check for minimal required data (e.g., creation date might be missing sometimes)
        if not domain_info or not hasattr(domain_info, 'creation_date'):
             logger.warning(f"WHOIS lookup returned incomplete data for {domain} (missing creation_date or other fields).")
             # Return error or partial data depending on strictness needed
             # For scoring, we need creation_date, so return error if missing.
             if not hasattr(domain_info, 'creation_date') or not domain_info.creation_date:
                  return {"error": "Incomplete WHOIS data (Missing creation date)"}
             # Otherwise proceed with potentially partial data if other fields exist

        result = {
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "organization": getattr(domain_info, 'org', None), # Use getattr for safety
            "registrar": getattr(domain_info, 'registrar', None),
            "status": getattr(domain_info, 'status', None),
            "name_servers": getattr(domain_info, 'name_servers', []),
            "emails": getattr(domain_info, 'emails', [])
        }

        # Helper to safely format dates (handle lists and different types)
        def format_whois_date(date_field):
            if not date_field: return None # Handle None input

            if isinstance(date_field, list):
                # Take the first valid date from the list
                date_val = next((d for d in date_field if isinstance(d, datetime)), None)
            else:
                date_val = date_field

            if isinstance(date_val, datetime):
                # Ensure timezone awareness (assume UTC if naive)
                if date_val.tzinfo is None:
                    date_val = date_val.replace(tzinfo=timezone.utc)
                try:
                     # Ensure year is reasonable before formatting
                     if date_val.year < 1900 or date_val.year > datetime.now(timezone.utc).year + 10:
                          raise ValueError("Year out of reasonable range")
                     return date_val.isoformat()
                except ValueError as ve: # Handle potential issues with date values (e.g., year 0)
                     logger.warning(f"Could not format invalid datetime object: {date_val} - {ve}")
                     return str(date_val) # Fallback to string representation
            elif date_val:
                # Attempt to parse if it's a string (best effort)
                try:
                    # Handle various potential string formats if possible
                    # This is complex; relying on fromisoformat is simpler but less robust
                    dt_obj = datetime.fromisoformat(str(date_val).replace('Z', '+00:00'))
                    if dt_obj.tzinfo is None:
                         dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                    # Validate year again after parsing
                    if dt_obj.year < 1900 or dt_obj.year > datetime.now(timezone.utc).year + 10:
                         raise ValueError("Parsed year out of reasonable range")
                    return dt_obj.isoformat()
                except ValueError as ve:
                    logger.debug(f"Could not parse date string '{date_val}' to ISO format or year invalid: {ve}")
                    return str(date_val) # Return as string if parsing fails
            return None

        result["creation_date"] = format_whois_date(domain_info.creation_date)
        result["expiration_date"] = format_whois_date(domain_info.expiration_date)
        result["updated_date"] = format_whois_date(domain_info.updated_date)

        # Check again if creation date is None after formatting attempt
        if result["creation_date"] is None:
             logger.warning(f"Failed to format WHOIS creation date for {domain}.")
             # Decide if this constitutes an error for scoring purposes
             # return {"error": "Failed to format creation date"}

        save_to_cache('whois', domain, result)
        return result

    except whois.parser.PywhoisError as e:
        logger.error(f"WHOIS parsing error for {domain}: {e}")
        # Cache parsing errors briefly
        error_result = {"error": f"WHOIS parsing error: {e}"}
        save_to_cache('whois', domain, error_result, max_age=300)
        return error_result
    except socket.timeout:
         logger.error(f"WHOIS lookup timed out for {domain}")
         error_result = {"error": "WHOIS lookup timed out"}
         save_to_cache('whois', domain, error_result, max_age=300)
         return error_result
    except Exception as e: # Catch other potential errors like connection issues, unexpected data
        logger.error(f"WHOIS lookup unexpected error for {domain}: {e}", exc_info=True) # Log traceback
        error_result = {"error": f"WHOIS lookup error: {str(e)}"}
        save_to_cache('whois', domain, error_result, max_age=300)
        return error_result


def check_google_safe_browsing(url_to_check):
    """Checks a URL against the Google Safe Browsing API."""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        # logger.warning("Google Safe Browsing API key not configured, skipping check.")
        return {"error": "Google Safe Browsing API key not configured"}

    url_hash = hashlib.sha256(url_to_check.encode()).hexdigest() # Use SHA256
    cache_result = get_from_cache('gsb', url_hash)
    if cache_result is not None: # Check for None specifically, as empty list is valid cache
        return cache_result

    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    body = {
        "client": {
            "clientId": "phishi-detector", # Replace with your client ID if registered
            "clientVersion": "1.1"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }
    params = {'key': GOOGLE_SAFE_BROWSING_API_KEY}
    result = api_request(api_url, method='post', params=params, json_data=body)

    # GSB returns an empty dict {} if no threats are found, not an error
    if 'error' not in result:
        matches = result.get("matches", [])
        save_to_cache('gsb', url_hash, matches)
        return matches
    # Handle specific GSB errors if needed (e.g., API key invalid)
    elif result.get("error") and ("API key not valid" in result["error"] or "API_KEY_INVALID" in result["error"]):
         logger.error("Google Safe Browsing API key is invalid.")
         # Don't cache API key errors
         return {"error": "Invalid Google Safe Browsing API key"}
    else:
         # Log other errors but cache the error state briefly to avoid hammering
         logger.warning(f"Google Safe Browsing API error for {url_to_check}: {result.get('error')}")
         save_to_cache('gsb', url_hash, result, max_age=300) # Cache errors for 5 mins
         return result # Return the error dict

def check_ipqs(url_to_check):
    """Checks a URL against the IPQualityScore API."""
    if not IPQS_API_KEY:
        # logger.warning("IPQS API key not configured, skipping check.")
        return {"error": "IPQS API key not configured"}

    url_hash = hashlib.sha256(url_to_check.encode()).hexdigest() # Use SHA256
    cache_result = get_from_cache('ipqs', url_hash)
    if cache_result:
        return cache_result

    # IPQS API endpoint structure might vary, adjust if needed
    # Using parameter method seems more standard
    api_url = f"https://www.ipqualityscore.com/api/json/url/{IPQS_API_KEY}"
    params = {
         "url": url_to_check,
         "timeout": 15, # Request shorter timeout from IPQS if possible
         "strictness": 1 # Moderate strictness level (0-2)
         }

    result = api_request(api_url, params=params) # Default method is GET

    if 'error' not in result:
        # Check for specific IPQS success/failure indicators if available
        if result.get("success") is False:
             logger.warning(f"IPQS API request failed for {url_to_check}: {result.get('message')}")
             # Cache IPQS specific errors briefly
             error_data = {"error": result.get('message', 'IPQS request failed')}
             save_to_cache('ipqs', url_hash, error_data, max_age=300)
             return error_data
        save_to_cache('ipqs', url_hash, result)
        return result
    else:
        # Cache general API errors briefly
        save_to_cache('ipqs', url_hash, result, max_age=300)
        return result

def check_abuseipdb(ip_address):
    """Checks an IP address against the AbuseIPDB API."""
    if not ABUSEIPDB_API_KEY:
        # logger.warning("AbuseIPDB API key not configured, skipping check.")
        return {"error": "AbuseIPDB API key not configured"}
    if not is_ip_address(ip_address): # Basic validation
        return {"error": "Invalid IP address format"}

    cache_result = get_from_cache('abuseipdb', ip_address)
    if cache_result:
        return cache_result

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90', # API expects string
        'verbose': '' # Add verbose flag for more details if needed
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    result = api_request(url, headers=headers, params=params)

    # AbuseIPDB wraps results in a 'data' field upon success
    if 'error' not in result and 'data' in result:
        data = result['data']
        save_to_cache('abuseipdb', ip_address, data)
        return data
    elif 'errors' in result: # AbuseIPDB uses 'errors' list for failures
        error_message = result['errors'][0]['detail'] if (result['errors'] and isinstance(result['errors'], list) and result['errors'][0].get('detail')) else 'Unknown AbuseIPDB error'
        logger.warning(f"AbuseIPDB API error for {ip_address}: {error_message}")
        error_data = {"error": error_message}
        save_to_cache('abuseipdb', ip_address, error_data, max_age=300) # Cache errors briefly
        return error_data
    else: # Handle unexpected structure or non-API errors (like connection errors)
        # If result already contains 'error' from api_request, use that
        if 'error' not in result:
             result['error'] = 'Unexpected response structure from AbuseIPDB'
             logger.warning(f"Unexpected AbuseIPDB response structure for {ip_address}: {result}")

        save_to_cache('abuseipdb', ip_address, result, max_age=300)
        return result


# --- Email Processing Functions ---

def read_email_file(file_path):
    """Reads an email file (.eml) using BytesParser."""
    try:
        with open(file_path, 'rb') as f:
            # Use the default policy which creates EmailMessage objects
            return BytesParser(policy=policy.default).parse(f)
    except FileNotFoundError:
        logger.error(f"Email file not found: {file_path}")
        return None
    except IOError as e:
         logger.error(f"Error reading email file {file_path}: {e}")
         return None
    except Exception as e:
        logger.exception(f"Unexpected error reading email file {file_path}: {e}")
        return None

def extract_basic_email_details(msg):
    """Extracts basic header information from an email message object."""
    sender = msg.get('From')
    recipient = msg.get('To')
    reply_to = msg.get('Reply-To')
    return_path = msg.get('Return-Path') # Often contains the true sending address
    date_str = msg.get('Date')
    subject = msg.get('Subject', '') # Default to empty string if no subject

    sender_email, sender_name, sender_domain, sender_ip = None, None, None, "Not found"

    # Parse sender (handle various formats)
    if sender:
        sender_str = str(sender)
        # Regex to handle "Name <email@domain.com>" format
        match = re.match(r'^\s*(.*?)\s*<(.+@.+)>', sender_str)
        if match:
            sender_name = match.group(1).strip().strip('"') # Remove quotes and whitespace
            sender_email = match.group(2).strip()
        else:
            # Simple email address or potentially malformed - try to extract email-like part
            email_match = re.search(r'[\w\.-]+@[\w\.-]+', sender_str)
            if email_match:
                 sender_email = email_match.group(0).strip('<>')
            else:
                 # If no email found, use the whole string as name (less ideal)
                 sender_name = sender_str.strip()
                 sender_email = None # Explicitly set email to None if not found

    # Extract domain from sender email
    if sender_email and '@' in sender_email:
        try:
            # Handle potential display name remnants before the @
            email_part = sender_email.split('@')[-1]
            sender_domain = email_part
            # Basic validation for domain part
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', sender_domain):
                 logger.warning(f"Extracted domain '{sender_domain}' may be invalid from sender: {sender_email}")
                 # Optionally set sender_domain = None here if strict validation needed
        except IndexError:
            logger.warning(f"Could not extract domain from sender email: {sender_email}")
            sender_domain = None

    # Extract Sender IP (look in common headers, prioritize specific ones)
    # Regex to find IPv4 addresses more reliably
    ipv4_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_headers_priority = ["X-Sender-IP", "X-Originating-IP", "Received-SPF"] # Check these first
    received_headers = msg.get_all("Received", []) # Get all received headers

    # Check priority headers
    for header_name in ip_headers_priority:
        header_val = msg.get(header_name)
        if header_val:
            ip_match = re.search(ipv4_regex, str(header_val))
            if ip_match:
                potential_ip = ip_match.group(0)
                if is_ip_address(potential_ip) and not ipaddress.ip_address(potential_ip).is_private:
                    sender_ip = potential_ip
                    logger.debug(f"Found sender IP in {header_name}: {sender_ip}")
                    break # Found a valid public IP

    # Fallback: Check generic 'Received' headers if not found in priority ones
    if sender_ip == "Not found":
        for header in reversed(received_headers): # Check from bottom up (closer to origin)
            # Look for IP within square brackets or after 'from'/'by'
            ip_match = re.search(r'(?:from|by)\s+.*\[(' + ipv4_regex + r')\]|\[(' + ipv4_regex + r')\]', str(header))
            if ip_match:
                # Match groups capture IP inside brackets from 'from/by' or just inside brackets
                potential_ip = ip_match.group(1) or ip_match.group(2)
                if is_ip_address(potential_ip) and not ipaddress.ip_address(potential_ip).is_private:
                    sender_ip = potential_ip
                    logger.debug(f"Found sender IP in Received header: {sender_ip}")
                    break # Found valid public IP

    return {
        "date": date_str,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "sender_domain": sender_domain.lower() if sender_domain else None, # Store domain lowercase
        "sender_ip": sender_ip,
        "reply_to": reply_to,
        "return_path": return_path,
        "recipient": recipient,
        "subject": subject,
    }

# FIX: Added filtering for cid: links
def extract_urls_from_email(msg):
    """Extracts all unique URLs from the email body (text and HTML parts)."""
    urls = set()
    processed_parts = set() # Avoid processing the same part multiple times

    try:
        for part in msg.walk():
            # Check if part has already been processed (relevant for multipart/alternative)
            if part in processed_parts:
                continue

            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Skip attachments based on disposition or maintype (more robust)
            # Allow text/html parts even if disposition is attachment (e.g. saved webpage)
            is_attachment = "attachment" in content_disposition.lower()
            is_inline = "inline" in content_disposition.lower()
            main_type = part.get_content_maintype()

            # Skip non-text, non-multipart parts unless explicitly inline with filename (image?)
            if main_type not in ['text', 'multipart'] and not (is_inline and part.get_filename()):
                 continue
            # Skip parts clearly marked as attachment unless text/html
            if is_attachment and main_type != 'text':
                 continue


            # Check if it's a text or HTML part intended for display
            if content_type in ['text/plain', 'text/html']:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        # Detect charset or default to utf-8 with error handling
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                             body = payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError) as decode_err:
                             logger.warning(f"Could not decode email part with charset {charset}: {decode_err}. Trying fallback encodings.")
                             # Try common fallbacks
                             fallback_charsets = ['iso-8859-1', 'windows-1252']
                             body = None
                             for fb_charset in fallback_charsets:
                                  try:
                                       body = payload.decode(fb_charset, errors='replace')
                                       logger.info(f"Successfully decoded part with fallback: {fb_charset}")
                                       break
                                  except UnicodeDecodeError:
                                       continue
                             if body is None:
                                  logger.error(f"Failed to decode part even with fallbacks. Skipping.")
                                  continue # Skip this part if decoding fails completely


                        if content_type == 'text/plain':
                            extract_urls_from_text(body, urls)
                        elif content_type == 'text/html':
                            extract_urls_from_html(body, urls)

                        processed_parts.add(part) # Mark part as processed

                except Exception as e:
                    logger.error(f"Error processing email part payload ({content_type}): {e}", exc_info=True)

    except Exception as e:
        logger.exception(f"Error walking through email parts: {e}")

    # Clean, normalize, and filter URLs
    final_urls = set()
    for url in urls:
        try:
            # Basic cleaning: remove surrounding whitespace and common trailing chars
            cleaned = url.strip().rstrip('.,;!?)>"\'')

            # --- FILTERING ---
            # Ignore cid: links used for embedded content
            if cleaned.lower().startswith('cid:'):
                 logger.debug(f"Ignoring cid: link: {cleaned}")
                 continue
            # Ignore mailto:, tel:, data:, javascript:, ftp: schemes
            if re.match(r'^(mailto|tel|data|javascript|ftp):', cleaned, re.IGNORECASE):
                 logger.debug(f"Ignoring non-http(s) scheme link: {cleaned}")
                 continue

            # Add scheme if missing (default to http)
            if not re.match(r'^[a-zA-Z]+://', cleaned):
                 cleaned = 'http://' + cleaned

            # Use urlparse for basic validation and normalization
            parsed = urlparse(cleaned)
            # Require http/https scheme and a netloc (domain/IP)
            if parsed.scheme in ['http', 'https'] and parsed.netloc:
                 # Additional check: netloc should contain at least one dot or be a valid IP
                 if '.' in parsed.netloc or is_ip_address(parsed.netloc):
                      # Reconstruct for consistency (optional)
                      # cleaned = parsed.geturl()
                      final_urls.add(cleaned)
                 else:
                      logger.debug(f"Ignoring URL with invalid netloc: {cleaned}")

            elif not parsed.scheme and parsed.path and '.' in parsed.path:
                 # Handle cases like www.example.com without scheme that urlparse puts in path
                 cleaned = 'http://' + cleaned
                 parsed_again = urlparse(cleaned)
                 if parsed_again.scheme and parsed_again.netloc:
                      final_urls.add(cleaned)
                 else:
                      logger.debug(f"Ignoring URL after adding scheme (still invalid): {cleaned}")

        except Exception as parse_err:
             logger.warning(f"Could not clean or parse potential URL '{url}': {parse_err}")


    return list(final_urls)


def extract_urls_from_text(text, url_set):
    """Finds URLs in plain text using regex."""
    # Improved regex: handles various TLDs, paths, queries, fragments
    # Balances finding more URLs vs. false positives. May need tuning.
    # Includes basic handling for URLs in brackets/parentheses.
    # Allows longer TLDs, requires path/query/fragment or specific ending char
    url_regex = re.compile(
        # Scheme (optional http/https), or www, or domain part
        r'((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,18}/?)'
        # Path/query/fragment chars, allows nested parens, excludes trailing punctuation more carefully
        r'(?:[^\s()<>\[\]\'"]+|\(([^\s()<>\[\]\'"]+|(\([^\s()<>\[\]\'"]+\)))*\))+'
        # Ensure it doesn't end with common punctuation that shouldn't be part of the URL
        r'(?<![.,;!?])'
        r')',
        re.IGNORECASE | re.UNICODE
    )

    # Simpler regex as fallback or alternative (might miss complex cases but fewer false positives?)
    # url_regex_simple = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)

    for match in url_regex.finditer(text):
        url = match.group(0)
        # Further clean URL extracted by regex if needed
        url = url.rstrip('.')
        url_set.add(url)

def extract_urls_from_html(html, url_set):
    """Finds URLs in HTML content using BeautifulSoup and regex."""
    try:
        # Use 'html5lib' for better parsing of potentially broken HTML
        soup = BeautifulSoup(html, 'html5lib')

        # Extract from <a> tags href
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()
            # Ignore mailto, tel, javascript, #fragment links, and empty hrefs
            if href and not href.lower().startswith(('mailto:', 'tel:', 'javascript:', '#', 'data:', 'cid:')):
                url_set.add(href)

        # Extract from other common tags (img src, script src, link href, iframe src)
        for tag_name, attr_name in [('img', 'src'), ('script', 'src'), ('link', 'href'), ('iframe', 'src')]:
             for tag in soup.find_all(tag_name, **{attr_name: True}): # Find tags with the attribute set
                  attr_value = tag[attr_name].strip()
                  if attr_value and not attr_value.lower().startswith(('data:', 'javascript:', 'cid:')):
                       url_set.add(attr_value)


        # Extract from inline styles (background URLs) - More robust regex
        for tag in soup.find_all(style=True):
            # Find url(...) patterns in the style attribute, handle quotes
            style_urls = re.findall(r'url\s*\(\s*[\'"]?([^\'"\)\s]+)[\'"]?\s*\)', tag['style'])
            for style_url in style_urls:
                 # Ignore data URIs and cid: links
                 if not style_url.lower().startswith(('data:', 'cid:')):
                     url_set.add(style_url.strip())

        # Extract from text content within HTML as a fallback (using the improved regex)
        extract_urls_from_text(soup.get_text(), url_set)

    except Exception as e:
        logger.error(f"Error extracting URLs from HTML: {e}", exc_info=True)


def extract_attachments_from_email(msg):
    """Extracts information about attachments in the email."""
    attachments = []
    try:
        for part in msg.walk():
            # Check Content-Disposition header for attachment indication OR if filename exists
            filename = part.get_filename()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Check if it's likely an attachment
            is_attachment_disposition = "attachment" in content_disposition.lower()
            # Consider inline but with filename as potential attachment too (e.g., images)
            # is_inline_with_filename = "inline" in content_disposition.lower() and filename

            # Skip parts clearly not attachments (e.g., text/plain without filename/attachment disposition)
            # Also skip multipart containers themselves unless explicitly marked as attachment
            main_type = part.get_content_maintype()
            if not filename and not is_attachment_disposition:
                 if main_type == 'text': continue # Skip text parts without filename/attachment disposition
                 if main_type == 'multipart': continue # Skip multipart containers

            # Proceed if filename exists or disposition is attachment
            if filename or is_attachment_disposition:
                try:
                    content_type = part.get_content_type()
                    # Get payload size without decoding if possible, fallback to decoding
                    try:
                        payload_bytes = part.get_payload(decode=True)
                        size = len(payload_bytes) if payload_bytes else 0
                    except Exception as decode_err:
                         logger.warning(f"Could not decode attachment payload for size calculation ({filename or 'unnamed'}): {decode_err}. Estimating size.")
                         # Estimate size from raw payload if decode fails
                         raw_payload = part.get_payload(decode=False)
                         size = len(raw_payload) if isinstance(raw_payload, (str, bytes)) else 0


                    # Ensure filename is clean (remove potential path components)
                    clean_filename = os.path.basename(filename.strip()) if filename else "unnamed_attachment"

                    extension = os.path.splitext(clean_filename)[1].lower() if '.' in clean_filename else ''

                    attachment_info = {
                        'filename': clean_filename,
                        'content_type': content_type,
                        'size': size, # Size in bytes
                        'extension': extension
                    }

                    # Define potentially risky extensions (expanded list)
                    suspicious_exts = [
                        # Executables & Scripts
                        '.exe', '.scr', '.pif', '.bat', '.cmd', '.com', '.dll', '.cpl', '.hta',
                        '.vbs', '.vbe', '.js', '.jse', '.ps1', '.psm1', '.wsf', '.wsh',
                        # Installers & Archives
                        '.msi', '.msp', '.mst', '.cab',
                        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', # Archives
                        # Office Macro-Enabled & Exploitable Formats
                        '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.ppam', '.sldm',
                        '.doc', '.xls', '.ppt', # Older formats can contain exploits
                        '.rtf', # Can contain exploits
                        # Shortcuts & Disk Images
                        '.lnk',
                        '.iso', '.img', '.vhd', '.vmdk',
                        # Web/Other
                        '.html', '.htm', '.svg', # Can contain scripts/links
                        '.jar', # Java archives
                        '.swf', # Flash (legacy risk)
                        '.pdf' # PDFs can contain exploits/scripts
                    ]
                    # Higher risk extensions (more likely direct execution/scripting)
                    high_risk_exts = [
                         '.exe', '.scr', '.pif', '.bat', '.cmd', '.com', '.dll', '.cpl', '.hta',
                         '.vbs', '.vbe', '.js', '.jse', '.ps1', '.psm1', '.wsf', '.wsh',
                         '.jar', '.msi', '.msp', '.lnk'
                         ]

                    attachment_info['suspicious'] = extension in suspicious_exts
                    attachment_info['high_risk'] = extension in high_risk_exts

                    attachments.append(attachment_info)
                except Exception as e:
                    logger.error(f"Error processing attachment part ({filename or 'unnamed'}): {e}", exc_info=True)

    except Exception as e:
        logger.exception(f"Error walking through parts for attachments: {e}")

    return attachments

def extract_email_content(msg):
    """Extracts plain text and HTML content from the email message."""
    plain_text = None
    html_content = None

    # --- Strategy: Find the 'best' text/plain and text/html parts ---
    # Iterate through parts, preferring non-attachment parts.
    # If multipart/alternative, the iteration order might implicitly
    # find the preferred parts first, but we explicitly check content type.

    # Find the most likely main text/plain part
    for part in msg.walk():
        content_type = part.get_content_type()
        is_attachment = part.is_attachment() or "attachment" in str(part.get("Content-Disposition", "")).lower()

        if content_type == "text/plain" and not is_attachment:
            payload_bytes = part.get_payload(decode=True) # Decode here
            if payload_bytes is not None:
                 # Try decoding with detected or default charset
                 charset = part.get_content_charset() or 'utf-8'
                 try:
                      decoded_text = payload_bytes.decode(charset, errors='replace')
                      # Assign if plain_text is not already set or if this part seems better
                      # (e.g., longer, though simple length isn't a perfect heuristic)
                      if plain_text is None or len(decoded_text) > len(plain_text):
                           plain_text = decoded_text
                      # Don't break immediately, might find a better plain text part later
                      # (e.g., in multipart/alternative)
                 except (LookupError, UnicodeDecodeError):
                      # Try common fallbacks if initial decode fails
                      fallback_charsets = ['iso-8859-1', 'windows-1252']
                      decoded = False
                      for fb_charset in fallback_charsets:
                           try:
                                decoded_text = payload_bytes.decode(fb_charset, errors='replace')
                                if plain_text is None or len(decoded_text) > len(plain_text):
                                     plain_text = decoded_text
                                decoded = True
                                break
                           except UnicodeDecodeError:
                                continue
                      if not decoded:
                           logger.warning(f"Failed to decode text/plain part with charset {charset} and fallbacks.")
                           # Keep existing plain_text if any, otherwise it remains None

    # Find the most likely main text/html part
    for part in msg.walk():
        content_type = part.get_content_type()
        is_attachment = part.is_attachment() or "attachment" in str(part.get("Content-Disposition", "")).lower()

        if content_type == "text/html" and not is_attachment:
            payload_bytes = part.get_payload(decode=True) # Decode here
            if payload_bytes is not None:
                 # Try decoding with detected or default charset
                 charset = part.get_content_charset() or 'utf-8'
                 try:
                      decoded_html = payload_bytes.decode(charset, errors='replace')
                      if html_content is None or len(decoded_html) > len(html_content):
                           html_content = decoded_html
                 except (LookupError, UnicodeDecodeError):
                      # Try common fallbacks if initial decode fails
                      fallback_charsets = ['iso-8859-1', 'windows-1252']
                      decoded = False
                      for fb_charset in fallback_charsets:
                           try:
                                decoded_html = payload_bytes.decode(fb_charset, errors='replace')
                                if html_content is None or len(decoded_html) > len(html_content):
                                     html_content = decoded_html
                                decoded = True
                                break
                           except UnicodeDecodeError:
                                continue
                      if not decoded:
                           logger.warning(f"Failed to decode text/html part with charset {charset} and fallbacks.")
                           # Keep existing html_content if any

    # --- Strategy: If only HTML found, extract text from it ---
    if html_content is not None and plain_text is None:
        try:
            soup = BeautifulSoup(html_content, 'html5lib')
            plain_text_from_html = soup.get_text(separator=' ', strip=True)
            if plain_text_from_html:
                 plain_text = plain_text_from_html
            else:
                 plain_text = "" # Ensure plain_text is at least an empty string
        except Exception as e:
            logger.error(f"Could not extract text from HTML content: {e}")
            if plain_text is None: plain_text = "" # Ensure plain_text is string if extraction fails

    # Ensure both are strings, defaulting to empty string if None
    plain_text = plain_text if plain_text is not None else ""
    html_content = html_content if html_content is not None else ""

    return plain_text.strip(), html_content.strip()


def check_content_for_phishing_indicators(text, html_content=""):
    """Analyzes email text and HTML for common phishing indicators."""
    indicators = []
    points = 0
    text_lower = text.lower().strip() # Use stripped lowercase text

    # Return early if text is essentially empty
    if not text_lower:
         return {'indicators': [], 'score': 0, 'suspicious': False}

    # --- Keyword/Phrase Checks ---
    # Higher weights for more direct credential requests or threats
    keyword_categories = {
        "Urgency/Threat": (['urgent', 'immediate', 'action required', 'final notice', 'warning', 'alert', 'suspended', 'locked', 'blocked', 'unauthorized access', 'suspicious activity', 'security alert', 'account compromised', 'unusual sign-in', 'verify your identity', 'problem with your account'], 0.7),
        "Financial/Reward": (['won', 'winner', 'prize', 'lottery', 'inheritance', 'claim your reward', 'refund', 'invoice', 'payment due', 'confirm your payment', 'transaction failed', 'payment details', 'bitcoin', 'crypto', 'investment opportunity', 'wire transfer'], 0.5),
        "Credential Request": (['login', 'password', 'username', 'userid', 'pin', 'ssn', 'social security', 'sign in', 're-enter password', 'verify your information', 'confirm your account', 'security check', 'authentication required', 'account verification', 'your credentials', 'reset your password', 'update your details', 'validate your account'], 1.0),
        "Generic/Social Engineering": (['click here', 'follow this link', 'view document', 'download attachment', 'confirm subscription', 'dear customer', 'dear valued user', 'undelivered mail', 'storage limit exceeded', 'verify account', 'update required'], 0.3),
        "Greeting/Salutation": (['dear friend', 'dear sir/madam', 'undisclosed recipients'], 0.4) # Impersonal greetings
    }

    found_keywords = set()
    for category, (phrases, weight) in keyword_categories.items():
        # Use word boundaries for some keywords to reduce false positives
        matches = []
        for phrase in phrases:
             try:
                  # Simple check first
                  if phrase in text_lower:
                       # Add more specific regex for common words if needed
                       if len(phrase.split()) == 1 and phrase in ['login', 'password', 'bank', 'account', 'click', 'update', 'verify']:
                            if re.search(r'\b' + re.escape(phrase) + r'\b', text_lower):
                                 matches.append(phrase)
                       else:
                            matches.append(phrase)
             except re.error as re_err: # Catch potential regex errors in phrases
                  logger.warning(f"Regex error for phrase '{phrase}': {re_err}")
                  if phrase in text_lower: # Fallback to simple check
                       matches.append(phrase)


        if matches:
            unique_matches = set(matches)
            indicators.append(f"{category}: {', '.join(list(unique_matches)[:3])}{'...' if len(unique_matches) > 3 else ''}")
            # Add points per unique phrase found in this category
            points += len(unique_matches) * weight
            found_keywords.update(unique_matches)

    # --- Structural/Formatting Checks ---
    grammar_issues = 0
    # Basic checks (can be expanded with a grammar library if needed)
    common_errors = ['kindly', 'pls ', 'urgent reply needed', 'information is require', 'login details below', 'click link below'] # Examples
    # Check for multiple consecutive punctuation marks or excessive capitalization
    if re.search(r'[!?,.]{2,}', text) or re.search(r'\b[A-Z]{5,}\b', text): # Multiple punctuation or long ALL CAPS words
        grammar_issues += 1
    # Very simple check for awkward phrasing (needs improvement)
    if 'attached herewith' in text_lower or 'as per attached' in text_lower:
        grammar_issues += 1

    if grammar_issues > 0:
        indicators.append(f"Poor grammar/formatting issues found")
        points += grammar_issues * 0.3 # Lower weight for grammar

    # --- HTML Specific Checks (if HTML is available) ---
    link_mismatch_found = False # Flag to count only one major mismatch
    form_found = False
    hidden_text_found = False

    if html_content:
        try:
            # Use html5lib for better tolerance of malformed HTML
            soup = BeautifulSoup(html_content, 'html5lib')

            # 1. Link Mismatch (Display text vs. actual href) - More robust check
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].strip()
                # Get visible text, handle images inside links
                text_content = a_tag.get_text(strip=True)
                if not text_content: # If link contains only image, check alt text
                     img_tag = a_tag.find('img', alt=True)
                     if img_tag: text_content = img_tag['alt'].strip()

                # Ignore non-http links
                if not href.lower().startswith('http'): continue

                # Check if display text looks like a domain/URL but differs significantly from href domain
                is_text_url_like = re.match(r'^(www\.|[a-z0-9.-]+\.[a-z]{2,})', text_content, re.IGNORECASE)
                if is_text_url_like and text_content != href:
                     try:
                          href_domain = urlparse(href).netloc.lower().replace('www.', '')
                          # Attempt to parse text content as URL to get domain
                          text_domain = urlparse( 'http://' + text_content if not text_content.startswith('http') else text_content).netloc.lower().replace('www.', '')

                          # Penalize if domains differ (and text domain looks valid)
                          if href_domain and text_domain and href_domain != text_domain:
                                indicators.append(f"Link mismatch: Text '{text_content[:30]}...' points to domain '{href_domain}'")
                                points += 1.2
                                link_mismatch_found = True
                                break # Count one major mismatch
                     except Exception as parse_err:
                          logger.debug(f"Could not parse domains for link mismatch check: {parse_err}")


            # 2. Use of Forms (especially password fields)
            password_input = soup.find('input', {'type': 'password'})
            if soup.find('form') and password_input:
                indicators.append("HTML form with password field found")
                points += 1.0
                form_found = True

            # 3. Obfuscation techniques (tiny fonts, hidden elements, text matching background) - Basic checks
            # Tiny font size check
            tiny_font = soup.find(style=lambda s: s and ('font-size' in s.lower() and (('px' in s and int(re.search(r'\d+', s).group()) < 6) or ('pt' in s and int(re.search(r'\d+', s).group()) < 4))))
            # Hidden elements check (display:none, visibility:hidden, opacity:0)
            hidden_style = soup.find(style=lambda s: s and any(prop in s.lower() for prop in ['display:none', 'visibility:hidden', 'opacity:0']))
            if tiny_font or hidden_style:
                 indicators.append("Potentially hidden text/elements found in HTML")
                 points += 0.5
                 hidden_text_found = True

            # 4. Embedded scripts (especially from external/suspicious sources)
            for script_tag in soup.find_all('script', src=True):
                 script_src = script_tag['src']
                 try:
                      src_domain = urlparse(script_src).netloc.lower()
                      # Check if script source is external and not from a known CDN/trusted source (needs a list)
                      # Example: if src_domain and src_domain not in TRUSTED_SCRIPT_DOMAINS:
                      #     points += 0.3
                      #     indicators.append(f"External script source: {src_domain}")
                 except Exception: pass # Ignore script src parsing errors

        except Exception as e:
            logger.error(f"Error analyzing HTML content: {e}", exc_info=True)

    # --- Overall Score Adjustment ---
    # Reduce points slightly if text is very short (less context)
    if len(text) < 50: # Shorter threshold
        points *= 0.7
    elif len(text) < 150:
         points *= 0.9


    final_points = round(max(0, points), 2) # Ensure score is not negative

    return {
        'indicators': indicators,
        'score': final_points,
        'suspicious': final_points >= 1.5 # Adjust threshold as needed
    }


# --- Scoring and Verdict ---

def calculate_email_phishing_score(email_details, results, url_results, attachments, content_analysis, auth_alignment, is_whitelisted):
    """Calculates a phishing score based on various analysis results."""
    score = 0.0
    reasons = [] # Keep track of factors contributing to the score

    # 1. Authentication Checks (SPF, DKIM, DMARC, Alignment)
    spf_result = results.get('spf', 'Not checked')
    dkim_result = results.get('dkim', 'Not checked')
    dmarc_result = results.get('dmarc', 'Not checked')

    # SPF Penalty (Fail/SoftFail/Error)
    if spf_result not in ["Pass", "Not checked", "Neutral", "None"]: # None can be valid if no mail sent
        score += 1.5
        reasons.append(f"SPF Check Failed ({spf_result})")
    elif spf_result == "Neutral":
         score += 0.3
         reasons.append("SPF Neutral")
    elif spf_result == "Pass (Permissive +all)": # Penalize overly permissive SPF slightly
         score += 0.2
         reasons.append("SPF Permissive (+all)")


    # DKIM Penalty (Fail/Error/None) - None is suspicious if mail expected
    if dkim_result not in ["Pass", "Not checked"]:
        if dkim_result == "None" and email_details.get('sender_domain'): # No signature from known domain is suspicious
             score += 1.0
             reasons.append(f"DKIM Missing (None)")
        elif dkim_result != "None": # Fail or Error
             score += 1.5
             reasons.append(f"DKIM Check Failed ({dkim_result})")

    # DMARC Penalty (Missing/None Policy/Fail)
    if dmarc_result in ["No DMARC record", "Error checking DMARC", "Timeout"]:
        score += 1.0
        reasons.append("DMARC Missing/Error")
    elif dmarc_result == "Pass (p=none)":
        score += 0.5
        reasons.append("DMARC Policy=None")
    # Note: DMARC 'Fail' isn't a direct output of check_dmarc, it depends on alignment + policy.
    # Alignment check handles the DMARC failure implication.

    # Alignment Check Penalty (if checks passed but domains didn't align)
    # Use the alignment dictionary directly
    alignment = results.get('auth_alignment', {'aligned': True}) # Get the result
    if not alignment.get('aligned', True): # Default to True if check failed
        # Only penalize if at least one auth method (SPF/DKIM) passed validation but failed alignment
        # (Logic moved inside check_authentication_alignment to determine 'aligned' status)
        score += 2.0
        # Construct reason based on which domain was present/misaligned if needed
        reason_detail = []
        if alignment.get('dkim_domain'): reason_detail.append("DKIM")
        if alignment.get('spf_domain'): reason_detail.append("SPF")
        if reason_detail:
            reasons.append(f"Authentication Misaligned ({'/'.join(reason_detail)})")
        else: # Should not happen if aligned is False, but as fallback:
            reasons.append("Authentication Misaligned")


    # 2. Sender Reputation (Domain/IP)
    sender_domain = email_details.get('sender_domain')
    sender_ip = email_details.get('sender_ip')

    # VirusTotal Domain Reputation
    if sender_domain and 'vt_domain' in results and isinstance(results['vt_domain'], dict) and 'error' not in results['vt_domain']:
        vt_domain = results['vt_domain']
        stats = vt_domain.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        if malicious > 0:
            score += min(malicious * 0.6 + 0.5, 2.5) # Base penalty + per engine
            reasons.append(f"VT Domain Malicious ({malicious})")
        elif suspicious > 0:
             score += min(suspicious * 0.3, 1.0)
             reasons.append(f"VT Domain Suspicious ({suspicious})")

    # VirusTotal IP Reputation
    if sender_ip and sender_ip != "Not found" and 'vt_ip' in results and isinstance(results['vt_ip'], dict) and 'error' not in results['vt_ip']:
        vt_ip = results['vt_ip']
        stats = vt_ip.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        if malicious > 0:
            score += min(malicious * 0.4 + 0.3, 2.0)
            reasons.append(f"VT IP Malicious ({malicious})")
        elif suspicious > 0:
             score += min(suspicious * 0.2, 0.8)
             reasons.append(f"VT IP Suspicious ({suspicious})")

    # AbuseIPDB Reputation
    if sender_ip and sender_ip != "Not found" and 'abuseipdb' in results and isinstance(results['abuseipdb'], dict) and 'error' not in results['abuseipdb']:
        abuseipdb = results['abuseipdb']
        abuse_score = abuseipdb.get('abuseConfidenceScore', 0)
        reports = abuseipdb.get('totalReports', 0)
        if abuse_score >= 75: # Higher threshold for major penalty
            score += min(abuse_score / 35.0, 3.0) # Increase impact
            reasons.append(f"AbuseIPDB Score Very High ({abuse_score})")
        elif abuse_score >= 40: # Moderate threshold
            score += min(abuse_score / 50.0, 1.5) # Scale score contribution
            reasons.append(f"AbuseIPDB Score Moderate ({abuse_score})")
        elif reports > 10: # Even low scores with many reports are suspicious
             score += min(reports * 0.05, 1.0) # Increase potential impact
             reasons.append(f"AbuseIPDB High Report Count ({reports})")

    # WHOIS Domain Age
    if sender_domain and 'whois' in results and isinstance(results['whois'], dict) and 'error' not in results['whois']:
        whois_info = results['whois']
        creation_date_str = whois_info.get('creation_date')
        if creation_date_str:
            try:
                # Parse ISO format date string, ensuring timezone awareness
                creation_date = datetime.fromisoformat(creation_date_str)
                now = datetime.now(timezone.utc) # Use timezone-aware current time
                # Ensure creation_date is timezone-aware (assume UTC if naive)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)

                # Ignore check if creation date is clearly wrong (e.g., way in the future)
                if creation_date > now + timedelta(days=1):
                     logger.warning(f"WHOIS creation date {creation_date_str} is unreasonably far in the future for {sender_domain}.")
                else:
                     domain_age_days = (now - creation_date).days

                     if domain_age_days < 0: # Allow small grace period for clock skew
                          if domain_age_days < -5:
                               score += 1.5
                               reasons.append("WHOIS Creation Date in Future?")
                          # else: ignore small negative age
                     elif domain_age_days < 15: # Very recent
                          score += 2.0
                          reasons.append(f"WHOIS Domain Age < 15 days ({domain_age_days})")
                     elif domain_age_days < 60: # Recent
                          score += 1.2
                          reasons.append(f"WHOIS Domain Age < 60 days ({domain_age_days})")
                     elif domain_age_days < 180: # Relatively new
                          score += 0.6
                          reasons.append(f"WHOIS Domain Age < 180 days ({domain_age_days})")
            except (ValueError, TypeError) as e:
                logger.error(f"Error parsing domain creation date '{creation_date_str}': {e}")
            except Exception as e: # Catch any other unexpected date issues
                 logger.error(f"Unexpected error calculating domain age from '{creation_date_str}': {e}")
        else:
             # Penalize slightly if WHOIS lookup worked but creation date is missing
             score += 0.3
             reasons.append("WHOIS Creation Date Missing")


    # 3. URL Analysis
    malicious_urls = 0
    suspicious_urls = 0
    potentially_susp_urls = 0
    total_url_score = 0
    num_urls_analyzed = len(url_results)

    for url_result in url_results:
        # Ensure url_result is a dictionary before accessing keys
        if isinstance(url_result, dict):
            url_verdict = url_result.get('verdict', 'Unknown')
            url_score = url_result.get('score', 0)
            total_url_score += url_score
            if url_verdict == "Phishing":
                malicious_urls += 1
            elif url_verdict == "Suspicious":
                suspicious_urls += 1
            elif url_verdict == "Potentially Suspicious":
                 potentially_susp_urls += 1
        else:
             logger.warning(f"Unexpected item in url_results (expected dict): {url_result}")


    if malicious_urls > 0:
        score += min(malicious_urls * 2.0, 4.5) # Higher weight for confirmed phishing URLs
        reasons.append(f"Phishing URLs Found ({malicious_urls})")
    if suspicious_urls > 0:
        score += min(suspicious_urls * 1.0, 2.5)
        reasons.append(f"Suspicious URLs Found ({suspicious_urls})")
    if potentially_susp_urls > 0:
         score += min(potentially_susp_urls * 0.5, 1.5)
         reasons.append(f"Potentially Suspicious URLs Found ({potentially_susp_urls})")

    # Add a small contribution from the average URL score if no direct hits but average is high
    if malicious_urls == 0 and suspicious_urls == 0 and num_urls_analyzed > 0:
         avg_url_score = total_url_score / num_urls_analyzed
         if avg_url_score > 1.5: # Threshold for average score impact
              score += min((avg_url_score - 1.5) * 0.3, 0.7) # Scale impact based on how high avg is
              reasons.append(f"High Avg URL Score ({avg_url_score:.2f})")


    # 4. Attachment Analysis
    high_risk_attachments = sum(1 for attachment in attachments if attachment.get('high_risk', False))
    suspicious_attachments = sum(1 for attachment in attachments if attachment.get('suspicious', False) and not attachment.get('high_risk', False))

    if high_risk_attachments > 0:
        score += high_risk_attachments * 2.5 # High penalty for directly executable/script attachments
        reasons.append(f"High-Risk Attachments ({high_risk_attachments})")
    if suspicious_attachments > 0:
        # Slightly increase penalty for suspicious but not high-risk
        score += suspicious_attachments * 1.2
        reasons.append(f"Suspicious Attachments ({suspicious_attachments})")

    # 5. Content Analysis
    if content_analysis.get('suspicious', False):
        content_score = content_analysis.get('score', 0)
        # Increase impact of content score
        score += min(content_score * 1.0, 3.0) # Scale content score contribution more strongly
        reasons.append(f"Suspicious Content (Score: {content_score})")

    # 6. Header Mismatches
    reply_to = email_details.get('reply_to')
    from_email = email_details.get('sender_email')
    return_path = email_details.get('return_path') # Often the true envelope sender
    sender_domain_lower = email_details.get('sender_domain') # Already lowercase

    # Reply-To different from From domain
    if reply_to and from_email and '@' in reply_to:
        try:
            # Extract email from potentially complex Reply-To field
            reply_email_match = re.search(r'[\w\.-]+@[\w\.-]+', reply_to)
            if reply_email_match:
                 reply_email = reply_email_match.group(0).lower()
                 if '@' in reply_email:
                      reply_domain = reply_email.split('@')[1]
                      if sender_domain_lower and reply_domain != sender_domain_lower:
                           # Allow subdomains of the sender domain
                           if not reply_domain.endswith('.' + sender_domain_lower):
                                score += 1.5
                                reasons.append("Reply-To Domain Mismatch")
        except Exception as e:
             logger.warning(f"Could not parse Reply-To header '{reply_to}': {e}")


    # Return-Path different from From domain (can be legitimate, but adds suspicion)
    if return_path and from_email and return_path != '<>': # Ignore null return path
         try:
             # Clean return path <address@domain.com> or just address@domain.com
             return_path_email_match = re.search(r'[\w\.-]+@[\w\.-]+', return_path)
             if return_path_email_match:
                 return_path_email = return_path_email_match.group(0).lower()
                 if '@' in return_path_email:
                      return_path_domain = return_path_email.split('@')[1]
                      if sender_domain_lower and return_path_domain != sender_domain_lower:
                           if not return_path_domain.endswith('.' + sender_domain_lower):
                                score += 0.5 # Lower penalty as this can be normal (mailing lists etc)
                                reasons.append("Return-Path Domain Mismatch")
         except Exception as e:
              logger.warning(f"Could not parse Return-Path header '{return_path}': {e}")


    # 7. Whitelisting Adjustment
    if is_whitelisted:
        # Apply a significant reduction, but don't necessarily make it zero
        score *= 0.2 # Reduce score by 80% for whitelisted sender
        reasons.append("Sender Whitelisted (Score Reduced)")

    # Final score capping
    final_score = max(0.0, min(score, 10.0)) # Ensure score is between 0 and 10

    logger.info(f"Email Score Calculation: Final={final_score:.2f}, Base={score:.2f}, Reasons={reasons}")

    return final_score, reasons


def get_email_verdict(score):
    """Determines the email verdict based on the calculated score."""
    # Adjusted thresholds based on refined scoring
    if score <= 1.0:
        return "Legitimate"
    elif score <= 3.0: # Increased threshold for likely legitimate
        return "Likely Legitimate"
    elif score <= 5.5: # Slightly adjusted suspicious threshold
        return "Suspicious"
    elif score <= 7.5: # Adjusted highly suspicious threshold
        return "Highly Suspicious"
    else:
        return "Phishing"

# --- URL Analysis Functions ---

# FIX: Added stricter validation for domain/IP before API calls
def analyze_url(url, analyzed_domains_cache=None):
    """Analyzes a single URL for phishing indicators."""
    if analyzed_domains_cache is None:
         analyzed_domains_cache = {} # Initialize if not passed

    # --- Input Validation and Parsing ---
    try:
        original_url = url # Keep original for hashing/reporting
        # Pre-parse cleaning: Add scheme if missing
        if not re.match(r'^[a-zA-Z]+://', url):
             url = 'http://' + url

        parsed_url = urlparse(url)
        # Check for essential components and basic validity
        if not parsed_url.scheme in ['http', 'https'] or not parsed_url.netloc:
            raise ValueError("Missing http/https scheme or domain/netloc")

        domain_ip_raw = parsed_url.netloc.lower() # e.g., example.com:8080 or 1.2.3.4:80
        # Separate domain/IP from port
        domain_or_ip = domain_ip_raw
        if ':' in domain_ip_raw:
             domain_or_ip = domain_ip_raw.split(':', 1)[0]

        # --- Stricter Validation of Domain/IP ---
        is_ip = is_ip_address(domain_or_ip)
        # Regex for basic domain validation (allows LDH rule - letters, digits, hyphen)
        # Does not validate TLD existence, just format.
        domain_regex = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'
        if not is_ip and not re.match(domain_regex, domain_or_ip):
             # Check for common invalid characters that might slip through urlparse
             if re.search(r'[{}[\]<>"\s]', domain_or_ip): # Check for braces, brackets, quotes, spaces etc.
                  raise ValueError(f"Invalid characters found in domain part: {domain_or_ip}")
             # If not IP and doesn't match basic domain pattern, treat as invalid
             raise ValueError(f"Domain part '{domain_or_ip}' is not a valid domain format")

    except ValueError as ve:
         logger.warning(f"Invalid URL format skipped: {original_url} - {ve}")
         return {"url": original_url, "error": f"Invalid URL format: {ve}", "score": 0, "verdict": "Error"}
    except Exception as e: # Catch other parsing errors
         logger.error(f"URL parsing failed for {original_url}: {e}")
         return {"url": original_url, "error": f"URL parsing error: {e}", "score": 0, "verdict": "Error"}

    # --- Whitelist Check ---
    is_whitelisted_url = False
    for wl_domain in WHITELISTED_URLS:
         # Ensure wl_domain is not empty before checking endswith
         if wl_domain and (domain_or_ip == wl_domain or domain_or_ip.endswith('.' + wl_domain)):
              is_whitelisted_url = True
              break

    if is_whitelisted_url:
        logger.info(f"URL whitelisted: {url}")
        return {
            "url": url,
            "domain": domain_or_ip, # Use the validated domain/IP
            "features": {},
            "api_results": {},
            "verdict": "Legitimate (Whitelisted)",
            "score": 0,
            "reasons": ["URL Whitelisted"]
        }

    # --- Feature Extraction ---
    # Pass the validated domain/IP to feature extraction
    features = extract_url_features(url, parsed_url, domain_or_ip, is_ip)

    # --- API Calls (Concurrent) ---
    api_results = {}
    # Use SHA256 hash of the *original* input URL for caching consistency
    url_hash_key = hashlib.sha256(original_url.encode()).hexdigest()

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}

        # Check cache for full URL analysis result first
        cached_full_analysis = get_from_cache('url_analysis', url_hash_key)
        if cached_full_analysis:
             logger.info(f"Full URL analysis cache hit for: {url}")
             # Ensure cached result has the 'reasons' field
             if 'reasons' not in cached_full_analysis:
                  cached_full_analysis['reasons'] = ['Loaded from cache']
             return cached_full_analysis # Return cached result directly


        # Submit API checks (using the validated URL and domain/IP)
        if VIRUSTOTAL_API_KEY:
             futures['virustotal_url'] = executor.submit(check_virustotal_url, url)
        if GOOGLE_SAFE_BROWSING_API_KEY:
             futures['google_safe_browsing'] = executor.submit(check_google_safe_browsing, url)
        if IPQS_API_KEY:
             futures['ipqs'] = executor.submit(check_ipqs, url)

        # Domain/IP specific checks (using validated domain_or_ip)
        cache_key = f"{'ip' if is_ip else 'domain'}_{domain_or_ip}"

        if cache_key in analyzed_domains_cache:
             logger.info(f"Using cached reputation for {'IP' if is_ip else 'Domain'}: {domain_or_ip}")
             # Load cached results into the current api_results
             for k, v in analyzed_domains_cache[cache_key].items():
                  if k not in api_results: # Avoid overwriting URL-specific results
                       api_results[k] = v
        else:
             domain_futures = {}
             if is_ip:
                  if VIRUSTOTAL_API_KEY:
                       domain_futures['vt_ip'] = executor.submit(check_virustotal_ip, domain_or_ip)
                  if ABUSEIPDB_API_KEY:
                       domain_futures['abuseipdb'] = executor.submit(check_abuseipdb, domain_or_ip)
             else: # Is a domain
                  if VIRUSTOTAL_API_KEY:
                       domain_futures['vt_domain'] = executor.submit(check_virustotal_domain, domain_or_ip)
                  # Run WHOIS check concurrently only for domains
                  domain_futures['whois'] = executor.submit(get_whois_info, domain_or_ip)

             # Add domain futures to main futures dict to be collected
             futures.update(domain_futures)


        # Collect results from all futures
        for key, future in futures.items():
            try:
                api_results[key] = future.result()
            except Exception as e:
                logger.error(f"Error getting result for {key} on {url}: {e}", exc_info=True)
                api_results[key] = {"error": f"Future execution error: {str(e)}"}

        # Store domain/IP results back in the shared cache if they were fetched *and* successful
        if cache_key not in analyzed_domains_cache:
             domain_cache_data = {}
             if is_ip:
                  if 'vt_ip' in api_results and isinstance(api_results['vt_ip'], dict) and 'error' not in api_results['vt_ip']:
                       domain_cache_data['vt_ip'] = api_results['vt_ip']
                  if 'abuseipdb' in api_results and isinstance(api_results['abuseipdb'], dict) and 'error' not in api_results['abuseipdb']:
                       domain_cache_data['abuseipdb'] = api_results['abuseipdb']
             else:
                  if 'vt_domain' in api_results and isinstance(api_results['vt_domain'], dict) and 'error' not in api_results['vt_domain']:
                       domain_cache_data['vt_domain'] = api_results['vt_domain']
                  if 'whois' in api_results and isinstance(api_results['whois'], dict) and 'error' not in api_results['whois']:
                       domain_cache_data['whois'] = api_results['whois']

             if domain_cache_data: # Only store if we got some non-error results
                  analyzed_domains_cache[cache_key] = domain_cache_data


    # --- Scoring & Verdict ---
    score, reasons = calculate_url_phishing_score(features, api_results)
    verdict = get_url_verdict(score)

    analysis_result = {
        "url": url,
        "domain": domain_or_ip, # Store the validated domain/IP
        "features": features,
        "api_results": api_results, # Include API results for detailed report
        "verdict": verdict,
        "score": round(score, 2),
        "reasons": reasons
    }

    # Cache the final analysis result for the URL
    save_to_cache('url_analysis', url_hash_key, analysis_result)

    return analysis_result


# FIX: Accept validated domain/IP and is_ip flag
def extract_url_features(url, parsed_url, domain_or_ip, is_ip):
    """Extracts various features from a URL string and its parsed components."""
    # domain_ip_raw = parsed_url.netloc.lower() # Use the passed, validated domain/IP
    path = parsed_url.path
    query = parsed_url.query
    fragment = parsed_url.fragment

    domain_part = domain_or_ip if not is_ip else None # Only set domain_part if not IP

    features = {
        "url": url, # Store original URL for reference
        "domain_ip_for_rep_check": domain_or_ip, # Domain or IP used for lookups
        "is_ip_address": is_ip,
        "url_length": len(url),
        "domain_length": len(domain_or_ip),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "subdomain_count": domain_or_ip.count('.') if not is_ip else 0, # Count dots only in domains
        "path_depth": len([p for p in path.split('/') if p]), # Number of '/' separated parts
        "query_param_count": len(parse_qs(query)),
        "domain_dash_count": domain_or_ip.count('-'),
        "path_dash_count": path.count('-'),
        "query_underscore_count": query.count('_'),
        "path_dot_count": path.count('.'), # Dots in path can be suspicious
        "domain_digit_count": sum(c.isdigit() for c in domain_or_ip),
        "path_digit_count": sum(c.isdigit() for c in path),

        "has_at_sign": '@' in parsed_url.netloc.lower(), # Check original netloc for '@' (userinfo)
        "has_double_slash_in_path": '//' in path.lstrip('/'), # Check path after initial slash
        "has_hex_chars": bool(re.search(r'%[0-9a-fA-F]{2}', url)), # Percent encoding
        "has_suspicious_tld": has_suspicious_tld(domain_or_ip) if not is_ip else False,
        "has_suspicious_keywords": has_suspicious_keywords(url), # Check whole URL
        "is_shortened_url": is_shortened_url(domain_or_ip) if not is_ip else False,
        "uses_https": parsed_url.scheme == 'https',
        "uses_non_std_port": uses_uncommon_port(parsed_url),

        # Calculate entropy only for the actual domain part (excluding TLD) if it's not an IP
        "domain_entropy": calculate_string_entropy(domain_part.split('.')[-2]) if domain_part and '.' in domain_part and len(domain_part.split('.')) > 1 else 0.0,
        "path_entropy": calculate_string_entropy(path),
        "query_entropy": calculate_string_entropy(query),

        "contains_brand_name": contains_brand_name(domain_or_ip) if not is_ip else False,
        "is_potential_typosquatting": check_typosquatting(domain_or_ip) if not is_ip else False,
        "has_redirect_param": has_unusual_redirect_param(query)
    }
    return features

def calculate_url_phishing_score(features, api_results):
    """Calculates a phishing score for a URL based on features and API results."""
    score = 0.0
    reasons = []

    # --- Feature-Based Scoring ---
    feature_weights = {
        # Structural/Length - Penalties increase with deviation
        "is_ip_address": 1.5, # Direct weight
        "url_length_thresh": (80, 0.025), # (threshold, weight_per_char_over)
        "domain_length_thresh": (25, 0.06),
        "path_length_thresh": (60, 0.015),
        "subdomain_count_thresh": (3, 0.5), # (threshold, weight_per_subdomain_over)
        "path_depth_thresh": (4, 0.3),
        "domain_dash_count_thresh": (1, 0.4),
        "path_dot_count_thresh": (1, 0.6),
        "domain_digit_count_ratio": (0.3, 1.0), # (ratio_threshold, weight)
        # Suspicious Characters/Patterns - Direct penalties
        "has_at_sign": 1.2, # Direct weight
        "has_double_slash_in_path": 0.8, # Direct weight
        "has_hex_chars": 0.6, # Direct weight
        "has_suspicious_tld": 1.5, # Direct weight
        "has_suspicious_keywords": 1.8, # Direct weight
        "is_shortened_url": 1.0, # Direct weight
        "uses_non_std_port": 0.7, # Direct weight
        # Security/Entropy
        "uses_https": -1.2, # Direct weight (bonus)
        "domain_entropy_thresh": (3.5, 0.3), # (threshold, weight_per_unit_over)
        "path_entropy_thresh": (4.0, 0.1),
        # Deception Techniques
        "contains_brand_name": 2.0, # Direct weight
        "is_potential_typosquatting": 1.8, # Direct weight
        "has_redirect_param": 1.0, # Direct weight
    }

    # Apply weights based on feature values
    # Iterate through features present in the 'features' dict first
    for feature_key, feature_value in features.items():
        if feature_key in feature_weights:
            weight_config = feature_weights[feature_key]

            # --- Handle Threshold-Based Weights ---
            if isinstance(weight_config, tuple):
                # Check if it's ratio or threshold type based on key name convention
                if feature_key.endswith("_thresh"):
                    threshold, weight = weight_config
                    # Ensure feature_value is numeric before comparing
                    if isinstance(feature_value, (int, float)) and feature_value > threshold:
                        increase = (feature_value - threshold) * weight
                        score += increase
                        # Use the base feature key name in the reason
                        reason_key = feature_key.replace("_thresh", "")
                        reasons.append(f"{reason_key} > {threshold} (Val: {feature_value}, Score +{increase:.2f})")
                elif feature_key.endswith("_ratio"):
                    threshold, weight = weight_config
                    # Need corresponding count and length features to calculate ratio
                    count_key = feature_key.replace("_ratio", "_count")
                    length_key = feature_key.replace("_ratio", "_length")
                    count_value = features.get(count_key, 0)
                    length_value = features.get(length_key, 0)
                    # Ensure values are numeric and length > 0
                    if isinstance(count_value, (int, float)) and isinstance(length_value, (int, float)) and length_value > 0:
                         if (count_value / length_value) > threshold:
                              score += weight
                              reason_key = feature_key.replace("_ratio", "")
                              reasons.append(f"{reason_key} ratio > {threshold} (Score +{weight:.2f})")

            # --- Handle Direct Boolean/Value Weights ---
            elif isinstance(weight_config, (int, float)):
                weight = weight_config
                # Apply weight if feature is True (for boolean features)
                if isinstance(feature_value, bool) and feature_value:
                     # Special case for HTTPS (negative score/bonus)
                     if feature_key == "uses_https":
                          # Apply HTTPS bonus more readily, cap its effect if score is already low
                          bonus = max(weight, -score * 0.5) # Bonus is at most half the current positive score
                          if bonus < 0: # Only apply if bonus is negative
                               score += bonus
                               reasons.append(f"Uses HTTPS (Score {bonus:.2f})")
                     # Avoid double counting IP address penalty applied via direct weight
                     elif feature_key != "is_ip_address":
                          score += weight
                          reasons.append(f"Feature: {feature_key} (Score +{weight:.2f})")
                # Could add logic here for non-boolean features with direct weights if needed


    # --- API Result-Based Scoring ---
    # (Keep this section as it was, it accesses api_results directly)

    # VirusTotal URL
    if 'virustotal_url' in api_results and isinstance(api_results['virustotal_url'], dict) and 'error' not in api_results['virustotal_url']:
        stats = api_results['virustotal_url'].get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        if malicious > 0:
            increase = min(malicious * 0.8 + 0.5, 3.5) # Base + per engine, increased cap
            score += increase
            reasons.append(f"VT URL Malicious ({malicious}) (Score +{increase:.2f})")
        elif suspicious > 0:
             increase = min(suspicious * 0.4, 1.5)
             score += increase
             reasons.append(f"VT URL Suspicious ({suspicious}) (Score +{increase:.2f})")

    # Google Safe Browsing
    # GSB result is a list of matches, or an error dict
    if 'google_safe_browsing' in api_results:
        gsb_result = api_results['google_safe_browsing']
        if isinstance(gsb_result, list): # Success case (list of matches or empty list)
            if gsb_result: # Non-empty list means a threat was found
                threat_types = list(set(match.get('threatType', 'UNKNOWN') for match in gsb_result))
                increase = 2.8 # Increased strong signal from GSB
                score += increase
                reasons.append(f"GSB Hit ({', '.join(threat_types)}) (Score +{increase:.2f})")
        elif isinstance(gsb_result, dict) and 'error' in gsb_result:
             logger.warning(f"Google Safe Browsing check failed: {gsb_result['error']}")
             # Optional: Add a small penalty for failed check? reasons.append("GSB Check Failed") score += 0.1


    # IPQS
    if 'ipqs' in api_results and isinstance(api_results['ipqs'], dict) and 'error' not in api_results['ipqs']:
        ipqs_data = api_results['ipqs']
        risk = ipqs_data.get('risk_score', 0)
        is_phishing = ipqs_data.get('phishing', False)
        is_malware = ipqs_data.get('malware', False)
        is_suspicious = ipqs_data.get('suspicious', False)
        ipqs_increase = 0

        if is_phishing: ipqs_increase = max(ipqs_increase, 2.2) # Increased weight
        elif is_malware: ipqs_increase = max(ipqs_increase, 1.7) # Increased weight
        elif is_suspicious: ipqs_increase = max(ipqs_increase, 1.0) # Increased weight

        if risk > 85:
            ipqs_increase = max(ipqs_increase, min((risk - 85) * 0.1 + 0.5, 2.0)) # Add score based on high risk, ensure minimum bump

        if ipqs_increase > 0:
             score += ipqs_increase
             reason_parts = []
             if is_phishing: reason_parts.append("Phishing")
             if is_malware: reason_parts.append("Malware")
             if is_suspicious: reason_parts.append("Suspicious")
             if risk > 85: reason_parts.append(f"Risk:{risk}")
             reasons.append(f"IPQS Hit ({','.join(reason_parts)}) (Score +{ipqs_increase:.2f})")


    # Domain/IP Reputation (reuse results from email analysis if available)
    domain_rep_key = 'vt_ip' if features.get("is_ip_address") else 'vt_domain'
    if domain_rep_key in api_results and isinstance(api_results[domain_rep_key], dict) and 'error' not in api_results[domain_rep_key]:
        stats = api_results[domain_rep_key].get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        rep_increase = 0
        if malicious > 0:
            rep_increase = max(rep_increase, min(malicious * 0.5 + 0.2, 2.2)) # Slightly lower weight than direct URL hit
        elif suspicious > 0:
             rep_increase = max(rep_increase, min(suspicious * 0.25, 1.2))
        if rep_increase > 0:
             score += rep_increase
             rep_type = 'IP' if features.get('is_ip_address') else 'Domain'
             status = "Malicious" if malicious > 0 else "Suspicious"
             count = malicious if malicious > 0 else suspicious
             reasons.append(f"VT {rep_type} {status} ({count}) (Score +{rep_increase:.2f})")


    if 'abuseipdb' in api_results and isinstance(api_results['abuseipdb'], dict) and 'error' not in api_results['abuseipdb']:
         abuse_score_val = api_results['abuseipdb'].get('abuseConfidenceScore', 0)
         abuse_increase = 0
         if abuse_score_val >= 75: # Higher threshold
             abuse_increase = max(abuse_increase, min(abuse_score_val / 40.0, 2.5)) # Increase impact
         elif abuse_score_val >= 40:
             abuse_increase = max(abuse_increase, min(abuse_score_val / 50.0, 1.5))

         if abuse_increase > 0:
             score += abuse_increase
             reasons.append(f"AbuseIPDB Score High ({abuse_score_val}) (Score +{abuse_increase:.2f})")


    # WHOIS Age (for domains)
    if not features.get("is_ip_address") and 'whois' in api_results and isinstance(api_results['whois'], dict) and 'error' not in api_results['whois']:
        creation_date_str = api_results['whois'].get('creation_date')
        if creation_date_str:
            try:
                creation_date = datetime.fromisoformat(creation_date_str)
                now = datetime.now(timezone.utc)
                if creation_date.tzinfo is None: creation_date = creation_date.replace(tzinfo=timezone.utc)

                if creation_date <= now + timedelta(days=1): # Ignore unreasonable future dates
                     domain_age_days = (now - creation_date).days
                     age_increase = 0
                     age_reason = None

                     if domain_age_days < 0: # Allow small grace period
                          if domain_age_days < -5: age_increase = 1.0; age_reason = "WHOIS Creation Date in Future?"
                     elif domain_age_days < 15: age_increase = 1.2; age_reason = f"WHOIS Domain Age < 15 days ({domain_age_days})"
                     elif domain_age_days < 60: age_increase = 0.8; age_reason = f"WHOIS Domain Age < 60 days ({domain_age_days})"
                     elif domain_age_days < 180: age_increase = 0.4; age_reason = f"WHOIS Domain Age < 180 days ({domain_age_days})"

                     if age_increase > 0:
                          score += age_increase
                          reasons.append(f"{age_reason} (Score +{age_increase:.2f})")

            except Exception as e:
                logger.error(f"Error parsing domain creation date for URL feature: {e}")


    final_score = max(0.0, min(score, 10.0)) # Cap score between 0 and 10
    logger.info(f"URL Score Calculation ({features.get('url', 'N/A')}): Final={final_score:.2f}, Base={score:.2f}, Reasons={reasons}")
    return final_score, reasons


def get_url_verdict(score):
    """Determines the URL verdict based on its score."""
    # Adjusted thresholds for URL scoring
    if score <= 0.8: # Lower threshold for legitimate
        return "Legitimate"
    elif score <= 2.0: # Adjusted potentially suspicious
        return "Potentially Suspicious"
    elif score <= 4.5: # Adjusted suspicious
        return "Suspicious"
    else: # score > 4.5
        return "Phishing"

# --- URL Feature Helper Functions ---

def is_ip_address(domain_or_ip):
    """Checks if a string is a valid IP address (v4 or v6)."""
    if not domain_or_ip: return False
    try:
        ipaddress.ip_address(domain_or_ip)
        return True
    except ValueError:
        return False

def has_suspicious_tld(domain):
    """Checks if the domain uses a TLD often associated with phishing."""
    if not domain or '.' not in domain: return False
    # List can be expanded based on threat intelligence (e.g., from Spamhaus DBL)
    suspicious_tlds = [
        # Common / High Risk
        '.xyz', '.top', '.info', '.club', '.site', '.online', '.buzz', '.rest',
        '.tk', '.ml', '.ga', '.cf', '.gq', # Freenom TLDs (often abused)
        '.link', '.click', '.live', '.loan', '.work', '.ninja', '.world',
        '.accountants', '.download', '.racing', '.security', '.gift', '.review',
        '.zip', '.mov', # Recently abused gTLDs
        # Less common but sometimes abused
        '.biz', '.ws', '.cc', '.pw', '.asia', '.vip', '.icu'
        ]
    # Check the actual TLD part
    try:
         # Use effective TLD list concepts if possible (e.g., publicsuffixlist library)
         # Simple check for now:
         tld = '.' + domain.split('.')[-1]
         return tld in suspicious_tlds
    except IndexError:
         return False


def has_suspicious_keywords(url):
    """Checks if the URL (domain, path, query) contains common phishing-related keywords."""
    url_lower = url.lower()
    # Use the globally defined PHISHING_KEYWORDS list
    # Check for keywords as whole words or parts of words
    return any(re.search(r'\b' + re.escape(keyword) + r'\b|' + re.escape(keyword), url_lower) for keyword in PHISHING_KEYWORDS)


def is_shortened_url(domain):
    """Checks if the domain belongs to a known URL shortening service."""
    if not domain: return False
    shortening_services = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
        'adf.ly', 'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae', 'cutt.ly', 'rebrand.ly',
        'soo.gd', 's2r.co', 'shorte.st', 'clk.im', 'mcaf.ee', 'su.pr', 'rb.gy',
        'shorturl.at', 'wa.me', 'fb.me' # Add more as needed
    ]
    # Check if the domain *is* or *ends with* a known shortener domain
    # (e.g., handles custom shortener domains like pep.si)
    domain_lower = domain.lower()
    return any(domain_lower == service or domain_lower.endswith('.' + service) for service in shortening_services)

def uses_uncommon_port(parsed_url):
    """Checks if the URL specifies a port other than standard HTTP/HTTPS ports."""
    if parsed_url.port:
        # Standard ports for common web/mail protocols
        common_ports = [80, 443, 8080, 8443, 21, 22, 23, 25, 110, 143, 993, 995]
        return parsed_url.port not in common_ports
    return False

def calculate_string_entropy(text):
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    text = str(text) # Ensure it's a string
    # Calculate frequency of each character
    freq = {}
    text_len = len(text)
    if text_len == 0: return 0.0 # Avoid division by zero for empty strings
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        if count > 0: # Avoid log2(0)
            probability = count / text_len
            entropy -= probability * math.log2(probability)
    return entropy

def contains_brand_name(domain):
    """Checks if the domain likely contains a known brand name (potential impersonation)."""
    if not domain: return False
    # List of common targets (lowercase) - expand as needed
    popular_brands = [
        'paypal', 'apple', 'amazon', 'microsoft', 'google', 'facebook', 'instagram',
        'netflix', 'gmail', 'outlook', 'hotmail', 'live', 'office', 'windows', 'azure',
        'twitter', 'linkedin', 'whatsapp', 'telegram', 'meta',
        'bank', 'wellsfargo', 'chase', 'bankofamerica', 'citibank', 'hsbc', 'barclays', 'capitalone', 'usaa',
        'amex', 'mastercard', 'visa', 'discover',
        'dropbox', 'icloud', 'adobe', 'docusign', 'onedrive',
        'yahoo', 'aol',
        'coinbase', 'binance', 'kraken', 'metamask', # Crypto
        'dhl', 'fedex', 'ups', 'usps', # Shipping
        'irs', 'gov', 'hmrc', 'servicecanada', # Government (often impersonated)
        'ebay', 'walmart', 'costco', 'target', # Retail
        'steam', 'epicgames', 'playstation', 'xbox', # Gaming
        'verizon', 'at&t', 'comcast', 'xfinity' # ISP/Telecom
    ]
    # Check parts of the domain against the brand list more carefully
    domain_lower = domain.lower()
    domain_parts = re.split(r'[.-]', domain_lower) # Split by dot or dash

    # Check if a brand name exists as a whole part or substring within a part
    # Avoid matching the TLD itself if it resembles a brand (e.g., '.live')
    # Ensure part is long enough to be meaningful (avoid matching 'a' in 'bank')
    return any( (brand == part or brand in part)
                for brand in popular_brands
                for part in domain_parts[:-1] # Exclude TLD part
                if len(part) >= max(3, len(brand) - 1) ) # Part should be reasonably long


def check_typosquatting(domain):
    """Performs basic checks for common typosquatting techniques."""
    if not domain: return False
    domain_lower = domain.lower()
    # Common target domains (keys) and typical typo variations/patterns (values)
    common_targets = {
        # Target: [list of common typos or regex patterns]
        'google': ['g00gle', 'googie', 'gogle', 'googel', 'googl', 'gooogle', 'googgle'],
        'paypal': ['paypa1', 'paypai', 'paypaI', 'paypol', 'paaypal', r'paypa\w'], # Added regex for extra char
        'microsoft': ['micros0ft', 'micosoft', 'mlcrosoft', 'rnicrosoft', 'microsfot', 'microsof', 'mircosoft'],
        'apple': ['appie', 'app1e', 'aple', 'appl', 'aplle', 'aapple'],
        'amazon': ['amazn', 'amaz0n', 'amzon', 'amason', 'arnazon', 'amazonn', 'ammazon'],
        'facebook': ['faceb00k', 'faceboook', 'fcbook', 'fcebook', 'facebok', 'faceboook', 'faebook'],
        'linkedin': ['linkdin', 'linkedn', 'linkein', 'linkedln'],
        'netflix': ['netflx', 'netfix', 'netfli', 'neflix'],
        'gmail': ['gmai', 'gmil', 'gmal'],
        'outlook': ['outlok', 'outloook', 'outlokk'],
        # Add more brands and patterns
    }

    domain_parts = domain_lower.split('.') # Check main part primarily
    # Handle cases like single-word domains (e.g., localhost) or just TLD (.com)
    if len(domain_parts) > 1:
         main_domain_part = domain_parts[-2]
    elif len(domain_parts) == 1:
         main_domain_part = domain_parts[0]
    else: # Empty domain?
         return False


    for target, variations in common_targets.items():
        # Check if the main domain part IS a typo variation
        if main_domain_part in variations:
             # Ensure it's not the actual target (e.g., google.com)
             if main_domain_part != target:
                  return True

        # Check if the main domain part CONTAINS a typo variation (more sensitive)
        # E.g., "secure-g00gle-login.com"
        if any(var in main_domain_part for var in variations if len(var) > 2): # Avoid short/common substrings
             if main_domain_part != target:
                  # Add check: is the target brand *also* in the domain? Increases confidence.
                  if target in main_domain_part:
                       return True


    # Check for common techniques like character repetition, omission, transposition (more advanced)
    # Example: Homoglyphs (e.g., 'pаypal' using Cyrillic 'а') - Requires unicode normalization/comparison

    return False # Default if no basic typos found


def has_unusual_redirect_param(query_string):
    """Checks if the query string contains common parameters used for open redirects, often followed by http(s)."""
    if not query_string:
        return False
    # Common redirect parameter names (lowercase) - expanded list
    redirect_params = [
        'url', 'redirect', 'goto', 'next', 'continue', 'return_to', 'returnto',
        'r_url', 'dest', 'destination', 'target', 'redir', 'redirect_uri', 'return',
        'r', 'u', 'go', 'ReturnUrl', 'redirecturl', 'redirect_url', 'checkout_url',
        'image_url', 'callback', 'cb', 'next_url' # Add more as observed
    ]
    query_lower = query_string.lower()
    # Check if any param is followed by '=' and then 'http://' or 'https://' or '//'
    for param in redirect_params:
        # Regex: param_name followed by = then optionally quotes then http(s):// or // (protocol relative)
        # Use word boundary \b to avoid matching params within other words
        try:
             # Ensure param is not empty before compiling regex
             if not param: continue
             # Match param at start of query string or after &
             if re.search(rf'(?:^|&)\b{re.escape(param)}\b\s*=\s*[\'"]?(?:https?:|)//', query_lower):
                 return True
        except re.error as re_err: # Handle potential errors in param regex escaping if needed
             logger.warning(f"Regex error checking redirect param '{param}': {re_err}")
             # Fallback to simpler check
             if f"{param}=http" in query_lower: return True

    return False


# --- Reporting ---

def display_email_analysis_report(email_details, results, url_results, attachments, content_analysis, auth_alignment, phishing_score, score_reasons, verdict):
    """Formats and prints the detailed email analysis report."""
    print("\n" + "="*80)
    print(f"{GREEN}       EMAIL ANALYSIS REPORT       {END}".center(80))
    print("="*80)

    # --- Basic Details ---
    email_table = [
        ["Date", email_details.get('date', 'N/A')],
        ["Subject", email_details.get('subject', 'N/A')],
        ["Sender Name", email_details.get('sender_name', 'N/A')],
        # Color sender if domain is suspicious based on VT or WHOIS age?
        ["Sender Email", colorize_value(email_details.get('sender_email', 'N/A'))],
        ["Sender Domain", email_details.get('sender_domain', 'N/A')],
        ["Sender IP", colorize_value(email_details.get('sender_ip', 'Not found'), 1)], # Color if IP found
        ["Reply-To", email_details.get('reply_to', 'N/A')],
        ["Return-Path", email_details.get('return_path', 'N/A')],
        # ["Recipient", email_details.get('recipient', 'N/A')] # Often less relevant
    ]
    print(f"\n{GREEN}--- EMAIL DETAILS ---{END}")
    # Use the aliased function name here
    print(tabulate_func(email_table, tablefmt="pretty"))

    # --- Authentication ---
    auth_table = [
        ["SPF", colorize_value(results.get('spf', 'Not checked'))],
        ["DKIM", colorize_value(results.get('dkim', 'Not checked'))],
        ["DMARC", colorize_value(results.get('dmarc', 'Not checked'))],
        ["Alignment (DKIM/SPF)", colorize_value("Aligned" if auth_alignment.get('aligned', False) else "Misaligned")]
    ]
    print(f"\n{GREEN}--- EMAIL AUTHENTICATION ---{END}")
    # Use the aliased function name here
    print(tabulate_func(auth_table, tablefmt="pretty"))
    if not auth_alignment.get('aligned', True):
         print(f"  {YELLOW}Note:{END} From: {auth_alignment.get('from_domain')}, DKIM Domain: {auth_alignment.get('dkim_domain')}, SPF Domain: {auth_alignment.get('spf_domain')}")

    # --- Sender Reputation ---
    reputation_table = []
    sender_domain = email_details.get('sender_domain')
    sender_ip = email_details.get('sender_ip')

    # WHOIS
    if sender_domain and 'whois' in results:
        whois_info = results['whois']
        if isinstance(whois_info, dict) and 'error' not in whois_info:
            created = whois_info.get('creation_date', 'Unknown')
            # expires = whois_info.get('expiration_date', 'Unknown') # Less relevant for phishing
            registrar = whois_info.get('registrar', 'Unknown')
            age_str = "Unknown"
            if created and created != 'Unknown':
                 try:
                     creation_date = datetime.fromisoformat(created)
                     now = datetime.now(timezone.utc)
                     if creation_date.tzinfo is None: creation_date = creation_date.replace(tzinfo=timezone.utc)

                     if creation_date <= now + timedelta(days=1): # Ignore future dates beyond tolerance
                         age_days = (now - creation_date).days
                         if age_days >= 0:
                              age_str = f"{age_days} days"
                              # Highlight young domains based on thresholds used in scoring
                              if age_days < 60: age_str = colorize_value(age_str, 0) # Yellow/Red for < 60 days
                         else:
                              age_str = f"{YELLOW}Future Date?{END}"
                     else:
                          age_str = f"{RED}Invalid Date{END}"

                 except Exception as e:
                      logger.debug(f"Could not calculate age from WHOIS date {created}: {e}")
                      age_str = "Parse Error"

            # Truncate long registrar names
            registrar_display = registrar[:35] + '...' if registrar and len(registrar) > 35 else registrar
            reputation_table.append(["WHOIS", f"Created: {created.split('T')[0] if created and 'Unknown' not in created else 'N/A'} (Age: {age_str}), Registrar: {registrar_display}"])
        elif isinstance(whois_info, dict): # Handle error case
             reputation_table.append(["WHOIS", colorize_value(f"Error: {whois_info.get('error', 'Unknown WHOIS Error')}", 1)])
        else: # Handle unexpected type
             reputation_table.append(["WHOIS", colorize_value(f"Error: Unexpected WHOIS result format", 1)])


    # VirusTotal Domain
    if sender_domain and 'vt_domain' in results:
         vt_domain = results['vt_domain']
         if isinstance(vt_domain, dict) and 'error' not in vt_domain:
              stats = vt_domain.get('last_analysis_stats', {})
              # Add reputation score if available
              rep_score = vt_domain.get('reputation')
              rep_display = f" (Rep: {rep_score})" if rep_score is not None else ""
              rep_data = f"Mal: {colorize_value(stats.get('malicious', 0), 1)}, Susp: {colorize_value(stats.get('suspicious', 0), 1)}, Hmless: {stats.get('harmless', 0)}{rep_display}"
              reputation_table.append(["VT Domain", rep_data])
         elif isinstance(vt_domain, dict):
              reputation_table.append(["VT Domain", colorize_value(f"Error: {vt_domain.get('error', 'Unknown VT Domain Error')}", 1)])
         else:
              reputation_table.append(["VT Domain", colorize_value(f"Error: Unexpected VT Domain result format", 1)])


    # VirusTotal IP
    if sender_ip and sender_ip != "Not found" and 'vt_ip' in results:
         vt_ip = results['vt_ip']
         if isinstance(vt_ip, dict) and 'error' not in vt_ip:
              stats = vt_ip.get('last_analysis_stats', {})
              rep_score = vt_ip.get('reputation')
              rep_display = f" (Rep: {rep_score})" if rep_score is not None else ""
              rep_data = f"Mal: {colorize_value(stats.get('malicious', 0), 1)}, Susp: {colorize_value(stats.get('suspicious', 0), 1)}, Hmless: {stats.get('harmless', 0)}{rep_display}"
              reputation_table.append(["VT IP", rep_data])
         elif isinstance(vt_ip, dict):
              reputation_table.append(["VT IP", colorize_value(f"Error: {vt_ip.get('error', 'Unknown VT IP Error')}", 1)])
         else:
               reputation_table.append(["VT IP", colorize_value(f"Error: Unexpected VT IP result format", 1)])


    # AbuseIPDB
    if sender_ip and sender_ip != "Not found" and 'abuseipdb' in results:
        abuseipdb = results['abuseipdb']
        if isinstance(abuseipdb, dict) and 'error' not in abuseipdb:
            abuse_score = abuseipdb.get('abuseConfidenceScore', 0)
            reports = abuseipdb.get('totalReports', 0)
            country = abuseipdb.get('countryCode', 'N/A')
            isp = abuseipdb.get('isp', 'N/A')
            # Colorize score based on thresholds used in scoring
            score_color = colorize_value(abuse_score, 40) # Yellow >= 40, Red >= 75 (approx)
            reputation_table.append(["AbuseIPDB", f"Score: {score_color}, Reports: {colorize_value(reports, 10)}, Country: {country}, ISP: {isp[:30]}"])
        elif isinstance(abuseipdb, dict):
             reputation_table.append(["AbuseIPDB", colorize_value(f"Error: {abuseipdb.get('error', 'Unknown AbuseIPDB Error')}", 1)])
        else:
             reputation_table.append(["AbuseIPDB", colorize_value(f"Error: Unexpected AbuseIPDB result format", 1)])


    if reputation_table:
        print(f"\n{GREEN}--- SENDER REPUTATION ---{END}")
        # Use the aliased function name here
        print(tabulate_func(reputation_table, headers=["Source", "Details"], tablefmt="pretty"))

    # --- URL Analysis ---
    if url_results:
        print(f"\n{GREEN}--- URL ANALYSIS (Top {len(url_results)}) ---{END}")
        url_table_data = []
        headers = ["#", "URL (Truncated)", "Domain", "Verdict", "Score", "Key Reasons"]
        for i, url_result in enumerate(url_results, 1):
             # Check if url_result is a dictionary before processing
             if isinstance(url_result, dict):
                 url = url_result.get('url', 'N/A')
                 domain = url_result.get('domain', 'N/A')
                 score = url_result.get('score', 0)
                 url_verdict = url_result.get('verdict', 'Unknown')
                 reasons = url_result.get('reasons', [])

                 # Truncate long URLs for display
                 display_url = url[:70] + '...' if len(url) > 70 else url
                 # Format reasons nicely
                 key_reasons_str = ', '.join(r.split(' (Score')[0] for r in reasons[:2]) # Show top 2 reasons without score details

                 url_table_data.append([
                     i,
                     display_url,
                     domain,
                     colorize_value(url_verdict),
                     colorize_value(score, 2.5), # Threshold for coloring score (Potentially Suspicious)
                     key_reasons_str
                 ])
             else:
                  logger.warning(f"Skipping invalid item in url_results during report generation: {url_result}")
                  url_table_data.append([i, f"{RED}Error processing URL result{END}", "N/A", "Error", "N/A", "N/A"])

        # Use the aliased function name here
        if url_table_data: # Only print table if there's data
             print(tabulate_func(url_table_data, headers=headers, tablefmt="pretty"))
        else:
             print("  No valid URL analysis results to display.")

    else:
        print(f"\n{GREEN}--- URL ANALYSIS ---{END}")
        print("  No URLs found or analyzed in the email body.")


    # --- Attachment Analysis ---
    if attachments:
        print(f"\n{GREEN}--- ATTACHMENTS ({len(attachments)}) ---{END}")
        attachment_table = []
        headers = ["#", "Filename", "Type", "Size (Bytes)", "Status"]
        for i, attachment in enumerate(attachments, 1):
            filename = attachment.get('filename', 'Unknown')
            size = attachment.get('size', 0)
            content_type = attachment.get('content_type', 'Unknown')
            is_suspicious = attachment.get('suspicious', False)
            is_high_risk = attachment.get('high_risk', False)

            status = f"{RED}[HIGH RISK]{END}" if is_high_risk else (f"{YELLOW}[Suspicious]{END}" if is_suspicious else f"{GREEN}[OK]{END}")
            # Truncate long filenames
            display_filename = filename[:45] + '...' if len(filename) > 45 else filename
            attachment_table.append([i, display_filename, content_type, size, status])
        # Use the aliased function name here
        print(tabulate_func(attachment_table, headers=headers, tablefmt="pretty"))


    # --- Content Analysis ---
    print(f"\n{GREEN}--- CONTENT ANALYSIS ---{END}")
    content_indicators = content_analysis.get('indicators', [])
    content_score = content_analysis.get('score', 0)
    if content_indicators:
        print(f"  {YELLOW}Suspicious content indicators found (Score contribution: {content_score:.2f}):{END}")
        for indicator in content_indicators[:5]: # Show top 5 indicators
            print(f"  - {indicator}")
        if len(content_indicators) > 5: print("  - ...")
    else:
        print(f"  {GREEN}No major suspicious content indicators found (Score contribution: {content_score:.2f}){END}")


    # --- Final Verdict ---
    print("\n" + "="*80)
    print(f"{GREEN}--- FINAL ASSESSMENT ---{END}")
    # Color score based on verdict thresholds
    score_color = GREEN
    if verdict == "Phishing": score_color = RED
    elif verdict == "Highly Suspicious": score_color = RED
    elif verdict == "Suspicious": score_color = YELLOW
    elif verdict == "Likely Legitimate": score_color = YELLOW # Color this slightly too

    print(f"  {GREEN}Overall Phishing Score:{END} {score_color}{phishing_score:.2f}{END} / 10.0")

    if score_reasons:
         # Show top 3-4 reasons without the score details for cleaner output
         display_reasons = [r.split(' (Score')[0] for r in score_reasons[:4]]
         print(f"  {YELLOW}Key Factors:{END} {', '.join(display_reasons)}{'...' if len(score_reasons) > 4 else ''}")

    verdict_color = GREEN
    if verdict in ["Suspicious", "Highly Suspicious"]:
        verdict_color = YELLOW
    elif verdict == "Phishing":
        verdict_color = RED

    print(f"  {GREEN}Verdict:{END} {verdict_color}{verdict}{END}")
    print("="*80 + "\n")


# --- Main Analysis Logic ---

def analyze_email(file_path):
    """Orchestrates the analysis of a single email file."""
    # 1. Input Validation
    if not os.path.isfile(file_path):
        print(f"{RED}Error: Email file not found at '{file_path}'.{END}")
        logger.error(f"Email file not found: {file_path}")
        return None # Return None to indicate failure

    start_time = time.time()
    print(f"\n{GREEN}[+] Analyzing email file: {os.path.basename(file_path)}{END}")

    # 2. Read Email
    msg = read_email_file(file_path)
    if not msg:
        print(f"{RED}Error: Failed to read or parse email file.{END}")
        return None

    # 3. Initial Extraction
    print(f"{GREEN}[+] Extracting headers, URLs, and attachments...{END}")
    email_details = extract_basic_email_details(msg)
    urls = extract_urls_from_email(msg) # Now filters cid: links
    attachments = extract_attachments_from_email(msg)
    plain_text, html_content = extract_email_content(msg) # Extract both

    sender_domain = email_details.get('sender_domain')
    sender_ip = email_details.get('sender_ip')

    # Log basic details
    logger.info(f"Analyzing email: Subject='{email_details.get('subject', '')}', From='{email_details.get('sender_email', 'N/A')}', IP='{sender_ip}'")
    logger.info(f"Found {len(urls)} URLs (after filtering) and {len(attachments)} attachments.")

    # 4. Concurrent Analysis
    print(f"{GREEN}[+] Performing authentication, reputation, and content checks...{END}")
    results = {}
    url_results = []
    # Cache for domain/IP checks within this email context - use lowercase keys
    analyzed_domains_cache = {}

    auth_checker = EmailAuthenticationChecker()
    is_whitelisted = sender_domain in WHITELISTED_SENDERS if sender_domain else False
    if is_whitelisted:
         print(f"{YELLOW}[!] Sender domain '{sender_domain}' is whitelisted.{END}")

    with ThreadPoolExecutor(max_workers=10) as executor: # Increased workers for potentially many tasks
        futures = {}

        # --- Submit Core Email Checks ---
        futures['spf'] = executor.submit(auth_checker.check_spf, sender_domain, sender_ip)
        futures['dkim'] = executor.submit(auth_checker.check_dkim, msg) # Pass the full message object
        futures['dmarc'] = executor.submit(auth_checker.check_dmarc, sender_domain)
        futures['content'] = executor.submit(check_content_for_phishing_indicators, plain_text, html_content)
        futures['auth_alignment'] = executor.submit(auth_checker.check_authentication_alignment, msg, sender_domain)

        # --- Submit Sender Reputation Checks (if not whitelisted and data available) ---
        sender_rep_cache_key = None
        if not is_whitelisted:
            # Use lowercase domain/ip for cache key consistency
            lc_sender_domain = sender_domain.lower() if sender_domain else None
            lc_sender_ip = sender_ip.lower() if sender_ip and sender_ip != "Not found" else None

            if lc_sender_domain:
                sender_rep_cache_key = f"domain_{lc_sender_domain}"
                futures['vt_domain'] = executor.submit(check_virustotal_domain, lc_sender_domain)
                futures['whois'] = executor.submit(get_whois_info, lc_sender_domain)

            if lc_sender_ip:
                 # If domain check is happening, use its cache key, else use IP
                 if not sender_rep_cache_key: sender_rep_cache_key = f"ip_{lc_sender_ip}"
                 futures['vt_ip'] = executor.submit(check_virustotal_ip, lc_sender_ip)
                 futures['abuseipdb'] = executor.submit(check_abuseipdb, lc_sender_ip)

        # --- Submit URL Analysis Checks (limit number of URLs analyzed) ---
        url_limit = 5 # Analyze top 5 URLs
        url_futures = {}
        # Analyze unique URLs up to limit (already filtered in extract_urls_from_email)
        unique_urls_to_analyze = list(set(urls))[:url_limit]
        print(f"{GREEN}[+] Submitting {len(unique_urls_to_analyze)} unique URLs for analysis...{END}")
        for i, url in enumerate(unique_urls_to_analyze):
            # Pass the shared domain cache to avoid redundant checks
            url_futures[f'url_{i}'] = executor.submit(analyze_url, url, analyzed_domains_cache)

        # --- Collect Core Results ---
        core_keys = ['spf', 'dkim', 'dmarc', 'content', 'auth_alignment', 'vt_domain', 'whois', 'vt_ip', 'abuseipdb']
        for key in core_keys:
             if key in futures:
                 try:
                     results[key] = futures[key].result()
                     # If sender rep was checked, store results in the shared cache
                     # Ensure cache key exists before trying to store
                     if sender_rep_cache_key and key in ['vt_domain', 'whois', 'vt_ip', 'abuseipdb']:
                          if sender_rep_cache_key not in analyzed_domains_cache:
                               analyzed_domains_cache[sender_rep_cache_key] = {}
                          # Store only non-error results in the shared cache
                          if isinstance(results[key], dict) and 'error' not in results[key]:
                               analyzed_domains_cache[sender_rep_cache_key][key] = results[key]

                 except Exception as e:
                     logger.error(f"Error getting result for {key}: {e}", exc_info=True)
                     results[key] = {"error": f"Future execution error: {str(e)}"}

        # --- Collect URL Results ---
        print(f"{GREEN}[+] Collecting URL analysis results...{END}")
        for key, future in url_futures.items():
            try:
                url_analysis = future.result()
                # Ensure result is a dict before adding (handles potential None returns on error)
                if isinstance(url_analysis, dict) and 'error' not in url_analysis:
                     url_results.append(url_analysis)
                elif isinstance(url_analysis, dict): # Log URL analysis errors
                     logger.warning(f"URL analysis failed for {url_analysis.get('url', key)}: {url_analysis.get('error')}")
                elif url_analysis is not None: # Log unexpected non-dict results
                     logger.warning(f"URL analysis future {key} returned unexpected type: {type(url_analysis)}")
            except Exception as e:
                # Log exceptions raised during future.result() itself
                logger.error(f"Error getting result for URL future {key}: {e}", exc_info=True)


    # Sort URL results by score (highest first)
    # Ensure sorting handles potential non-dict items gracefully if error handling above fails
    url_results.sort(key=lambda x: x.get('score', 0) if isinstance(x, dict) else 0, reverse=True)


    # 5. Calculate Final Score and Verdict
    print(f"{GREEN}[+] Calculating final score...{END}")
    auth_alignment_result = results.get('auth_alignment', {'aligned': True}) # Default to aligned if check failed
    content_analysis_result = results.get('content', {'score': 0, 'indicators': [], 'suspicious': False})

    phishing_score, score_reasons = calculate_email_phishing_score(
        email_details, results, url_results, attachments, content_analysis_result, auth_alignment_result, is_whitelisted
    )
    verdict = get_email_verdict(phishing_score)

    # 6. Display Report
    display_email_analysis_report(
        email_details, results, url_results, attachments, content_analysis_result, auth_alignment_result, phishing_score, score_reasons, verdict
    )

    end_time = time.time()
    logger.info(f"Email analysis completed for {os.path.basename(file_path)} in {end_time - start_time:.2f} seconds. Score: {phishing_score:.2f}, Verdict: {verdict}")


    # Return a summary dictionary (optional)
    return {
        "file": file_path,
        "subject": email_details.get('subject'),
        "sender": email_details.get('sender_email'),
        "score": phishing_score,
        "verdict": verdict,
        "urls_analyzed": len(url_results),
        "attachments_found": len(attachments)
    }


# --- Email Authentication Class ---

class EmailAuthenticationChecker:
    """Handles SPF, DKIM, and DMARC checks."""
    def __init__(self, timeout=5):
        # Configure DNS resolver with timeout
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = timeout
        self.dns_resolver.lifetime = timeout
        # Optional: Specify nameservers if needed
        # self.dns_resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    def _query_dns(self, domain, record_type):
        """Helper to query DNS with error handling."""
        try:
            # Use resolve method which handles CNAMEs automatically
            answer = self.dns_resolver.resolve(domain, record_type, raise_on_no_answer=False)
            # Check if the answer object itself is None or has an empty rrset
            if answer is None or not answer.rrset:
                 logger.debug(f"DNS NoAnswer/NXDOMAIN for {domain} ({record_type})")
                 return None # Consistent return for NoAnswer/NXDOMAIN
            return answer # Return the answer object
        except dns.resolver.NXDOMAIN:
            logger.debug(f"DNS NXDOMAIN exception for {domain} ({record_type})")
            return None
        except dns.resolver.Timeout:
            logger.warning(f"DNS query timeout for {domain} ({record_type})")
            return "Timeout"
        except dns.exception.DNSException as e:
            logger.error(f"DNS query error for {domain} ({record_type}): {e}")
            # Return specific error type if helpful
            return f"Error ({type(e).__name__})"

    def check_spf(self, sender_domain, sender_ip):
        """Checks SPF record for the sender domain against the sender IP."""
        # Note: Proper SPF evaluation is complex (includes, redirects, macros).
        # This is a simplified check focusing on basic mechanisms and '-all'.
        # Consider using a dedicated SPF library (like 'pyspf', 'spf-engine') for full validation.
        if not sender_domain: return "Not checked (No domain)"
        if not sender_ip or sender_ip == "Not found" or not is_ip_address(sender_ip):
            return "Not checked (No valid IP)"

        spf_query_domain = sender_domain
        result = self._query_dns(spf_query_domain, 'TXT')

        if isinstance(result, str): return result # Return Timeout or Error string
        if result is None: return "No SPF record" # NXDOMAIN or NoAnswer

        spf_record = None
        for record in result.rrset:
            # TXT records can be split; join them
            record_text = b"".join(record.strings).decode('utf-8', errors='replace').strip('"')
            if record_text.lower().startswith('v=spf1'):
                spf_record = record_text
                logger.debug(f"Found SPF record for {sender_domain}: {spf_record}")
                break

        if not spf_record: return "No SPF record"

        # Basic checks (not a full SPF evaluation)
        spf_parts = spf_record.lower().split()
        try:
             ip_obj = ipaddress.ip_address(sender_ip)
        except ValueError:
             logger.error(f"Invalid sender IP format for SPF check: {sender_ip}")
             return "Error (Invalid IP)"


        # Check mechanisms (simplified) - focus on direct IP match and 'all' mechanism
        verdict = "Neutral" # Default if no mechanism matches strongly
        matched_mechanism = False

        for part in spf_parts:
             qualifier = '+' # Default qualifier
             if part.startswith(('-', '~', '?')):
                  qualifier = part[0]
                  mechanism = part[1:]
             elif part.startswith('+'):
                  qualifier = '+'
                  mechanism = part[1:]
             else:
                  mechanism = part

             # Check ip4/ip6 first
             if mechanism.startswith(('ip4:', 'ip6:')):
                  try:
                       network_str = mechanism.split(':', 1)[1]
                       network = ipaddress.ip_network(network_str, strict=False)
                       if ip_obj in network:
                            if qualifier == '+': verdict = "Pass"
                            elif qualifier == '-': verdict = "Fail"
                            elif qualifier == '~': verdict = "SoftFail"
                            elif qualifier == '?': verdict = "Neutral"
                            matched_mechanism = True
                            break # Found matching IP mechanism
                  except ValueError: continue # Ignore invalid network strings
             # Check 'all' mechanism (processed last if no IP match)
             elif mechanism == 'all':
                  # If we haven't matched an IP mechanism yet, 'all' determines the fallback
                  if not matched_mechanism:
                       if qualifier == '+': verdict = "Pass (Permissive +all)"
                       elif qualifier == '-': verdict = "Fail (Fallback -all)"
                       elif qualifier == '~': verdict = "SoftFail (Fallback ~all)"
                       elif qualifier == '?': verdict = "Neutral (Fallback ?all)"
                  # Don't break here, let specific IP matches override 'all' if they appear later

        logger.info(f"Simplified SPF check result for {sender_domain}/{sender_ip}: {verdict}")
        return verdict


    def check_dkim(self, msg):
        """Checks DKIM signature using Authentication-Results or DKIM-Signature header."""
        # Note: Full DKIM verification requires crypto checks and DNS lookups.
        # This check primarily relies on the MTA's Authentication-Results header.
        # Consider using a library like 'dkimpy' or 'authres' for full verification.

        auth_results_header = msg.get("Authentication-Results", "") or msg.get("X-Authentication-Results", "") # Check common variations
        dkim_status = "Not checked"

        if auth_results_header:
            # Look for dkim=pass/fail/etc. in the header (case-insensitive)
            # Handle potential multiple dkim results (e.g., ARC) - take the first? Or most strict?
            # Simple approach: find first dkim= result
            dkim_match = re.search(r'dkim\s*=\s*([a-z]+)', str(auth_results_header).lower())
            if dkim_match:
                status = dkim_match.group(1)
                if status == 'pass':
                    dkim_status = "Pass"
                elif status in ['fail', 'permerror', 'temperror']:
                    dkim_status = "Fail"
                elif status == 'none':
                    dkim_status = "None" # Explicitly no signature found/checked by MTA
                elif status == 'neutral':
                     dkim_status = "Neutral" # Signature present but unverifiable policy/key issues
                # Other statuses like 'policy', 'hardfail' might exist
                logger.info(f"DKIM status from Authentication-Results: {dkim_status} (raw status: {status})")
                return dkim_status
            else:
                 logger.debug("DKIM status keyword not found in Authentication-Results header.")

        # Fallback: Check if a DKIM-Signature header exists (doesn't verify it)
        if "DKIM-Signature" in msg:
            logger.info("DKIM-Signature header found, but verification relies on Authentication-Results or external library.")
            # Return a status indicating presence but lack of verification from Auth-Results
            return "Header present (No Auth-Results)"

        logger.info("No DKIM information found in headers.")
        return "No DKIM info" # Neither Auth-Results nor DKIM-Signature found

    def check_dmarc(self, sender_domain):
        """Checks for a DMARC record and its policy (p=)."""
        if not sender_domain:
            return "Not checked (No domain)"

        dmarc_query_domain = f"_dmarc.{sender_domain}"
        result = self._query_dns(dmarc_query_domain, 'TXT')

        if isinstance(result, str): return result # Timeout or Error string
        if result is None: return "No DMARC record" # NXDOMAIN or NoAnswer

        dmarc_record = None
        for record in result.rrset:
            # Join potentially split TXT record strings
            record_text = b"".join(record.strings).decode('utf-8', errors='replace').strip('"')
            if record_text.lower().startswith('v=dmarc1'):
                dmarc_record = record_text
                logger.debug(f"Found DMARC record for {sender_domain}: {dmarc_record}")
                break

        if not dmarc_record: return "No DMARC record"

        # Extract policy (p=) - case insensitive search
        policy_match = re.search(r'p\s*=\s*(\w+)', dmarc_record, re.IGNORECASE)
        policy = "none" # Default DMARC policy if 'p=' tag is missing (per RFC)
        if policy_match:
            policy = policy_match.group(1).lower() # Use lowercase policy value

        if policy == 'reject':
            return "Pass (p=reject)"
        elif policy == 'quarantine':
            return "Pass (p=quarantine)"
        else: # policy == 'none' or invalid/missing
            # Log if policy is explicitly none vs missing/invalid?
            return "Pass (p=none)"


    def check_authentication_alignment(self, msg, sender_domain):
        """Checks if DKIM or SPF domains align with the From: domain."""
        # Ensure sender_domain is lowercase for comparisons
        from_domain_lower = sender_domain.lower() if sender_domain else None

        alignment = {
            "from_domain": from_domain_lower,
            "dkim_domain": None,
            "spf_domain": None,
            "aligned": True # Default to aligned if checks fail or aren't applicable
        }
        if not from_domain_lower:
             logger.debug("Cannot check alignment: No From domain provided.")
             return alignment # Cannot check alignment

        # Use lowercased header for case-insensitive matching
        auth_results_header = str(msg.get("Authentication-Results", "") or msg.get("X-Authentication-Results", "")).lower()
        dkim_aligned = False
        spf_aligned = False
        dkim_result_found = False
        spf_result_found = False


        # Extract DKIM domain (header.d=) if DKIM passed
        # Handle multiple DKIM results potentially? For now, find first pass.
        dkim_pass_match = re.search(r'dkim=pass(?:\s|\().*?header\.d=([a-z0-9.\-]+)', auth_results_header)
        if dkim_pass_match:
            dkim_result_found = True
            alignment["dkim_domain"] = dkim_pass_match.group(1) # Already lowercase due to header processing
            # Check alignment (exact match or subdomain) - relaxed alignment
            if alignment["dkim_domain"] == from_domain_lower or \
               alignment["dkim_domain"].endswith('.' + from_domain_lower):
                dkim_aligned = True

        # Extract SPF domain (smtp.mailfrom= or header.from=) if SPF passed
        # Handle multiple SPF results? Find first pass.
        spf_pass_match = re.search(r'spf=pass(?:\s|\().*?(?:smtp\.mailfrom=|header\.from=)(?:.*?@)?([a-z0-9.\-]+)', auth_results_header)
        if spf_pass_match:
            spf_result_found = True
            alignment["spf_domain"] = spf_pass_match.group(1) # Already lowercase
            # Check alignment - relaxed alignment
            if alignment["spf_domain"] == from_domain_lower or \
               alignment["spf_domain"].endswith('.' + from_domain_lower):
                spf_aligned = True

        # Determine overall alignment based on DMARC identifier alignment rules (RFC 7489 Sec 3.1)
        # Alignment passes if *either* DKIM or SPF aligns.
        # Alignment fails if *at least one* check passed but *neither* aligned.
        # Alignment is indeterminate (treat as pass/aligned here) if neither check passed.

        if (dkim_result_found and not dkim_aligned) and (spf_result_found and not spf_aligned):
             # If both checks happened, passed, but neither aligned -> Misaligned
             alignment["aligned"] = False
        elif (dkim_result_found and not dkim_aligned) and not spf_result_found:
             # If only DKIM passed and it misaligned -> Misaligned
             alignment["aligned"] = False
        elif (spf_result_found and not spf_aligned) and not dkim_result_found:
             # If only SPF passed and it misaligned -> Misaligned
             alignment["aligned"] = False
        elif dkim_aligned or spf_aligned:
             # If at least one passed and aligned -> Aligned
             alignment["aligned"] = True
        else:
             # If neither check resulted in a 'pass' in Auth-Results -> Indeterminate (treat as aligned)
             alignment["aligned"] = True


        logger.info(f"Auth Alignment Check: From={alignment['from_domain']}, DKIM_Dom={alignment['dkim_domain']}, SPF_Dom={alignment['spf_domain']}, DKIM_Align={dkim_aligned}, SPF_Align={spf_aligned}, Overall_Aligned={alignment['aligned']}")
        return alignment


# --- Main Execution ---

def main():
    """Main function to handle user interaction and initiate analysis."""
    runPEnv()
    print(f"Welcome to Phishi Detector!")
    # Reminder about dependencies
    print(f"{YELLOW}Note:{END} Ensure required libraries are installed (requests, beautifulsoup4, dnspython, python-whois, tabulate, html5lib).")
    print(f"{YELLOW}Tip:{END} Create a 'requirements.txt' file and run 'pip install -r requirements.txt'.")
    # Reminder about API Keys
    if missing_keys:
         print(f"{RED}Warning:{END} Set missing API keys as environment variables: {', '.join(missing_keys)}")


    while True:
        print("\nChoose an option:")
        print("  1. Analyze Email File (.eml)")
        print("  2. Analyze Single URL")
        # Add batch analysis option later if needed
        # print("  3. Batch Analyze Emails in Directory")
        print("  Q. Quit")
        choice = input("Enter your choice (1, 2, or Q): ").strip().upper()

        if choice == '1':
            file_path = input("Enter the path to the email file (.eml): ").strip()
            # Remove quotes if present (e.g., drag-and-drop on Windows/Mac)
            file_path = file_path.strip('"\'')
            analyze_email(file_path) # analyze_email handles file not found

        elif choice == '2':
            url_input = input("Enter the URL to analyze: ").strip()
            if not url_input:
                print(f"{RED}Error: No URL entered.{END}")
                continue

            # Basic check if it looks like a URL before analyzing
            # Allow URLs without scheme, add http:// by default in analyze_url
            if '.' not in url_input and not is_ip_address(url_input):
                 print(f"{RED}Error: Input does not look like a valid URL or IP address.{END}")
                 continue

            print(f"\n{GREEN}[+] Analyzing URL: {url_input}{END}")
            url_analysis_result = analyze_url(url_input)

            # Display URL analysis results
            if url_analysis_result and isinstance(url_analysis_result, dict) and 'error' not in url_analysis_result:
                print("\n" + "="*80)
                print(f"{GREEN}       URL ANALYSIS REPORT       {END}".center(80))
                print("="*80)
                url_report_table = [
                    ["URL", url_analysis_result.get('url')],
                    ["Domain", url_analysis_result.get('domain')],
                    ["Score", f"{colorize_value(url_analysis_result.get('score', 0), 2.5)} / 10.0"], # Color based on Potentially Suspicious threshold
                    ["Verdict", colorize_value(url_analysis_result.get('verdict', 'Error'))],
                    # Show top 3-4 reasons without score details for cleaner output
                    ["Key Factors", ', '.join([r.split(' (Score')[0] for r in url_analysis_result.get('reasons', ['N/A'])[:4]])]
                ]
                # Add features and API results if needed for more detail
                # features = url_analysis_result.get('features', {})
                # api_res = url_analysis_result.get('api_results', {})
                # ... add more rows to table ...

                # Use the aliased function name here
                print(tabulate_func(url_report_table, tablefmt="pretty"))
                print("="*80 + "\n")

            elif url_analysis_result and isinstance(url_analysis_result, dict):
                print(f"{RED}Error analyzing URL: {url_analysis_result.get('error')}{END}")
            else:
                 print(f"{RED}Error: URL analysis returned no result or an unexpected format.{END}")

        elif choice == 'Q':
            print("Exiting Phishi Detector. Stay safe!")
            break
        else:
            print(f"{RED}Invalid choice. Please enter 1, 2, or Q.{END}")

if __name__ == "__main__":
    # --- Dependency Check (Optional but Recommended) ---
    try:
        import requests
        import bs4
        import dns.resolver
        import whois
        # Use the aliased function name here for the check if needed, though not strictly necessary
        # from tabulate import tabulate as tabulate_func
        import tabulate # Check if module exists
        import html5lib # Added dependency for better HTML parsing
    except ImportError as e:
        print(f"{RED}Error: Missing required library: {e.name}{END}")
        print("Please install requirements: pip install requests beautifulsoup4 dnspython python-whois tabulate html5lib")
        exit(1)

    # Import timedelta here after checks (already imported globally)
    # from datetime import timedelta

    main()
