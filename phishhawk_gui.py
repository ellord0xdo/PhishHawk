"""
PhishHawk GUI – Advanced Phishing Analysis Tool
Author: Ebrahim Aref – Cyber Security Engineer @ Sunrun

A Python-based GUI for scanning emails and URLs to detect potential phishing threats.
"""
import sys
import os
import re
import requests
import logging
import hashlib
import time
import json
import base64
import ipaddress
import math # For entropy calculation
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from bs4 import BeautifulSoup
from tabulate import tabulate as tabulate_func # Keep for potential future use if needed, but GUI uses tables

# --- PyQt5 Imports ---
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog, QTextEdit,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QMessageBox, QSpacerItem, QSizePolicy, QScrollArea,
    QStyleFactory # Import QStyleFactory
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, pyqtSlot
from PyQt5.QtGui import QFont, QColor, QPalette # Import QPalette for dark theme base

# --- Import backend logic components ---
# (Assuming the original script's functions are available or adapted below)
# It's better practice to have the backend logic in separate modules,
# but for this example, we'll integrate necessary functions/classes directly
# or adapt them.

# --- Configuration (Copied and adapted from original script) ---

# Configure logging (Consider logging to a file and maybe a GUI element)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='phishhawk_gui.log' # Log GUI activity separately
)
logger = logging.getLogger('phishhawk_gui')

# Color codes for terminal output (Not directly used in GUI, but kept for reference)
RED, GREEN, YELLOW, END = '\033[91m', '\033[1;32m', '\033[93m', '\033[0m'

# --- API Key Management (IMPORTANT SECURITY WARNING) ---
# WARNING: Hardcoding API keys is insecure. Use environment variables,
# a configuration file, or a secure key management system in production.
# These keys are copied from the original script for demonstration purposes ONLY.
VIRUSTOTAL_API_KEY = "" # Replace with your actual key or load securely
ABUSEIPDB_API_KEY = "" # Replace with your actual key or load securely
GOOGLE_SAFE_BROWSING_API_KEY = "" # Replace with your actual key or load securely
IPQS_API_KEY = "" # Replace with your actual key or load securely

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
    # Consider showing a warning in the GUI status bar or a popup

# Whitelists (Copied from original script)
WHITELISTED_SENDERS = ["linkedin.com", "google.com", "microsoft.com", "medium.com"]
WHITELISTED_URLS = ["linkedin.com", "google.com", "microsoft.com", "medium.com", "docs.google.com"]

# Common phishing keywords (Copied from original script)
PHISHING_KEYWORDS = [
    'account', 'alert', 'authenticate', 'bank', 'click', 'confirm', 'credit',
    'debit', 'expire', 'login', 'password', 'pay', 'purchase', 'secure',
    'update', 'urgent', 'verify', 'wallet', 'warning', 'unusual', 'activity',
    'action required', 'suspended', 'locked', 'compromised', 'identity'
]

# Cache directory (Copied from original script)
CACHE_DIR = os.path.join(os.getcwd(), '.cache')
os.makedirs(CACHE_DIR, exist_ok=True)

# --- Backend Logic (Adapted Functions from Original Script) ---
# It's highly recommended to refactor the original script into classes and functions
# that return data rather than print. Here, we'll include adapted versions or placeholders.

# --- Helper Functions (Adapted) ---

def get_cache_path(request_type, key):
    """Generates a cache file path based on request type and key using SHA256."""
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

def save_to_cache(request_type, key, data, max_age=None):
    """Saves data to the cache. Allows specifying max_age for error caching."""
    cache_path = get_cache_path(request_type, key)
    try:
        payload = {'timestamp': time.time(), 'data': data}
        with open(cache_path, 'w') as f:
            json.dump(payload, f)
        logger.info(f"Saved to cache for {request_type}: {key[:20]}...")
    except IOError as e:
         logger.error(f"Cache file write error for {cache_path}: {e}")
    except Exception as e:
        logger.error(f"Cache write error for {cache_path}: {e}")

def api_request(url, method='get', headers=None, params=None, data=None, json_data=None, timeout=20):
    """Makes an API request with improved error handling."""
    # (Keep the original api_request function implementation here)
    try:
        if method.lower() == 'get':
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
        elif method.lower() == 'post':
            response = requests.post(url, headers=headers, params=params, data=data, json=json_data, timeout=timeout)
        else:
            logger.error(f"Unsupported HTTP method: {method}")
            return {"error": f"Unsupported HTTP method: {method}"}

        response.raise_for_status()

        if response.status_code == 204:
            return {}
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
        status_code = response.status_code if 'response' in locals() else 'N/A'
        reason = response.reason if 'response' in locals() else 'N/A'
        text = response.text[:200] if 'response' in locals() else 'N/A'
        logger.warning(f"API HTTP error for {url}: {status_code} {reason}. Response: {text}")
        return {"error": f"HTTP {status_code} {reason}", "status_code": status_code}
    except requests.exceptions.RequestException as e:
        logger.error(f"API request error for {url}: {e}")
        return {"error": f"Request error: {e}"}
    except json.JSONDecodeError as e:
        text = response.text[:200] if 'response' in locals() else 'N/A'
        logger.error(f"API JSON decode error for {url}. Response: {text}")
        return {"error": f"JSON decode error: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected API request error for {url}: {e}")
        return {"error": f"Unexpected error: {str(e)}"}

# --- Reputation Check Functions (Adapted) ---
# (Keep the original implementations of check_virustotal, check_virustotal_domain,
# check_virustotal_url, check_virustotal_ip, get_whois_info, check_google_safe_browsing,
# check_ipqs, check_abuseipdb here)
# --- Placeholder implementations for brevity in this example ---
def check_virustotal(api_type, identifier):
    """Generic function to check VirusTotal for domain, IP, or URL."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    cache_key = identifier
    request_identifier = identifier

    if api_type == 'urls':
        cache_key = hashlib.sha256(identifier.encode()).hexdigest()
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

    if result.get("error"):
        status_code = result.get("status_code")
        if status_code == 404:
            logger.info(f"VirusTotal: Resource not found for {api_type} {identifier[:30]}...")
            not_found_data = {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0}, "not_found": True}
            save_to_cache(f'vt_{api_type}', cache_key, not_found_data)
            return not_found_data
        elif status_code in [400, 429]:
             logger.warning(f"VirusTotal API error {status_code} for {api_type} {identifier[:30]}. Error: {result.get('error')}")
             save_to_cache(f'vt_{api_type}', cache_key, result, max_age=300 if status_code == 400 else 900)
             return result
        else:
             logger.warning(f"VirusTotal API error for {api_type} {identifier[:30]}: {result.get('error')}")
             save_to_cache(f'vt_{api_type}', cache_key, result, max_age=300)
             return result

    if 'data' in result:
        data = result.get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        relevant_data = {
            "last_analysis_stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            },
             "reputation": data.get("reputation"),
             "last_analysis_date": data.get("last_analysis_date"),
             "total_votes": data.get("total_votes"),
             "whois": data.get("whois")
        }
        save_to_cache(f'vt_{api_type}', cache_key, relevant_data)
        return relevant_data
    else:
         logger.warning(f"VirusTotal returned 200 OK but no 'data' field for {api_type} {identifier[:30]}. Response: {result}")
         no_data_error = {"error": "API returned OK but no data field"}
         save_to_cache(f'vt_{api_type}', cache_key, no_data_error, max_age=300)
         return no_data_error

def check_virustotal_domain(domain): return check_virustotal('domains', domain)
def check_virustotal_url(url_to_check): return check_virustotal('urls', url_to_check)
def check_virustotal_ip(ip_address): return check_virustotal('ip_addresses', ip_address)

# --- Need full implementations of: ---
# get_whois_info(domain)
# check_google_safe_browsing(url_to_check)
# check_ipqs(url_to_check)
# check_abuseipdb(ip_address)
# --- Placeholder implementations ---
def get_whois_info(domain):
    # Replace with actual implementation from original script
    # Ensure you have 'python-whois' installed and handle potential errors
    try:
        import whois
        logger.info(f"Performing WHOIS lookup for: {domain}")
        # Add timeout handling if possible with the library or via socket default timeout
        domain_info = whois.whois(domain)

        if not domain_info or not hasattr(domain_info, 'creation_date'):
             logger.warning(f"WHOIS lookup returned incomplete data for {domain}")
             # Return specific error if creation date is crucial and missing
             if not hasattr(domain_info, 'creation_date') or not domain_info.creation_date:
                  return {"error": "Incomplete WHOIS data (Missing creation date)"}

        result = {
            "creation_date": None, "expiration_date": None, "updated_date": None,
            "organization": getattr(domain_info, 'org', None),
            "registrar": getattr(domain_info, 'registrar', None),
            "status": getattr(domain_info, 'status', None),
            "name_servers": getattr(domain_info, 'name_servers', []),
            "emails": getattr(domain_info, 'emails', [])
        }

        def format_whois_date(date_field):
             # (Keep the date formatting logic from the previous version)
             if not date_field: return None
             date_val = date_field[0] if isinstance(date_field, list) else date_field
             if isinstance(date_val, datetime):
                 if date_val.tzinfo is None: date_val = date_val.replace(tzinfo=timezone.utc)
                 try:
                     if date_val.year < 1900 or date_val.year > datetime.now(timezone.utc).year + 10: raise ValueError("Year out of range")
                     return date_val.isoformat()
                 except ValueError: return str(date_val) # Fallback
             elif date_val:
                 try:
                     dt_obj = datetime.fromisoformat(str(date_val).replace('Z', '+00:00'))
                     if dt_obj.tzinfo is None: dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                     if dt_obj.year < 1900 or dt_obj.year > datetime.now(timezone.utc).year + 10: raise ValueError("Parsed year out of range")
                     return dt_obj.isoformat()
                 except ValueError: return str(date_val) # Fallback
             return None

        result["creation_date"] = format_whois_date(domain_info.creation_date)
        result["expiration_date"] = format_whois_date(domain_info.expiration_date)
        result["updated_date"] = format_whois_date(domain_info.updated_date)

        # Cache successful result
        # save_to_cache('whois', domain, result) # Consider caching strategy
        return result

    except ImportError:
         logger.error("WHOIS check failed: 'python-whois' library not installed or importable.")
         return {"error": "WHOIS library not available"}
    except Exception as e: # Catch potential whois library errors or timeouts
        logger.error(f"WHOIS lookup error for {domain}: {e}", exc_info=True)
        # Cache error briefly
        # save_to_cache('whois', domain, {"error": f"WHOIS lookup error: {str(e)}"}, max_age=300)
        return {"error": f"WHOIS lookup error: {str(e)}"}


def check_google_safe_browsing(url_to_check):
    # Replace with actual implementation from original script
    logger.info(f"GSB check placeholder for {url_to_check}")
    time.sleep(0.1)
    if not GOOGLE_SAFE_BROWSING_API_KEY: return {"error": "Google Safe Browsing API key not configured"}
    if "phishing-site.com" in url_to_check:
        return [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM"}]
    if "error-gsb" in url_to_check:
        return {"error": "Simulated GSB API error"}
    return [] # No matches

def check_ipqs(url_to_check):
    # Replace with actual implementation from original script
    logger.info(f"IPQS check placeholder for {url_to_check}")
    time.sleep(0.1)
    if not IPQS_API_KEY: return {"error": "IPQS API key not configured"}
    if "phishing-site.com" in url_to_check:
        return {"success": True, "phishing": True, "suspicious": True, "risk_score": 95}
    if "suspicious-site" in url_to_check:
        return {"success": True, "phishing": False, "suspicious": True, "risk_score": 70}
    if "error-ipqs" in url_to_check:
        return {"success": False, "message": "Simulated IPQS error"}
    return {"success": True, "phishing": False, "suspicious": False, "risk_score": 10}

def check_abuseipdb(ip_address):
    # Replace with actual implementation from original script
    logger.info(f"AbuseIPDB check placeholder for {ip_address}")
    time.sleep(0.1)
    if not ABUSEIPDB_API_KEY: return {"error": "AbuseIPDB API key not configured"}
    if ip_address == "1.2.3.4": # Simulate bad IP
        return {"abuseConfidenceScore": 90, "totalReports": 50, "countryCode": "US", "isp": "Bad ISP"}
    if ip_address == "5.6.7.8": # Simulate error
        return {"error": "Simulated AbuseIPDB error"}
    return {"abuseConfidenceScore": 5, "totalReports": 1, "countryCode": "CA", "isp": "Good ISP"}


# --- Email Processing Functions (Adapted) ---
# (Keep the original implementations of read_email_file, extract_basic_email_details,
# extract_urls_from_email, extract_urls_from_text, extract_urls_from_html,
# extract_attachments_from_email, extract_email_content,
# check_content_for_phishing_indicators here)
# --- Placeholder implementations ---
def read_email_file(file_path):
    # Replace with actual implementation
    logger.info(f"Reading email file placeholder: {file_path}")
    try:
        with open(file_path, 'rb') as f:
            # Use the default policy which creates EmailMessage objects
            # Ensure correct parsing policy is used if needed
            return BytesParser(policy=policy.default).parse(f)
    except FileNotFoundError:
        logger.error(f"Email file not found: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Error reading email file {file_path}: {e}", exc_info=True)
        return None

def extract_basic_email_details(msg):
    # Replace with actual implementation from original script
    # Ensure correct handling of different 'From'/'To' formats and IP extraction
    logger.info("Extracting basic email details placeholder")
    sender = msg.get('From')
    sender_email, sender_name, sender_domain, sender_ip = None, None, None, "Not found"
    if sender:
        sender_str = str(sender)
        match = re.match(r'^\s*(.*?)\s*<(.+@.+)>', sender_str)
        if match:
            sender_name = match.group(1).strip().strip('"')
            sender_email = match.group(2).strip()
        else:
            email_match = re.search(r'[\w\.-]+@[\w\.-]+', sender_str)
            if email_match: sender_email = email_match.group(0).strip('<>')
            else: sender_name = sender_str.strip()
    if sender_email and '@' in sender_email:
        try: sender_domain = sender_email.split('@')[-1]
        except IndexError: pass
    # Add IP extraction logic from original script (checking headers)
    ipv4_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_headers_priority = ["X-Sender-IP", "X-Originating-IP", "Received-SPF"]
    for header_name in ip_headers_priority:
        header_val = msg.get(header_name)
        if header_val:
            ip_match = re.search(ipv4_regex, str(header_val))
            if ip_match:
                potential_ip = ip_match.group(0)
                if is_ip_address(potential_ip) and not ipaddress.ip_address(potential_ip).is_private:
                    sender_ip = potential_ip; break
    if sender_ip == "Not found":
        received_headers = msg.get_all("Received", [])
        for header in reversed(received_headers):
            ip_match = re.search(r'(?:from|by)\s+.*\[(' + ipv4_regex + r')\]|\[(' + ipv4_regex + r')\]', str(header))
            if ip_match:
                potential_ip = ip_match.group(1) or ip_match.group(2)
                if is_ip_address(potential_ip) and not ipaddress.ip_address(potential_ip).is_private:
                    sender_ip = potential_ip; break

    return {
        "date": msg.get('Date', 'N/A'),
        "sender_name": sender_name,
        "sender_email": sender_email,
        "sender_domain": sender_domain.lower() if sender_domain else None,
        "sender_ip": sender_ip,
        "reply_to": msg.get('Reply-To'),
        "return_path": msg.get('Return-Path'),
        "recipient": msg.get('To'),
        "subject": msg.get('Subject', 'N/A'),
    }

def extract_urls_from_email(msg):
    # Replace with actual implementation from original script
    # Ensure correct handling of HTML, text parts, and filtering (cid:, mailto:, etc.)
    logger.info("Extracting URLs from email placeholder")
    urls = set()
    # --- Add the full URL extraction logic from original script here ---
    # This involves walking through email parts, decoding, using BeautifulSoup for HTML,
    # regex for text, and filtering schemes.
    try:
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            is_attachment = "attachment" in content_disposition.lower()
            main_type = part.get_content_maintype()

            if main_type not in ['text', 'multipart'] or (is_attachment and main_type != 'text'):
                 continue

            if content_type in ['text/plain', 'text/html']:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try: body = payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError): body = None # Add fallback logic if needed

                        if body:
                            if content_type == 'text/plain':
                                extract_urls_from_text(body, urls)
                            elif content_type == 'text/html':
                                extract_urls_from_html(body, urls)
                except Exception as e: logger.error(f"Error processing part payload: {e}")
    except Exception as e: logger.exception(f"Error walking email parts: {e}")

    # --- Filtering logic from original script ---
    final_urls = set()
    for url in urls:
        try:
            cleaned = url.strip().rstrip('.,;!?)>"\'')
            if cleaned.lower().startswith(('cid:', 'mailto:', 'tel:', 'data:', 'javascript:', 'ftp:')): continue
            if not re.match(r'^[a-zA-Z]+://', cleaned): cleaned = 'http://' + cleaned
            parsed = urlparse(cleaned)
            if parsed.scheme in ['http', 'https'] and parsed.netloc:
                 if '.' in parsed.netloc or is_ip_address(parsed.netloc): final_urls.add(cleaned)
            elif not parsed.scheme and parsed.path and '.' in parsed.path: # Handle www.example.com case
                 cleaned = 'http://' + cleaned
                 parsed_again = urlparse(cleaned)
                 if parsed_again.scheme and parsed_again.netloc: final_urls.add(cleaned)
        except Exception as parse_err: logger.warning(f"Could not parse URL '{url}': {parse_err}")

    return list(final_urls)

# Need helpers: extract_urls_from_text, extract_urls_from_html
def extract_urls_from_text(text, url_set):
     # Use regex from original script
     url_regex = re.compile(r'((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,18}/?)(?:[^\s()<>\[\]\'"]+|\(([^\s()<>\[\]\'"]+|(\([^\s()<>\[\]\'"]+\)))*\))+(?<![.,;!?]))', re.IGNORECASE | re.UNICODE)
     for match in url_regex.finditer(text): url_set.add(match.group(0).rstrip('.'))

def extract_urls_from_html(html, url_set):
     # Use BeautifulSoup logic from original script
     try:
          soup = BeautifulSoup(html, 'html5lib')
          for a_tag in soup.find_all('a', href=True):
               href = a_tag['href'].strip()
               if href and not href.lower().startswith(('mailto:', 'tel:', 'javascript:', '#', 'data:', 'cid:')): url_set.add(href)
          # Add extraction from other tags (img, script, link, style) as in original
          for tag_name, attr_name in [('img', 'src'), ('script', 'src'), ('link', 'href'), ('iframe', 'src')]:
               for tag in soup.find_all(tag_name, **{attr_name: True}):
                    attr_value = tag[attr_name].strip()
                    if attr_value and not attr_value.lower().startswith(('data:', 'javascript:', 'cid:')): url_set.add(attr_value)
          for tag in soup.find_all(style=True):
               style_urls = re.findall(r'url\s*\(\s*[\'"]?([^\'"\)\s]+)[\'"]?\s*\)', tag['style'])
               for style_url in style_urls:
                    if not style_url.lower().startswith(('data:', 'cid:')): url_set.add(style_url.strip())
          extract_urls_from_text(soup.get_text(), url_set) # Fallback
     except Exception as e: logger.error(f"Error extracting URLs from HTML: {e}")


def extract_attachments_from_email(msg):
    # Replace with actual implementation from original script
    # Ensure correct identification of attachments and risk assessment
    logger.info("Extracting attachments placeholder")
    attachments = []
    # --- Add the full attachment extraction logic from original script ---
    # This involves walking parts, checking Content-Disposition/filename,
    # identifying risky extensions.
    try:
        for part in msg.walk():
            filename = part.get_filename()
            content_disposition = str(part.get("Content-Disposition", "")).lower()
            is_attachment_disposition = "attachment" in content_disposition
            main_type = part.get_content_maintype()

            if not filename and not is_attachment_disposition:
                 if main_type == 'text' or main_type == 'multipart': continue

            if filename or is_attachment_disposition:
                try:
                    content_type = part.get_content_type()
                    size = 0
                    try:
                        payload_bytes = part.get_payload(decode=True)
                        if payload_bytes: size = len(payload_bytes)
                    except Exception: pass # Ignore decode errors for size

                    clean_filename = os.path.basename(filename.strip()) if filename else "unnamed"
                    extension = os.path.splitext(clean_filename)[1].lower() if '.' in clean_filename else ''

                    suspicious_exts = ['.exe', '.scr', '.pif', '.bat', '.cmd', '.com', '.dll', '.cpl', '.hta', '.vbs', '.vbe', '.js', '.jse', '.ps1', '.wsf', '.msi', '.zip', '.rar', '.docm', '.xlsm', '.pptm', '.lnk', '.iso', '.html', '.htm', '.pdf'] # Simplified list
                    high_risk_exts = ['.exe', '.scr', '.pif', '.bat', '.cmd', '.com', '.dll', '.cpl', '.hta', '.vbs', '.vbe', '.js', '.jse', '.ps1', '.wsf', '.msi', '.lnk']

                    attachments.append({
                        'filename': clean_filename, 'content_type': content_type, 'size': size,
                        'extension': extension,
                        'suspicious': extension in suspicious_exts,
                        'high_risk': extension in high_risk_exts
                    })
                except Exception as e: logger.error(f"Error processing attachment: {e}")
    except Exception as e: logger.exception(f"Error walking parts for attachments: {e}")
    return attachments


def extract_email_content(msg):
    # Replace with actual implementation from original script
    # Ensure correct decoding and extraction of plain text and HTML
    logger.info("Extracting email content placeholder")
    plain_text, html_content = "", ""
    # --- Add the full content extraction logic from original script ---
    # This involves finding the best text/plain and text/html parts,
    # decoding with charset detection/fallbacks, and potentially extracting text from HTML.
    for part in msg.walk():
        content_type = part.get_content_type()
        is_attachment = part.is_attachment() or "attachment" in str(part.get("Content-Disposition", "")).lower()
        if content_type == "text/plain" and not is_attachment:
            payload_bytes = part.get_payload(decode=True)
            if payload_bytes:
                 charset = part.get_content_charset() or 'utf-8'
                 try: decoded_text = payload_bytes.decode(charset, errors='replace')
                 except (LookupError, UnicodeDecodeError): decoded_text = payload_bytes.decode('iso-8859-1', errors='replace') # Simple fallback
                 if plain_text is None or len(decoded_text) > len(plain_text): plain_text = decoded_text
        elif content_type == "text/html" and not is_attachment:
             payload_bytes = part.get_payload(decode=True)
             if payload_bytes:
                  charset = part.get_content_charset() or 'utf-8'
                  try: decoded_html = payload_bytes.decode(charset, errors='replace')
                  except (LookupError, UnicodeDecodeError): decoded_html = payload_bytes.decode('iso-8859-1', errors='replace') # Simple fallback
                  if html_content is None or len(decoded_html) > len(html_content): html_content = decoded_html

    if html_content and not plain_text: # Extract text from HTML if plain is missing
        try:
            soup = BeautifulSoup(html_content, 'html5lib')
            plain_text = soup.get_text(separator=' ', strip=True)
        except Exception: pass

    return plain_text.strip(), html_content.strip()


def check_content_for_phishing_indicators(text, html_content=""):
    # Replace with actual implementation from original script
    # Ensure correct keyword checking, structural analysis, and HTML checks
    logger.info("Checking content for phishing indicators placeholder")
    # --- Add the full content analysis logic from original script ---
    # This includes keyword checks (urgency, financial, credentials), grammar checks,
    # HTML checks (link mismatch, forms, obfuscation).
    indicators = []
    points = 0
    text_lower = text.lower().strip()
    if not text_lower: return {'indicators': [], 'score': 0, 'suspicious': False}

    keyword_categories = { # Simplified from original
        "Urgency/Threat": (['urgent', 'action required', 'warning', 'alert', 'suspended', 'locked'], 0.7),
        "Credential Request": (['login', 'password', 'username', 'sign in', 'verify your information'], 1.0),
        "Generic/Social Engineering": (['click here', 'follow this link', 'download attachment'], 0.3),
    }
    found_keywords = set()
    for category, (phrases, weight) in keyword_categories.items():
        matches = [p for p in phrases if p in text_lower]
        if matches:
            unique_matches = set(matches)
            indicators.append(f"{category}: {', '.join(list(unique_matches)[:3])}...")
            points += len(unique_matches) * weight
            found_keywords.update(unique_matches)

    # Add basic HTML checks if html_content provided
    if html_content:
        try:
            soup = BeautifulSoup(html_content, 'html5lib')
            if soup.find('form') and soup.find('input', {'type': 'password'}):
                indicators.append("HTML form with password field found")
                points += 1.0
            # Add link mismatch check from original if needed
        except Exception: pass

    final_points = round(max(0, points), 2)
    return {'indicators': indicators, 'score': final_points, 'suspicious': final_points >= 1.5}


# --- Scoring and Verdict (Adapted) ---
# (Keep the original implementations of calculate_email_phishing_score, get_email_verdict,
# analyze_url, extract_url_features, calculate_url_phishing_score, get_url_verdict here)
# --- Placeholder implementations ---
def calculate_email_phishing_score(email_details, results, url_results, attachments, content_analysis, auth_alignment, is_whitelisted):
    # Replace with actual implementation from original script
    # Ensure correct weighting of auth, reputation, URLs, attachments, content, headers
    logger.info("Calculating email phishing score placeholder")
    score = 0.0
    reasons = []
    # --- Add the full scoring logic from original script ---
    # This includes penalties/bonuses for SPF, DKIM, DMARC, alignment, VT results,
    # AbuseIPDB, WHOIS age, URL verdicts, attachment risk, content score, header mismatches.

    # Simplified example scoring:
    spf_result = results.get('spf', 'Not checked')
    dkim_result = results.get('dkim', 'Not checked')
    dmarc_result = results.get('dmarc', 'Not checked')
    if spf_result not in ["Pass", "Not checked", "Neutral", "None"]: score += 1.5; reasons.append(f"SPF Failed ({spf_result})")
    if dkim_result not in ["Pass", "Not checked"]: score += 1.5; reasons.append(f"DKIM Failed ({dkim_result})")
    if dmarc_result in ["No DMARC record", "Error checking DMARC"]: score += 1.0; reasons.append("DMARC Missing/Error")
    if not auth_alignment.get('aligned', True): score += 2.0; reasons.append("Authentication Misaligned")

    # Sender Rep
    vt_domain = results.get('vt_domain', {})
    if isinstance(vt_domain, dict) and 'error' not in vt_domain:
        if vt_domain.get('last_analysis_stats', {}).get('malicious', 0) > 0: score += 1.5; reasons.append("VT Domain Malicious")
        elif vt_domain.get('last_analysis_stats', {}).get('suspicious', 0) > 0: score += 0.8; reasons.append("VT Domain Suspicious")
    # Add VT IP, AbuseIPDB, WHOIS scoring from original

    # URLs
    mal_urls = sum(1 for u in url_results if isinstance(u, dict) and u.get('verdict') == 'Phishing')
    susp_urls = sum(1 for u in url_results if isinstance(u, dict) and u.get('verdict') == 'Suspicious')
    if mal_urls > 0: score += mal_urls * 2.0; reasons.append(f"Phishing URLs ({mal_urls})")
    if susp_urls > 0: score += susp_urls * 1.0; reasons.append(f"Suspicious URLs ({susp_urls})")

    # Attachments
    high_risk = sum(1 for a in attachments if a.get('high_risk'))
    susp = sum(1 for a in attachments if a.get('suspicious') and not a.get('high_risk'))
    if high_risk > 0: score += high_risk * 2.5; reasons.append(f"High-Risk Attachments ({high_risk})")
    if susp > 0: score += susp * 1.2; reasons.append(f"Suspicious Attachments ({susp})")

    # Content
    if content_analysis.get('suspicious'): score += min(content_analysis.get('score', 0) * 1.0, 3.0); reasons.append(f"Suspicious Content (Score: {content_analysis.get('score', 0):.2f})")

    # Whitelist
    if is_whitelisted: score *= 0.2; reasons.append("Sender Whitelisted (Score Reduced)")

    final_score = max(0.0, min(score, 10.0))
    return final_score, reasons

def get_email_verdict(score):
    # Replace with actual implementation from original script
    if score <= 1.0: return "Legitimate"
    elif score <= 3.0: return "Likely Legitimate"
    elif score <= 5.5: return "Suspicious"
    elif score <= 7.5: return "Highly Suspicious"
    else: return "Phishing"

def analyze_url(url, analyzed_domains_cache=None):
    # Replace with actual implementation from original script
    # This function orchestrates URL feature extraction, API calls, scoring
    logger.info(f"Analyzing URL placeholder: {url}")
    if analyzed_domains_cache is None: analyzed_domains_cache = {}
    start_time = time.time()

    # --- Basic Parsing and Validation ---
    try:
        original_url = url
        if not re.match(r'^[a-zA-Z]+://', url): url = 'http://' + url
        parsed_url = urlparse(url)
        if not parsed_url.scheme in ['http', 'https'] or not parsed_url.netloc:
            raise ValueError("Invalid scheme or netloc")
        domain_ip_raw = parsed_url.netloc.lower()
        domain_or_ip = domain_ip_raw.split(':', 1)[0] if ':' in domain_ip_raw else domain_ip_raw
        is_ip = is_ip_address(domain_or_ip)
        # Add more validation if needed (e.g., domain format regex)
        domain_regex = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'
        if not is_ip and not re.match(domain_regex, domain_or_ip):
            if re.search(r'[{}[\]<>"\s]', domain_or_ip): raise ValueError(f"Invalid characters in domain part")
            raise ValueError(f"Invalid domain format")

    except Exception as e:
        logger.warning(f"Invalid URL format skipped: {original_url} - {e}")
        return {"url": original_url, "error": f"Invalid URL format: {e}", "score": 0, "verdict": "Error"}

    # --- Whitelist Check ---
    is_whitelisted_url = any(wl_domain and (domain_or_ip == wl_domain or domain_or_ip.endswith('.' + wl_domain)) for wl_domain in WHITELISTED_URLS)
    if is_whitelisted_url:
        logger.info(f"URL whitelisted: {url}")
        return {"url": url, "domain": domain_or_ip, "features": {}, "api_results": {}, "verdict": "Legitimate (Whitelisted)", "score": 0, "reasons": ["URL Whitelisted"]}

    # --- Feature Extraction ---
    features = extract_url_features(url, parsed_url, domain_or_ip, is_ip)

    # --- API Calls (Concurrent) ---
    api_results = {}
    url_hash_key = hashlib.sha256(original_url.encode()).hexdigest()
    cached_full_analysis = get_from_cache('url_analysis', url_hash_key)
    if cached_full_analysis:
        logger.info(f"Full URL analysis cache hit for: {url}")
        if 'reasons' not in cached_full_analysis: cached_full_analysis['reasons'] = ['Loaded from cache']
        return cached_full_analysis

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        if VIRUSTOTAL_API_KEY: futures['virustotal_url'] = executor.submit(check_virustotal_url, url)
        if GOOGLE_SAFE_BROWSING_API_KEY: futures['google_safe_browsing'] = executor.submit(check_google_safe_browsing, url)
        if IPQS_API_KEY: futures['ipqs'] = executor.submit(check_ipqs, url)

        # Domain/IP specific checks
        cache_key = f"{'ip' if is_ip else 'domain'}_{domain_or_ip}"
        if cache_key in analyzed_domains_cache:
            logger.info(f"Using cached reputation for {'IP' if is_ip else 'Domain'}: {domain_or_ip}")
            api_results.update(analyzed_domains_cache[cache_key])
        else:
            domain_futures = {}
            if is_ip:
                if VIRUSTOTAL_API_KEY: domain_futures['vt_ip'] = executor.submit(check_virustotal_ip, domain_or_ip)
                if ABUSEIPDB_API_KEY: domain_futures['abuseipdb'] = executor.submit(check_abuseipdb, domain_or_ip)
            else:
                if VIRUSTOTAL_API_KEY: domain_futures['vt_domain'] = executor.submit(check_virustotal_domain, domain_or_ip)
                domain_futures['whois'] = executor.submit(get_whois_info, domain_or_ip)
            futures.update(domain_futures)

        for key, future in futures.items():
            try: api_results[key] = future.result()
            except Exception as e: api_results[key] = {"error": f"Future execution error: {str(e)}"}

        # Cache domain/IP results
        if cache_key not in analyzed_domains_cache:
             domain_cache_data = {}
             if is_ip:
                  if 'vt_ip' in api_results and 'error' not in api_results.get('vt_ip', {}): domain_cache_data['vt_ip'] = api_results['vt_ip']
                  if 'abuseipdb' in api_results and 'error' not in api_results.get('abuseipdb', {}): domain_cache_data['abuseipdb'] = api_results['abuseipdb']
             else:
                  if 'vt_domain' in api_results and 'error' not in api_results.get('vt_domain', {}): domain_cache_data['vt_domain'] = api_results['vt_domain']
                  if 'whois' in api_results and 'error' not in api_results.get('whois', {}): domain_cache_data['whois'] = api_results['whois']
             if domain_cache_data: analyzed_domains_cache[cache_key] = domain_cache_data

    # --- Scoring & Verdict ---
    score, reasons = calculate_url_phishing_score(features, api_results)
    verdict = get_url_verdict(score)

    analysis_result = {
        "url": url, "domain": domain_or_ip, "features": features,
        "api_results": api_results, "verdict": verdict,
        "score": round(score, 2), "reasons": reasons
    }
    save_to_cache('url_analysis', url_hash_key, analysis_result)
    logger.info(f"URL analysis completed for {url} in {time.time() - start_time:.2f} seconds. Score: {analysis_result['score']:.2f}, Verdict: {analysis_result['verdict']}")
    return analysis_result

def extract_url_features(url, parsed_url, domain_or_ip, is_ip):
    # Replace with actual implementation from original script
    # Ensure all features are extracted correctly
    logger.info("Extracting URL features placeholder")
    # --- Add the full feature extraction logic from original script ---
    # This includes lengths, counts (dots, dashes, digits), keywords, TLD checks,
    # entropy, brand names, typosquatting checks, etc.
    domain_part = domain_or_ip if not is_ip else None
    features = {
        "url": url, "domain_ip_for_rep_check": domain_or_ip, "is_ip_address": is_ip,
        "url_length": len(url), "domain_length": len(domain_or_ip),
        "path_length": len(parsed_url.path), "query_length": len(parsed_url.query),
        "fragment_length": len(parsed_url.fragment),
        "subdomain_count": domain_or_ip.count('.') if not is_ip else 0,
        "path_depth": len([p for p in parsed_url.path.split('/') if p]),
        "query_param_count": len(parse_qs(parsed_url.query)),
        "domain_dash_count": domain_or_ip.count('-'),
        "path_dash_count": parsed_url.path.count('-'),
        "query_underscore_count": parsed_url.query.count('_'),
        "path_dot_count": parsed_url.path.count('.'),
        "domain_digit_count": sum(c.isdigit() for c in domain_or_ip),
        "path_digit_count": sum(c.isdigit() for c in parsed_url.path),
        "has_at_sign": '@' in parsed_url.netloc.lower(),
        "has_double_slash_in_path": '//' in parsed_url.path.lstrip('/'),
        "has_hex_chars": bool(re.search(r'%[0-9a-fA-F]{2}', url)),
        "has_suspicious_tld": has_suspicious_tld(domain_or_ip) if not is_ip else False,
        "has_suspicious_keywords": any(re.search(r'\b' + re.escape(kw) + r'\b|' + re.escape(kw), url.lower()) for kw in PHISHING_KEYWORDS), # Use global list
        "is_shortened_url": is_shortened_url(domain_or_ip) if not is_ip else False,
        "uses_https": parsed_url.scheme == 'https',
        "uses_non_std_port": uses_uncommon_port(parsed_url),
        "domain_entropy": calculate_string_entropy(domain_part.split('.')[-2]) if domain_part and '.' in domain_part and len(domain_part.split('.')) > 1 else 0.0,
        "path_entropy": calculate_string_entropy(parsed_url.path),
        "query_entropy": calculate_string_entropy(parsed_url.query),
        "contains_brand_name": contains_brand_name(domain_or_ip) if not is_ip else False,
        "is_potential_typosquatting": check_typosquatting(domain_or_ip) if not is_ip else False,
        "has_redirect_param": has_unusual_redirect_param(parsed_url.query)
    }
    return features

def calculate_url_phishing_score(features, api_results):
    # Replace with actual implementation from original script
    # Ensure correct weighting of features and API results
    logger.info("Calculating URL phishing score placeholder")
    score = 0.0
    reasons = []
    # --- Add the full URL scoring logic from original script ---
    # This involves applying weights to features (length, keywords, entropy, etc.)
    # and API results (VT, GSB, IPQS, AbuseIPDB, WHOIS).

    # Simplified example scoring:
    feature_weights = { # Simplified weights
        "is_ip_address": 1.5, "url_length_thresh": (80, 0.025),
        "subdomain_count_thresh": (3, 0.5), "has_at_sign": 1.2,
        "has_suspicious_tld": 1.5, "has_suspicious_keywords": 1.8,
        "is_shortened_url": 1.0, "uses_https": -1.2,
        "contains_brand_name": 2.0, "is_potential_typosquatting": 1.8,
    }
    for feature_key, feature_value in features.items():
        if feature_key in feature_weights:
            weight_config = feature_weights[feature_key]
            if isinstance(weight_config, tuple): # Threshold based
                threshold, weight = weight_config
                if isinstance(feature_value, (int, float)) and feature_value > threshold:
                    increase = (feature_value - threshold) * weight; score += increase
                    reasons.append(f"{feature_key.replace('_thresh','')} > {threshold} (+{increase:.2f})")
            elif isinstance(weight_config, (int, float)): # Direct weight
                weight = weight_config
                if isinstance(feature_value, bool) and feature_value:
                     if feature_key == "uses_https":
                          bonus = max(weight, -score * 0.5); score += bonus
                          if bonus < 0: reasons.append(f"Uses HTTPS ({bonus:.2f})")
                     else: score += weight; reasons.append(f"Feature: {feature_key} (+{weight:.2f})")

    # API Scoring (Simplified)
    vt_url = api_results.get('virustotal_url', {})
    if isinstance(vt_url, dict) and 'error' not in vt_url:
        mal = vt_url.get('last_analysis_stats', {}).get('malicious', 0)
        susp = vt_url.get('last_analysis_stats', {}).get('suspicious', 0)
        if mal > 0: score += 2.5; reasons.append(f"VT URL Malicious ({mal})")
        elif susp > 0: score += 1.2; reasons.append(f"VT URL Suspicious ({susp})")
    gsb = api_results.get('google_safe_browsing', [])
    if isinstance(gsb, list) and gsb: score += 2.8; reasons.append("GSB Hit")
    ipqs = api_results.get('ipqs', {})
    if isinstance(ipqs, dict) and 'error' not in ipqs:
        if ipqs.get('phishing'): score += 2.2; reasons.append("IPQS Phishing")
        elif ipqs.get('suspicious'): score += 1.0; reasons.append("IPQS Suspicious")
        if ipqs.get('risk_score', 0) > 85: score += 1.5; reasons.append(f"IPQS Risk > 85 ({ipqs.get('risk_score')})")
    # Add Domain/IP rep scoring from original (VT Domain/IP, AbuseIPDB, WHOIS age)

    final_score = max(0.0, min(score, 10.0))
    return final_score, reasons

def get_url_verdict(score):
    # Replace with actual implementation from original script
    if score <= 0.8: return "Legitimate"
    elif score <= 2.0: return "Potentially Suspicious"
    elif score <= 4.5: return "Suspicious"
    else: return "Phishing"

# --- Helper Functions for Feature Extraction (Keep original implementations) ---
# (Keep is_ip_address, has_suspicious_tld, has_suspicious_keywords, is_shortened_url,
# uses_uncommon_port, calculate_string_entropy, contains_brand_name,
# check_typosquatting, has_unusual_redirect_param)
# --- Placeholder implementations ---
def is_ip_address(domain_or_ip):
    if not domain_or_ip: return False
    try: ipaddress.ip_address(domain_or_ip); return True
    except ValueError: return False
def has_suspicious_tld(domain): return domain.endswith(('.xyz', '.top', '.tk', '.link', '.zip', '.info', '.club', '.site', '.online', '.live', '.loan', '.work', '.ninja', '.accountants', '.download', '.security', '.gift', '.review', '.mov')) if '.' in domain else False
# def has_suspicious_keywords(url): return any(kw in url.lower() for kw in PHISHING_KEYWORDS) # Use the full check from analyze_url->extract_features
def is_shortened_url(domain): return domain.lower() in ['bit.ly', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rb.gy', 'shorturl.at']
def uses_uncommon_port(parsed_url): return parsed_url.port not in [None, 80, 443, 8080, 8443]
def calculate_string_entropy(text):
    if not text: return 0.0
    text = str(text)
    freq = {}
    text_len = len(text)
    if text_len == 0: return 0.0
    for char in text: freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        if count > 0: probability = count / text_len; entropy -= probability * math.log2(probability)
    return entropy
def contains_brand_name(domain):
    # Use the more robust check from the original script if possible
    return any(brand in domain.lower() for brand in ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix', 'bank'])
def check_typosquatting(domain):
    # Use the more robust check from the original script if possible
    return 'g00gle' in domain.lower() or 'paypa1' in domain.lower() or 'micros0ft' in domain.lower() or 'app1e' in domain.lower()
def has_unusual_redirect_param(query_string):
    # Use the more robust check from the original script if possible
    return any(f'{param}=' in query_string.lower() for param in ['url', 'redirect', 'goto', 'next', 'continue', 'return_to', 'dest', 'target'])


# --- Email Authentication Class (Adapted) ---
# (Keep the original EmailAuthenticationChecker class implementation here)
# --- Placeholder implementation ---
class EmailAuthenticationChecker:
    """Handles SPF, DKIM, and DMARC checks (adapted from original)."""
    def __init__(self, timeout=5):
        # Configure DNS resolver (consider making this configurable)
        try:
            import dns.resolver
            self.dns_resolver = dns.resolver.Resolver()
            self.dns_resolver.timeout = timeout
            self.dns_resolver.lifetime = timeout * 2 # Slightly longer lifetime
            self.resolver_available = True
        except ImportError:
            logger.warning("dnspython library not found. DNS checks (SPF, DMARC) will be skipped.")
            self.resolver_available = False
            self.dns_resolver = None

    def _query_dns(self, domain, record_type):
        """Helper to query DNS with error handling."""
        if not self.resolver_available: return "Error (dnspython unavailable)"
        try:
            answer = self.dns_resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answer is None or not answer.rrset:
                 logger.debug(f"DNS NoAnswer/NXDOMAIN for {domain} ({record_type})")
                 return None
            return answer
        except dns.resolver.NXDOMAIN:
            logger.debug(f"DNS NXDOMAIN exception for {domain} ({record_type})")
            return None
        except dns.resolver.Timeout:
            logger.warning(f"DNS query timeout for {domain} ({record_type})")
            return "Timeout"
        except dns.exception.DNSException as e:
            logger.error(f"DNS query error for {domain} ({record_type}): {e}")
            return f"Error ({type(e).__name__})"

    def check_spf(self, sender_domain, sender_ip):
        """Checks SPF record (simplified check from original)."""
        if not sender_domain: return "Not checked (No domain)"
        if not sender_ip or sender_ip == "Not found" or not is_ip_address(sender_ip):
            return "Not checked (No valid IP)"
        if not self.resolver_available: return "Skipped (No dnspython)"

        result = self._query_dns(sender_domain, 'TXT')
        if isinstance(result, str): return result # Timeout or Error
        if result is None: return "No SPF record"

        spf_record = None
        for record in result.rrset:
            record_text = b"".join(record.strings).decode('utf-8', errors='replace').strip('"')
            if record_text.lower().startswith('v=spf1'): spf_record = record_text; break
        if not spf_record: return "No SPF record"

        # Simplified check logic from original script
        spf_parts = spf_record.lower().split()
        try: ip_obj = ipaddress.ip_address(sender_ip)
        except ValueError: return "Error (Invalid IP)"

        verdict = "Neutral"; matched_mechanism = False
        for part in spf_parts:
             qualifier = '+'
             if part.startswith(('-', '~', '?')): qualifier = part[0]; mechanism = part[1:]
             elif part.startswith('+'): qualifier = '+'; mechanism = part[1:]
             else: mechanism = part
             if mechanism.startswith(('ip4:', 'ip6:')):
                  try:
                       network = ipaddress.ip_network(mechanism.split(':', 1)[1], strict=False)
                       if ip_obj in network:
                            if qualifier == '+': verdict = "Pass"
                            elif qualifier == '-': verdict = "Fail"
                            elif qualifier == '~': verdict = "SoftFail"
                            elif qualifier == '?': verdict = "Neutral"
                            matched_mechanism = True; break
                  except ValueError: continue
             elif mechanism == 'all' and not matched_mechanism:
                  if qualifier == '+': verdict = "Pass (Permissive +all)"
                  elif qualifier == '-': verdict = "Fail (Fallback -all)"
                  elif qualifier == '~': verdict = "SoftFail (Fallback ~all)"
                  elif qualifier == '?': verdict = "Neutral (Fallback ?all)"
        return verdict

    def check_dkim(self, msg):
        """Checks DKIM using Authentication-Results (from original)."""
        auth_results_header = msg.get("Authentication-Results", "") or msg.get("X-Authentication-Results", "")
        if auth_results_header:
            dkim_match = re.search(r'dkim\s*=\s*([a-z]+)', str(auth_results_header).lower())
            if dkim_match:
                status = dkim_match.group(1)
                if status == 'pass': return "Pass"
                elif status in ['fail', 'permerror', 'temperror']: return "Fail"
                elif status == 'none': return "None"
                elif status == 'neutral': return "Neutral"
                else: return f"Unknown ({status})" # Handle other statuses
            else: logger.debug("DKIM status not found in Auth-Results.")
        if "DKIM-Signature" in msg: return "Header present (No Auth-Results)"
        return "No DKIM info"

    def check_dmarc(self, sender_domain):
        """Checks for DMARC record and policy (from original)."""
        if not sender_domain: return "Not checked (No domain)"
        if not self.resolver_available: return "Skipped (No dnspython)"

        dmarc_query_domain = f"_dmarc.{sender_domain}"
        result = self._query_dns(dmarc_query_domain, 'TXT')
        if isinstance(result, str): return result # Timeout or Error
        if result is None: return "No DMARC record"

        dmarc_record = None
        for record in result.rrset:
            record_text = b"".join(record.strings).decode('utf-8', errors='replace').strip('"')
            if record_text.lower().startswith('v=dmarc1'): dmarc_record = record_text; break
        if not dmarc_record: return "No DMARC record"

        policy_match = re.search(r'p\s*=\s*(\w+)', dmarc_record, re.IGNORECASE)
        policy = "none"
        if policy_match: policy = policy_match.group(1).lower()
        if policy == 'reject': return "Pass (p=reject)"
        elif policy == 'quarantine': return "Pass (p=quarantine)"
        else: return "Pass (p=none)"

    def check_authentication_alignment(self, msg, sender_domain):
        """Checks DKIM/SPF alignment with From: domain (from original)."""
        from_domain_lower = sender_domain.lower() if sender_domain else None
        alignment = {"from_domain": from_domain_lower, "dkim_domain": None, "spf_domain": None, "aligned": True}
        if not from_domain_lower: return alignment

        auth_results_header = str(msg.get("Authentication-Results", "") or msg.get("X-Authentication-Results", "")).lower()
        dkim_aligned, spf_aligned = False, False
        dkim_result_found, spf_result_found = False, False

        dkim_pass_match = re.search(r'dkim=pass(?:\s|\().*?header\.d=([a-z0-9.\-]+)', auth_results_header)
        if dkim_pass_match:
            dkim_result_found = True; alignment["dkim_domain"] = dkim_pass_match.group(1)
            if alignment["dkim_domain"] == from_domain_lower or alignment["dkim_domain"].endswith('.' + from_domain_lower): dkim_aligned = True

        spf_pass_match = re.search(r'spf=pass(?:\s|\().*?(?:smtp\.mailfrom=|header\.from=)(?:.*?@)?([a-z0-9.\-]+)', auth_results_header)
        if spf_pass_match:
            spf_result_found = True; alignment["spf_domain"] = spf_pass_match.group(1)
            if alignment["spf_domain"] == from_domain_lower or alignment["spf_domain"].endswith('.' + from_domain_lower): spf_aligned = True

        # Determine overall alignment based on DMARC rules
        if (dkim_result_found and not dkim_aligned) and (spf_result_found and not spf_aligned): alignment["aligned"] = False
        elif (dkim_result_found and not dkim_aligned) and not spf_result_found: alignment["aligned"] = False
        elif (spf_result_found and not spf_aligned) and not dkim_result_found: alignment["aligned"] = False
        elif dkim_aligned or spf_aligned: alignment["aligned"] = True
        else: alignment["aligned"] = True # Treat indeterminate as aligned

        return alignment


# --- Worker Thread for Analysis ---
class AnalysisWorker(QObject):
    """Runs the analysis in a separate thread."""
    finished = pyqtSignal(object) # Signal emits the result dictionary or None on error
    progress = pyqtSignal(str)    # Signal for status updates
    error = pyqtSignal(str)       # Signal for errors

    def __init__(self, analysis_type, input_data):
        super().__init__()
        self.analysis_type = analysis_type # 'email' or 'url'
        self.input_data = input_data     # File path for email, URL string for URL

    @pyqtSlot()
    def run(self):
        """Performs the analysis."""
        try:
            if self.analysis_type == 'email':
                result = self._analyze_email_task(self.input_data)
            elif self.analysis_type == 'url':
                result = self._analyze_url_task(self.input_data)
            else:
                raise ValueError(f"Unknown analysis type: {self.analysis_type}")

            self.finished.emit(result)

        except Exception as e:
            logger.exception(f"Error during {self.analysis_type} analysis in worker thread:")
            self.error.emit(f"An unexpected error occurred during analysis: {e}")
            self.finished.emit(None) # Emit None to indicate failure


    def _analyze_email_task(self, file_path):
        """Orchestrates the analysis of a single email file within the thread."""
        self.progress.emit(f"Reading email file: {os.path.basename(file_path)}...")
        msg = read_email_file(file_path)
        if not msg:
            self.error.emit("Failed to read or parse email file.")
            return None # Indicate failure

        self.progress.emit("Extracting headers, URLs, attachments, content...")
        email_details = extract_basic_email_details(msg)
        urls = extract_urls_from_email(msg)
        attachments = extract_attachments_from_email(msg)
        plain_text, html_content = extract_email_content(msg)

        sender_domain = email_details.get('sender_domain')
        sender_ip = email_details.get('sender_ip')
        is_whitelisted = sender_domain in WHITELISTED_SENDERS if sender_domain else False
        if is_whitelisted:
            self.progress.emit(f"Sender domain '{sender_domain}' is whitelisted.")

        self.progress.emit("Performing authentication & content checks...")
        results = {}
        url_results = []
        analyzed_domains_cache = {} # Cache for domain/IP checks within this email context
        auth_checker = EmailAuthenticationChecker()

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            # Submit core checks
            futures['spf'] = executor.submit(auth_checker.check_spf, sender_domain, sender_ip)
            futures['dkim'] = executor.submit(auth_checker.check_dkim, msg)
            futures['dmarc'] = executor.submit(auth_checker.check_dmarc, sender_domain)
            futures['content'] = executor.submit(check_content_for_phishing_indicators, plain_text, html_content)
            futures['auth_alignment'] = executor.submit(auth_checker.check_authentication_alignment, msg, sender_domain)

            # Submit sender reputation checks
            sender_rep_cache_key = None
            if not is_whitelisted:
                lc_sender_domain = sender_domain.lower() if sender_domain else None
                lc_sender_ip = sender_ip.lower() if sender_ip and sender_ip != "Not found" else None
                if lc_sender_domain:
                    sender_rep_cache_key = f"domain_{lc_sender_domain}"
                    futures['vt_domain'] = executor.submit(check_virustotal_domain, lc_sender_domain)
                    futures['whois'] = executor.submit(get_whois_info, lc_sender_domain)
                if lc_sender_ip:
                    if not sender_rep_cache_key: sender_rep_cache_key = f"ip_{lc_sender_ip}"
                    futures['vt_ip'] = executor.submit(check_virustotal_ip, lc_sender_ip)
                    futures['abuseipdb'] = executor.submit(check_abuseipdb, lc_sender_ip)

            # Submit URL analysis
            url_limit = 10 # Analyze more URLs in GUI?
            unique_urls_to_analyze = list(set(urls))[:url_limit]
            self.progress.emit(f"Submitting {len(unique_urls_to_analyze)} URLs for analysis...")
            url_futures = {f'url_{i}': executor.submit(analyze_url, url, analyzed_domains_cache)
                           for i, url in enumerate(unique_urls_to_analyze)}

            # Collect core results
            self.progress.emit("Collecting core analysis results...")
            core_keys = ['spf', 'dkim', 'dmarc', 'content', 'auth_alignment', 'vt_domain', 'whois', 'vt_ip', 'abuseipdb']
            for key in core_keys:
                if key in futures:
                    try:
                        results[key] = futures[key].result()
                        # Populate shared cache (simplified)
                        if sender_rep_cache_key and key in ['vt_domain', 'whois', 'vt_ip', 'abuseipdb']:
                             if sender_rep_cache_key not in analyzed_domains_cache: analyzed_domains_cache[sender_rep_cache_key] = {}
                             if isinstance(results[key], dict) and 'error' not in results[key]:
                                  analyzed_domains_cache[sender_rep_cache_key][key] = results[key]
                    except Exception as e:
                        logger.error(f"Error getting result for {key}: {e}")
                        results[key] = {"error": f"Future execution error: {str(e)}"}

            # Collect URL results
            self.progress.emit("Collecting URL analysis results...")
            for key, future in url_futures.items():
                try:
                    url_analysis = future.result()
                    if isinstance(url_analysis, dict) and 'error' not in url_analysis:
                        url_results.append(url_analysis)
                    elif isinstance(url_analysis, dict):
                         logger.warning(f"URL analysis failed for {url_analysis.get('url', key)}: {url_analysis.get('error')}")
                except Exception as e:
                    logger.error(f"Error getting result for URL future {key}: {e}")

        # Sort URL results
        url_results.sort(key=lambda x: x.get('score', 0) if isinstance(x, dict) else 0, reverse=True)

        # Calculate final score
        self.progress.emit("Calculating final score...")
        auth_alignment_result = results.get('auth_alignment', {'aligned': True})
        content_analysis_result = results.get('content', {'score': 0, 'indicators': [], 'suspicious': False})
        phishing_score, score_reasons = calculate_email_phishing_score(
            email_details, results, url_results, attachments, content_analysis_result, auth_alignment_result, is_whitelisted
        )
        verdict = get_email_verdict(phishing_score)

        self.progress.emit("Analysis complete.")

        # Package results for the GUI
        return {
            "type": "email",
            "details": email_details,
            "auth_results": {k: results.get(k) for k in ['spf', 'dkim', 'dmarc']},
            "auth_alignment": auth_alignment_result,
            "reputation_results": {k: results.get(k) for k in ['vt_domain', 'whois', 'vt_ip', 'abuseipdb']},
            "url_results": url_results,
            "attachments": attachments,
            "content_analysis": content_analysis_result,
            "score": phishing_score,
            "score_reasons": score_reasons,
            "verdict": verdict,
            "is_whitelisted": is_whitelisted
        }

    def _analyze_url_task(self, url_to_analyze):
        """Orchestrates the analysis of a single URL within the thread."""
        self.progress.emit(f"Analyzing URL: {url_to_analyze}...")
        # analyze_url function already handles caching, API calls, scoring etc.
        analysis_result = analyze_url(url_to_analyze) # Use the existing function

        if analysis_result and 'error' in analysis_result:
             self.error.emit(f"URL Analysis Error: {analysis_result['error']}")
             return None # Indicate failure

        if not analysis_result:
             self.error.emit("URL Analysis failed to return results.")
             return None

        self.progress.emit("Analysis complete.")
        # Package results for the GUI
        return {
            "type": "url",
            "analysis": analysis_result # Contains score, verdict, reasons, etc.
        }


# --- Main GUI Window ---
class PhishiDetectorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phishi Detector GUI")
        self.setGeometry(100, 100, 950, 750) # Slightly larger window

        # --- Dark Theme Stylesheet ---
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b; /* Dark Gray */
            }
            QWidget#mainWidget {
                 background-color: #3c3c3c; /* Slightly Lighter Gray */
                 border-radius: 8px;
            }
            QLabel {
                font-size: 10pt;
                color: #dcdcdc; /* Light Gray/Off-white Text */
            }
            QLabel#titleLabel {
                font-size: 18pt; /* Larger title */
                font-weight: bold;
                color: #569cd6; /* Lighter Blue */
                padding-bottom: 15px;
                border-bottom: 1px solid #555555; /* Separator line */
                margin-bottom: 10px;
            }
            QLabel#verdictLabel {
                font-size: 15pt; /* Larger verdict */
                font-weight: bold;
                padding: 12px;
                border-radius: 6px;
                min-height: 45px; /* Ensure height */
                margin-top: 5px;
            }
            QLabel#scoreLabel {
                font-size: 12pt; /* Larger score */
                font-weight: bold;
                color: #dcdcdc;
            }
             QLabel#reasonsLabel {
                font-size: 11pt;
                font-weight: bold;
                color: #cccccc;
                margin-top: 10px;
            }
            QPushButton {
                background-color: #007acc; /* Brighter Blue */
                color: white;
                font-size: 10pt;
                font-weight: bold;
                padding: 10px 20px; /* More padding */
                border-radius: 6px;
                border: 1px solid #005c9d;
                min-width: 130px;
            }
            QPushButton:hover {
                background-color: #005c9d;
            }
            QPushButton:pressed {
                background-color: #004471;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #aaaaaa;
                border: 1px solid #666666;
            }
            QLineEdit {
                padding: 9px;
                border: 1px solid #555555;
                border-radius: 6px;
                font-size: 10pt;
                background-color: #4a4a4a; /* Darker input background */
                color: #dcdcdc; /* Light text */
            }
            QLineEdit:read-only {
                 background-color: #404040; /* Slightly different for read-only */
            }
            QTextEdit {
                border: 1px solid #555555;
                border-radius: 6px;
                background-color: #333333; /* Dark background */
                color: #dcdcdc; /* Light text */
                font-family: Consolas, Menlo, Monaco, monospace; /* Better monospace fonts */
                font-size: 9pt;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                border-radius: 6px;
                background-color: #3c3c3c; /* Match widget background */
                padding: 8px;
            }
            QTabBar::tab {
                background: #4a4a4a; /* Darker gray for tabs */
                color: #cccccc;
                border: 1px solid #555555;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 9px 18px; /* More padding */
                margin-right: 3px;
            }
            QTabBar::tab:selected {
                background: #3c3c3c; /* Match pane background */
                color: #ffffff; /* White text for selected */
                border-bottom: 1px solid #3c3c3c; /* Hide bottom border join */
            }
            QTabBar::tab:hover {
                background: #555555; /* Lighter gray on hover */
                color: #ffffff;
            }
            QTableWidget {
                border: 1px solid #555555;
                border-radius: 6px;
                gridline-color: #505050; /* Darker grid lines */
                font-size: 9pt;
                background-color: #3c3c3c; /* Base background */
                color: #dcdcdc; /* Default text color */
                alternate-background-color: #404040; /* Darker alternating row */
            }
            QHeaderView::section {
                background-color: #4a4a4a; /* Header background */
                padding: 6px;
                border: 1px solid #555555;
                font-weight: bold;
                font-size: 9pt;
                color: #e0e0e0; /* Lighter header text */
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 6px;
                text-align: center;
                color: #dcdcdc; /* Light text */
                height: 16px;
                background-color: #4a4a4a; /* Dark background */
            }
            QProgressBar::chunk {
                background-color: #007acc; /* Blue progress */
                border-radius: 5px;
            }
            QScrollBar:vertical {
                border: 1px solid #555555;
                background: #3c3c3c;
                width: 14px; /* Slightly wider */
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #666666;
                min-height: 25px;
                border-radius: 6px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                 border: 1px solid #555555;
                 background: #3c3c3c;
                 height: 14px;
                 margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:horizontal {
                 background: #666666;
                 min-width: 25px;
                 border-radius: 6px;
            }
             QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                 width: 0px;
            }
            QMessageBox {
                background-color: #3c3c3c; /* Dark background for message boxes */
            }
            QMessageBox QLabel { /* Style labels inside message boxes */
                color: #dcdcdc;
            }
            QMessageBox QPushButton { /* Style buttons inside message boxes */
                 min-width: 80px; /* Standard size */
                 background-color: #007acc;
                 border: 1px solid #005c9d;
                 padding: 8px 15px;
            }
             QMessageBox QPushButton:hover { background-color: #005c9d; }
             QMessageBox QPushButton:pressed { background-color: #004471; }

        """)

        # --- Main Layout ---
        self.main_widget = QWidget(self)
        self.main_widget.setObjectName("mainWidget")
        self.setCentralWidget(self.main_widget)
        self.layout = QVBoxLayout(self.main_widget)
        self.layout.setContentsMargins(25, 20, 25, 20) # Adjust padding
        self.layout.setSpacing(18) # Adjust spacing

        # --- Title ---
        self.title_label = QLabel("Phishi Detector")
        self.title_label.setObjectName("titleLabel")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.title_label)

        # --- Input Area ---
        input_layout = QVBoxLayout()
        input_layout.setSpacing(12)

        # Email Input
        email_layout = QHBoxLayout()
        self.email_label = QLabel("Email File (.eml):")
        self.email_path_edit = QLineEdit()
        self.email_path_edit.setPlaceholderText("Select an .eml file...")
        self.email_path_edit.setReadOnly(True)
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_email_file)
        self.analyze_email_button = QPushButton("Analyze Email")
        self.analyze_email_button.clicked.connect(self.start_email_analysis)
        email_layout.addWidget(self.email_label)
        email_layout.addWidget(self.email_path_edit, 1)
        email_layout.addWidget(self.browse_button)
        email_layout.addWidget(self.analyze_email_button)
        input_layout.addLayout(email_layout)

        # URL Input
        url_layout = QHBoxLayout()
        self.url_label = QLabel("URL:")
        self.url_input_edit = QLineEdit()
        self.url_input_edit.setPlaceholderText("Enter a URL to analyze...")
        self.analyze_url_button = QPushButton("Analyze URL")
        self.analyze_url_button.clicked.connect(self.start_url_analysis)
        url_layout.addWidget(self.url_label)
        url_layout.addWidget(self.url_input_edit, 1)
        url_layout.addWidget(self.analyze_url_button)
        input_layout.addLayout(url_layout)

        self.layout.addLayout(input_layout)

        # --- Progress Bar and Status ---
        status_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 0) # Indeterminate
        self.status_label = QLabel("Ready.")
        self.status_label.setStyleSheet("color: #aaaaaa;") # Lighter status text
        status_layout.addWidget(self.status_label, 1)
        status_layout.addWidget(self.progress_bar)
        self.layout.addLayout(status_layout)

        # --- Results Area (Tabbed Interface) ---
        self.tab_widget = QTabWidget()
        self.layout.addWidget(self.tab_widget, 1)

        # Summary Tab
        self.summary_tab = QWidget()
        self.tab_widget.addTab(self.summary_tab, "Summary")
        summary_layout = QVBoxLayout(self.summary_tab)
        summary_layout.setAlignment(Qt.AlignTop)
        summary_layout.setSpacing(15)

        self.verdict_label = QLabel("Verdict: N/A")
        self.verdict_label.setObjectName("verdictLabel")
        self.verdict_label.setAlignment(Qt.AlignCenter)
        self.verdict_label.setStyleSheet("background-color: #555555; color: #cccccc;") # Default dark style
        summary_layout.addWidget(self.verdict_label)

        self.score_label = QLabel("Overall Score: N/A")
        self.score_label.setObjectName("scoreLabel") # Give object name for potential specific styling
        summary_layout.addWidget(self.score_label)

        self.reasons_label = QLabel("Key Factors:")
        self.reasons_label.setObjectName("reasonsLabel")
        summary_layout.addWidget(self.reasons_label)
        self.reasons_text = QTextEdit()
        self.reasons_text.setReadOnly(True)
        self.reasons_text.setFixedHeight(100) # Slightly taller
        self.reasons_text.setStyleSheet("background-color: #333333; border: 1px solid #555555;")
        summary_layout.addWidget(self.reasons_text)

        summary_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))


        # Details Tab (for Email)
        self.details_tab = QWidget()
        self.tab_widget.addTab(self.details_tab, "Email Details")
        details_layout = QVBoxLayout(self.details_tab)
        self.details_table = QTableWidget()
        self.details_table.setColumnCount(2)
        self.details_table.setHorizontalHeaderLabels(["Field", "Value"])
        self.details_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.details_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.details_table.verticalHeader().setVisible(False)
        self.details_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.details_table.setAlternatingRowColors(True)
        details_layout.addWidget(self.details_table)

        # Authentication Tab (for Email)
        self.auth_tab = QWidget()
        self.tab_widget.addTab(self.auth_tab, "Authentication")
        auth_layout = QVBoxLayout(self.auth_tab)
        self.auth_table = QTableWidget()
        self.auth_table.setColumnCount(2)
        self.auth_table.setHorizontalHeaderLabels(["Check", "Result"])
        self.auth_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.auth_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.auth_table.verticalHeader().setVisible(False)
        self.auth_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.auth_table.setAlternatingRowColors(True) # Enable for dark theme contrast
        auth_layout.addWidget(self.auth_table)
        self.alignment_label = QLabel("Alignment Details: N/A")
        auth_layout.addWidget(self.alignment_label)


        # Reputation Tab (for Email)
        self.reputation_tab = QWidget()
        self.tab_widget.addTab(self.reputation_tab, "Sender Reputation")
        rep_layout = QVBoxLayout(self.reputation_tab)
        self.reputation_table = QTableWidget()
        self.reputation_table.setColumnCount(2)
        self.reputation_table.setHorizontalHeaderLabels(["Source", "Details"])
        self.reputation_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.reputation_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.reputation_table.verticalHeader().setVisible(False)
        self.reputation_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.reputation_table.setAlternatingRowColors(True)
        rep_layout.addWidget(self.reputation_table)

        # URLs Tab
        self.urls_tab = QWidget()
        self.tab_widget.addTab(self.urls_tab, "URLs")
        urls_layout = QVBoxLayout(self.urls_tab)
        self.urls_table = QTableWidget()
        self.urls_table.setColumnCount(5)
        self.urls_table.setHorizontalHeaderLabels(["URL", "Domain", "Verdict", "Score", "Key Factors"])
        self.urls_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.urls_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.urls_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.urls_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.urls_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.urls_table.verticalHeader().setVisible(False)
        self.urls_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.urls_table.setAlternatingRowColors(True)
        urls_layout.addWidget(self.urls_table)

        # Attachments Tab (for Email)
        self.attachments_tab = QWidget()
        self.tab_widget.addTab(self.attachments_tab, "Attachments")
        attach_layout = QVBoxLayout(self.attachments_tab)
        self.attachments_table = QTableWidget()
        self.attachments_table.setColumnCount(4)
        self.attachments_table.setHorizontalHeaderLabels(["Filename", "Content Type", "Size (Bytes)", "Status"])
        self.attachments_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.attachments_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.attachments_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.attachments_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.attachments_table.verticalHeader().setVisible(False)
        self.attachments_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.attachments_table.setAlternatingRowColors(True)
        attach_layout.addWidget(self.attachments_table)

        # Content Analysis Tab
        self.content_tab = QWidget()
        self.tab_widget.addTab(self.content_tab, "Content Analysis")
        content_layout = QVBoxLayout(self.content_tab)
        self.content_score_label = QLabel("Content Score Contribution: N/A")
        self.content_indicators_text = QTextEdit()
        self.content_indicators_text.setReadOnly(True)
        self.content_indicators_text.setPlaceholderText("Content analysis indicators will appear here...")
        content_layout.addWidget(self.content_score_label)
        content_layout.addWidget(self.content_indicators_text, 1)


        # Initially disable irrelevant tabs
        self._set_email_tabs_enabled(False)
        self._set_url_tabs_enabled(False)
        self.tab_widget.setCurrentIndex(0)

        # --- Worker Thread Setup ---
        self.thread = None # Initialize thread attribute
        self.worker = None # Initialize worker attribute

        # --- Show Missing API Keys Warning ---
        if missing_keys:
            # Use a timer to show the message box *after* the main window is shown
            # to ensure the message box inherits the dark theme style.
            from PyQt5.QtCore import QTimer
            QTimer.singleShot(100, self.show_api_key_warning)

    def show_api_key_warning(self):
        """Shows the API key warning message box."""
        QMessageBox.warning(self, "API Key Warning",
                            f"The following API keys are missing or not configured:\n\n"
                            f"- {', '.join(missing_keys)}\n\n"
                            f"Please configure them (e.g., via environment variables or by editing the script) "
                            f"for full functionality. Checks requiring these keys may fail or be skipped.",
                            QMessageBox.Ok)

    def browse_email_file(self):
        """Opens a file dialog to select an .eml file."""
        options = QFileDialog.Options()
        # options |= QFileDialog.DontUseNativeDialog
        filePath, _ = QFileDialog.getOpenFileName(self, "Select Email File", "",
                                                  "Email Files (*.eml);;All Files (*)", options=options)
        if filePath:
            self.email_path_edit.setText(filePath)
            self.status_label.setText(f"Selected: {os.path.basename(filePath)}")
            self.clear_results()

    def start_email_analysis(self):
        """Initiates the email analysis in a worker thread."""
        file_path = self.email_path_edit.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Input Error", "Please select a valid email file (.eml) first.", QMessageBox.Ok)
            return
        if not file_path.lower().endswith(".eml"):
             QMessageBox.warning(self, "Input Error", "Please select a file with the .eml extension.", QMessageBox.Ok)
             return

        self._start_analysis('email', file_path)

    def start_url_analysis(self):
        """Initiates the URL analysis in a worker thread."""
        url = self.url_input_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to analyze.", QMessageBox.Ok)
            return
        if '.' not in url and not is_ip_address(url):
            QMessageBox.warning(self, "Input Error", "The entered text does not look like a valid URL or IP address.", QMessageBox.Ok)
            return

        self._start_analysis('url', url)

    def _start_analysis(self, analysis_type, input_data):
        """Common function to set up and start the worker thread."""
        # FIX: Check if self.thread exists *before* calling isRunning
        if self.thread is not None and self.thread.isRunning():
            QMessageBox.information(self, "Busy", "An analysis is already in progress. Please wait.", QMessageBox.Ok)
            return

        self.clear_results()
        self.set_ui_busy(True)
        self.status_label.setText(f"Starting {analysis_type} analysis...")
        self.progress_bar.setVisible(True)

        # Create and start the thread
        self.thread = QThread()
        self.worker = AnalysisWorker(analysis_type, input_data)
        self.worker.moveToThread(self.thread)

        # Connect signals
        self.worker.progress.connect(self.update_status)
        self.worker.error.connect(self.show_error_message)
        self.worker.finished.connect(self.handle_analysis_results)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        # Use a dedicated cleanup method for the thread
        self.thread.finished.connect(self.cleanup_thread) # Connect to cleanup method
        self.thread.finished.connect(self.thread.deleteLater) # Still schedule deletion

        self.thread.started.connect(self.worker.run)
        self.thread.start()

    # FIX: Add cleanup method to reset thread reference
    def cleanup_thread(self):
        """Cleans up after the thread finishes."""
        logger.debug("Worker thread finished, cleaning up references.")
        self.set_ui_busy(False)
        self.progress_bar.setVisible(False)
        # Set references to None to prevent accessing deleted C++ objects
        self.thread = None
        self.worker = None # Worker is already scheduled for deletion

    def set_ui_busy(self, busy):
        """Disables/Enables input widgets during analysis."""
        self.email_path_edit.setEnabled(not busy)
        self.browse_button.setEnabled(not busy)
        self.analyze_email_button.setEnabled(not busy)
        self.url_input_edit.setEnabled(not busy)
        self.analyze_url_button.setEnabled(not busy)
        # self.tab_widget.setEnabled(not busy) # Keep tabs enabled

    @pyqtSlot(str)
    def update_status(self, message):
        """Updates the status label."""
        self.status_label.setText(message)

    @pyqtSlot(str)
    def show_error_message(self, message):
        """Shows an error message box and updates status."""
        QMessageBox.critical(self, "Analysis Error", message, QMessageBox.Ok)
        self.status_label.setText("Analysis failed.")
        # Ensure UI is re-enabled even if thread doesn't finish cleanly after error
        # This might be redundant if cleanup_thread is always called, but safe to keep
        if self.thread is None: # Only call if cleanup hasn't run yet
             self.set_ui_busy(False)
             self.progress_bar.setVisible(False)


    @pyqtSlot(object)
    def handle_analysis_results(self, results):
        """Processes the results from the worker thread and updates the GUI."""
        self.status_label.setText("Processing results...")
        if results is None:
            # Status might already be set by show_error_message if an error occurred
            if not self.status_label.text().startswith("Analysis failed"):
                 self.status_label.setText("Analysis failed or returned no results.")
            return # Do not proceed if results are None

        try:
            analysis_type = results.get("type")
            if analysis_type == 'email':
                self.populate_email_results(results)
                self._set_email_tabs_enabled(True)
                self._set_url_tabs_enabled(True) # Keep URL tab enabled for email URLs
                self.tab_widget.setTabEnabled(6, True) # Ensure content tab is enabled
            elif analysis_type == 'url':
                self.populate_url_results(results)
                self._set_email_tabs_enabled(False) # Disable email-specific tabs
                self._set_url_tabs_enabled(True) # Enable URL-specific tabs
                self.tab_widget.setTabEnabled(6, True) # Ensure content tab is enabled (shows features)
            else:
                self.show_error_message(f"Received unknown result type: {analysis_type}")
                return

            self.status_label.setText("Analysis complete.")
            self.tab_widget.setCurrentIndex(0) # Switch to summary tab

        except Exception as e:
            logger.exception("Error populating GUI with results:")
            self.show_error_message(f"Error displaying results: {e}")


    def _set_email_tabs_enabled(self, enabled):
        """Enables/disables tabs relevant to email analysis."""
        email_tab_indices = [1, 2, 3, 5] # Indices for Details, Auth, Reputation, Attachments
        for index in email_tab_indices:
            if index < self.tab_widget.count(): # Check index validity
                self.tab_widget.setTabEnabled(index, enabled)

    def _set_url_tabs_enabled(self, enabled):
         """Enables/disables tabs relevant to URL analysis."""
         # URL tab index is 4
         url_tab_index = 4
         if url_tab_index < self.tab_widget.count(): # Check index validity
             self.tab_widget.setTabEnabled(url_tab_index, enabled)


    def clear_results(self):
        """Clears all result display widgets."""
        # Summary Tab
        self.verdict_label.setText("Verdict: N/A")
        self.verdict_label.setStyleSheet("background-color: #555555; color: #cccccc;") # Reset dark style
        self.score_label.setText("Overall Score: N/A")
        self.reasons_text.clear()

        # Other Tabs
        self.details_table.setRowCount(0)
        self.auth_table.setRowCount(0)
        self.alignment_label.setText("Alignment Details: N/A")
        self.reputation_table.setRowCount(0)
        self.urls_table.setRowCount(0)
        self.attachments_table.setRowCount(0)
        self.content_score_label.setText("Content Score Contribution: N/A")
        self.content_indicators_text.clear()
        self.content_indicators_text.setPlaceholderText("Content analysis indicators will appear here...")


        # Reset tab states - disable specific ones, keep Summary enabled
        self._set_email_tabs_enabled(False)
        self._set_url_tabs_enabled(False)
        self.tab_widget.setTabEnabled(6, False) # Disable content tab initially
        self.tab_widget.setCurrentIndex(0) # Go back to summary

        self.status_label.setText("Ready.")


    def _get_verdict_style(self, verdict):
        """Returns background and text color based on verdict for dark theme."""
        # Dark Theme Verdict Colors
        if verdict == "Phishing": return "#5c0000", "#ffdddd"
        elif verdict == "Highly Suspicious": return "#6b3d00", "#ffeacc"
        elif verdict == "Suspicious": return "#6b6b00", "#ffffdd"
        elif verdict == "Likely Legitimate": return "#225400", "#e6ffcc"
        elif verdict == "Legitimate": return "#004000", "#ccffcc"
        elif verdict == "Legitimate (Whitelisted)": return "#1a2c4d", "#d0e0ff"
        else: return "#555555", "#cccccc" # Default/Error

    def _colorize_table_item(self, value, threshold=None, is_verdict=False):
        """Creates a QTableWidgetItem with dark theme color coding."""
        item = QTableWidgetItem(str(value))
        item.setFlags(item.flags() ^ Qt.ItemIsEditable) # Make item read-only

        color = QColor("#dcdcdc") # Default light text
        bg_color = None

        if is_verdict:
             bg_color_hex, color_hex = self._get_verdict_style(str(value))
             if bg_color_hex: bg_color = QColor(bg_color_hex)
             if color_hex: color = QColor(color_hex)

        elif isinstance(value, str):
            val_lower = value.lower()
            # Dark Theme Status Colors
            if any(s in val_lower for s in ['fail', 'phishing', 'suspicious', 'misaligned', 'malicious', 'high risk', 'error', 'timeout']):
                color = QColor("#ff8080") # Light Red
            elif any(s in val_lower for s in ['pass', 'legitimate', 'safe', 'aligned', 'clean', 'ok']):
                color = QColor("#80ff80") # Light Green
            elif any(s in val_lower for s in ['unknown', 'pending', 'neutral', 'potentially', 'likely', 'no record', 'none', 'skipped']):
                color = QColor("#ffd780") # Light Orange/Yellow
        elif isinstance(value, (int, float)) and threshold is not None:
            if value >= threshold:
                color = QColor("#ff8080") # Light Red for scores/counts over threshold

        item.setForeground(color)
        if bg_color:
             item.setBackground(bg_color) # Set background for verdicts

        return item

    def populate_email_results(self, results):
        """Populates the GUI tabs with email analysis results (Dark Theme)."""
        # --- Summary Tab ---
        verdict = results.get("verdict", "Error")
        score = results.get("score", 0.0)
        reasons = results.get("score_reasons", [])
        bg_color, text_color = self._get_verdict_style(verdict)
        self.verdict_label.setText(f"Verdict: {verdict}")
        self.verdict_label.setStyleSheet(f"background-color: {bg_color}; color: {text_color}; border-radius: 6px; padding: 12px;") # Ensure style overrides stylesheet
        self.score_label.setText(f"Overall Score: {score:.2f} / 10.0")
        self.reasons_text.setText("\n".join(f"- {r}" for r in reasons))

        # --- Details Tab ---
        self.details_table.setRowCount(0)
        details_data = results.get("details", {})
        details_order = ["subject", "date", "sender_name", "sender_email", "sender_domain", "sender_ip", "reply_to", "return_path", "recipient"]
        for key in details_order:
            value = details_data.get(key, "N/A") # Get value or N/A
            if value is not None: # Ensure value is not None before adding row
                row_pos = self.details_table.rowCount()
                self.details_table.insertRow(row_pos)
                # Colorize specific fields like IP if needed
                field_item = self._colorize_table_item(key.replace('_', ' ').title())
                value_item = self._colorize_table_item(value, threshold=1 if key == 'sender_ip' and value != "Not found" else None)
                self.details_table.setItem(row_pos, 0, field_item)
                self.details_table.setItem(row_pos, 1, value_item)
        self.details_table.resizeRowsToContents()


        # --- Authentication Tab ---
        self.auth_table.setRowCount(0)
        auth_data = results.get("auth_results", {})
        auth_order = ["spf", "dkim", "dmarc"]
        for key in auth_order:
            row_pos = self.auth_table.rowCount()
            self.auth_table.insertRow(row_pos)
            self.auth_table.setItem(row_pos, 0, self._colorize_table_item(key.upper()))
            self.auth_table.setItem(row_pos, 1, self._colorize_table_item(auth_data.get(key, "N/A")))
        align_data = results.get("auth_alignment", {})
        align_status = "Aligned" if align_data.get("aligned", True) else "Misaligned"
        from_dom = align_data.get('from_domain', 'N/A')
        dkim_dom = align_data.get('dkim_domain', 'N/A')
        spf_dom = align_data.get('spf_domain', 'N/A')
        row_pos = self.auth_table.rowCount()
        self.auth_table.insertRow(row_pos)
        self.auth_table.setItem(row_pos, 0, self._colorize_table_item("Alignment"))
        self.auth_table.setItem(row_pos, 1, self._colorize_table_item(align_status))
        self.alignment_label.setText(f"Alignment Details: From=[{from_dom}], DKIM=[{dkim_dom}], SPF=[{spf_dom}]")
        self.auth_table.resizeRowsToContents()

        # --- Reputation Tab ---
        self.reputation_table.setRowCount(0)
        rep_data = results.get("reputation_results", {})
        # WHOIS
        whois_info = rep_data.get('whois')
        if isinstance(whois_info, dict):
            row_pos = self.reputation_table.rowCount()
            self.reputation_table.insertRow(row_pos)
            self.reputation_table.setItem(row_pos, 0, self._colorize_table_item("WHOIS"))
            if 'error' not in whois_info:
                created = whois_info.get('creation_date', 'N/A')
                created_display = created.split('T')[0] if created != 'N/A' else 'N/A'
                reg = whois_info.get('registrar', 'N/A')
                age_str = self._calculate_whois_age_str(created)
                rep_str = f"Created: {created_display}, Age: {age_str}, Registrar: {reg[:40]}{'...' if reg and len(reg)>40 else ''}"
                # Colorize age based on calculated string
                age_threshold = 1 if "days" in age_str or "months" in age_str or "Future" in age_str else None
                item = self._colorize_table_item(rep_str, threshold=age_threshold)
                self.reputation_table.setItem(row_pos, 1, item)
            else:
                self.reputation_table.setItem(row_pos, 1, self._colorize_table_item(f"Error: {whois_info.get('error')}", 1))
        # VT Domain
        vt_domain = rep_data.get('vt_domain')
        if isinstance(vt_domain, dict):
             row_pos = self.reputation_table.rowCount()
             self.reputation_table.insertRow(row_pos)
             self.reputation_table.setItem(row_pos, 0, self._colorize_table_item("VirusTotal Domain"))
             if 'error' not in vt_domain:
                  stats = vt_domain.get('last_analysis_stats', {})
                  mal = stats.get('malicious', 0)
                  susp = stats.get('suspicious', 0)
                  rep = vt_domain.get('reputation')
                  rep_str = f"Malicious: {mal}, Suspicious: {susp}, Harmless: {stats.get('harmless', 0)}"
                  if rep is not None: rep_str += f", Reputation: {rep}"
                  item = self._colorize_table_item(rep_str, threshold=1 if mal > 0 or susp > 0 else None)
                  self.reputation_table.setItem(row_pos, 1, item)
             else:
                  self.reputation_table.setItem(row_pos, 1, self._colorize_table_item(f"Error: {vt_domain.get('error')}", 1))
        # VT IP
        vt_ip = rep_data.get('vt_ip')
        if isinstance(vt_ip, dict):
             row_pos = self.reputation_table.rowCount()
             self.reputation_table.insertRow(row_pos)
             self.reputation_table.setItem(row_pos, 0, self._colorize_table_item("VirusTotal IP"))
             if 'error' not in vt_ip:
                  stats = vt_ip.get('last_analysis_stats', {})
                  mal = stats.get('malicious', 0)
                  susp = stats.get('suspicious', 0)
                  rep = vt_ip.get('reputation')
                  rep_str = f"Malicious: {mal}, Suspicious: {susp}, Harmless: {stats.get('harmless', 0)}"
                  if rep is not None: rep_str += f", Reputation: {rep}"
                  item = self._colorize_table_item(rep_str, threshold=1 if mal > 0 or susp > 0 else None)
                  self.reputation_table.setItem(row_pos, 1, item)
             else:
                  self.reputation_table.setItem(row_pos, 1, self._colorize_table_item(f"Error: {vt_ip.get('error')}", 1))
        # AbuseIPDB
        abuse = rep_data.get('abuseipdb')
        if isinstance(abuse, dict):
             row_pos = self.reputation_table.rowCount()
             self.reputation_table.insertRow(row_pos)
             self.reputation_table.setItem(row_pos, 0, self._colorize_table_item("AbuseIPDB"))
             if 'error' not in abuse:
                  score = abuse.get('abuseConfidenceScore', 0)
                  reports = abuse.get('totalReports', 0)
                  country = abuse.get('countryCode', 'N/A')
                  isp = abuse.get('isp', 'N/A')
                  rep_str = f"Score: {score}, Reports: {reports}, Country: {country}, ISP: {isp[:35]}{'...' if isp and len(isp)>35 else ''}"
                  item = self._colorize_table_item(rep_str, threshold=40 if score >= 40 else None) # Color if score >= 40
                  self.reputation_table.setItem(row_pos, 1, item)
             else:
                  self.reputation_table.setItem(row_pos, 1, self._colorize_table_item(f"Error: {abuse.get('error')}", 1))
        self.reputation_table.resizeRowsToContents()


        # --- URLs Tab ---
        self.urls_table.setRowCount(0)
        url_data = results.get("url_results", [])
        for url_res in url_data:
             if isinstance(url_res, dict):
                 row_pos = self.urls_table.rowCount()
                 self.urls_table.insertRow(row_pos)
                 full_url = url_res.get('url', 'N/A')
                 display_url = full_url[:100] + '...' if len(full_url) > 100 else full_url
                 reasons_list = url_res.get('reasons', [])
                 display_reasons = ', '.join([r.split(' (Score')[0] for r in reasons_list[:2]])
                 if len(reasons_list) > 2: display_reasons += '...'

                 self.urls_table.setItem(row_pos, 0, self._colorize_table_item(display_url))
                 self.urls_table.setItem(row_pos, 1, self._colorize_table_item(url_res.get('domain', 'N/A')))
                 self.urls_table.setItem(row_pos, 2, self._colorize_table_item(url_res.get('verdict', 'N/A'), is_verdict=True))
                 self.urls_table.setItem(row_pos, 3, self._colorize_table_item(f"{url_res.get('score', 0.0):.2f}", threshold=2.5))
                 self.urls_table.setItem(row_pos, 4, self._colorize_table_item(display_reasons))
        self.urls_table.resizeColumnsToContents() # Resize columns after populating
        self.urls_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch) # Re-apply stretch to URL column
        self.urls_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch) # Re-apply stretch to Reasons column


        # --- Attachments Tab ---
        self.attachments_table.setRowCount(0)
        attach_data = results.get("attachments", [])
        for att in attach_data:
             row_pos = self.attachments_table.rowCount()
             self.attachments_table.insertRow(row_pos)
             status = "High Risk" if att.get('high_risk') else ("Suspicious" if att.get('suspicious') else "OK")
             self.attachments_table.setItem(row_pos, 0, self._colorize_table_item(att.get('filename', 'N/A')))
             self.attachments_table.setItem(row_pos, 1, self._colorize_table_item(att.get('content_type', 'N/A')))
             self.attachments_table.setItem(row_pos, 2, self._colorize_table_item(att.get('size', 0)))
             self.attachments_table.setItem(row_pos, 3, self._colorize_table_item(status)) # Colorize status string
        self.attachments_table.resizeRowsToContents()
        self.attachments_table.resizeColumnsToContents() # Resize columns
        self.attachments_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch) # Stretch filename


        # --- Content Analysis Tab ---
        content_data = results.get("content_analysis", {})
        cont_score = content_data.get('score', 0)
        cont_indicators = content_data.get('indicators', [])
        self.content_score_label.setText(f"Content Score Contribution: {cont_score:.2f}")
        if cont_indicators:
            self.content_indicators_text.setText("Suspicious content indicators found:\n" + "\n".join(f"- {ind}" for ind in cont_indicators))
        else:
            self.content_indicators_text.setText("No major suspicious content indicators found.")


    def populate_url_results(self, results):
        """Populates the GUI tabs with URL analysis results (Dark Theme)."""
        url_analysis = results.get("analysis")
        if not url_analysis or not isinstance(url_analysis, dict):
             self.show_error_message("Invalid URL analysis result format received.")
             return

        # --- Summary Tab ---
        verdict = url_analysis.get("verdict", "Error")
        score = url_analysis.get("score", 0.0)
        reasons = url_analysis.get("reasons", [])
        bg_color, text_color = self._get_verdict_style(verdict)
        self.verdict_label.setText(f"Verdict: {verdict}")
        self.verdict_label.setStyleSheet(f"background-color: {bg_color}; color: {text_color}; border-radius: 6px; padding: 12px;")
        self.score_label.setText(f"Overall Score: {score:.2f} / 10.0")
        self.reasons_text.setText("\n".join(f"- {r}" for r in reasons))

        # --- URLs Tab (Display the single analyzed URL) ---
        self.urls_table.setRowCount(0)
        row_pos = self.urls_table.rowCount()
        self.urls_table.insertRow(row_pos)
        full_url = url_analysis.get('url', 'N/A')
        display_url = full_url[:100] + '...' if len(full_url) > 100 else full_url
        reasons_list = url_analysis.get('reasons', [])
        display_reasons = ', '.join([r.split(' (Score')[0] for r in reasons_list[:2]])
        if len(reasons_list) > 2: display_reasons += '...'

        self.urls_table.setItem(row_pos, 0, self._colorize_table_item(display_url))
        self.urls_table.setItem(row_pos, 1, self._colorize_table_item(url_analysis.get('domain', 'N/A')))
        self.urls_table.setItem(row_pos, 2, self._colorize_table_item(url_analysis.get('verdict', 'N/A'), is_verdict=True))
        self.urls_table.setItem(row_pos, 3, self._colorize_table_item(f"{url_analysis.get('score', 0.0):.2f}", threshold=2.5))
        self.urls_table.setItem(row_pos, 4, self._colorize_table_item(display_reasons))
        self.urls_table.resizeColumnsToContents() # Resize columns after populating
        self.urls_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch) # Re-apply stretch
        self.urls_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch) # Re-apply stretch


        # --- Content Analysis Tab (Show URL features) ---
        features = url_analysis.get("features", {})
        self.content_score_label.setText("URL Features:") # Relabel
        try:
             # Pretty print features JSON for readability
             features_text = json.dumps(features, indent=2)
        except TypeError as e:
             logger.error(f"Could not serialize URL features to JSON: {e}")
             features_text = str(features) # Fallback to string representation
        self.content_indicators_text.setText(features_text)

        # --- Clear/Disable other tabs ---
        self.details_table.setRowCount(0)
        self.auth_table.setRowCount(0)
        self.alignment_label.setText("Alignment Details: N/A")
        self.reputation_table.setRowCount(0)
        self.attachments_table.setRowCount(0)

    def _calculate_whois_age_str(self, creation_date_str):
        """Helper to calculate and format WHOIS age string."""
        if not creation_date_str or creation_date_str == 'N/A':
            return "N/A"
        try:
            # Handle potential list of dates from whois library
            if isinstance(creation_date_str, list):
                if not creation_date_str: return "N/A"
                creation_date_str = creation_date_str[0] # Take the first date
                if isinstance(creation_date_str, datetime): # If it's already datetime
                     creation_date = creation_date_str
                else: # Assume it's a string needing parsing
                     creation_date = datetime.fromisoformat(str(creation_date_str).replace('Z', '+00:00'))
            elif isinstance(creation_date_str, datetime):
                creation_date = creation_date_str
            else: # Assume string
                creation_date = datetime.fromisoformat(str(creation_date_str).replace('Z', '+00:00'))

            now = datetime.now(timezone.utc)
            if creation_date.tzinfo is None: creation_date = creation_date.replace(tzinfo=timezone.utc)

            if creation_date > now + timedelta(days=1): return "Future Date?"

            age_delta = now - creation_date
            age_days = age_delta.days

            if age_days < 0: return f"Future? ({age_days}d)"
            elif age_days < 31: return f"{age_days} days"
            elif age_days < 365 * 2 : return f"{age_days // 30} months"
            else: return f"{age_days // 365} years"
        except ValueError:
            logger.warning(f"Could not parse WHOIS date: {creation_date_str}")
            return "Invalid Date Format"
        except Exception as e:
            logger.error(f"Error calculating WHOIS age: {e}")
            return "Calculation Error"


# --- Main Execution ---
if __name__ == "__main__":
    # --- Dependency Check ---
    missing_deps = []
    try: import requests
    except ImportError: missing_deps.append("requests")
    try: import bs4 # BeautifulSoup4
    except ImportError: missing_deps.append("beautifulsoup4")
    try: import dns.resolver
    except ImportError: missing_deps.append("dnspython")
    # try: import whois # python-whois can be problematic, handle gracefully
    # except ImportError: missing_deps.append("python-whois")
    try: import tabulate
    except ImportError: missing_deps.append("tabulate")
    try: import PyQt5
    except ImportError: missing_deps.append("PyQt5")
    try: import html5lib
    except ImportError: missing_deps.append("html5lib")

    if missing_deps:
        print(f"Error: Missing required libraries: {', '.join(missing_deps)}")
        print("Please install them, for example:")
        print(f"  pip install {' '.join(missing_deps)}")
        # Attempt to install python-whois separately if missing, as it might fail
        if "python-whois" in missing_deps:
             print("  pip install python-whois")
        sys.exit(1)
    # Check for whois separately due to potential install issues
    # and because the placeholder now tries to import it
    try:
        import whois
    except ImportError:
        print("Warning: 'python-whois' library not found or failed to import.")
        print("WHOIS checks will likely fail. Try installing it: pip install python-whois")


    app = QApplication(sys.argv)

    # --- Apply Dark Theme Palette ---
    # Set a style that supports palettes well, like Fusion
    app.setStyle(QStyleFactory.create('Fusion'))

    # Create dark palette
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor(53, 53, 53)) # Slightly lighter than #2b2b2b for better contrast?
    dark_palette.setColor(QPalette.WindowText, Qt.white)
    dark_palette.setColor(QPalette.Base, QColor(42, 42, 42)) # Darker for text edits, lists
    dark_palette.setColor(QPalette.AlternateBase, QColor(66, 66, 66)) # Table alternating rows
    dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
    dark_palette.setColor(QPalette.ToolTipText, Qt.white)
    dark_palette.setColor(QPalette.Text, Qt.white)
    dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ButtonText, Qt.white)
    dark_palette.setColor(QPalette.BrightText, Qt.red)
    dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218)) # Selection highlight
    dark_palette.setColor(QPalette.HighlightedText, Qt.black)
    # Disabled state colors
    dark_palette.setColor(QPalette.Disabled, QPalette.Text, QColor(127, 127, 127))
    dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(127, 127, 127))
    dark_palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor(127, 127, 127))
    dark_palette.setColor(QPalette.Disabled, QPalette.Base, QColor(60, 60, 60))


    app.setPalette(dark_palette)
    # Set stylesheet AFTER palette for overrides and specific widget styling
    # The stylesheet defined in PhishiDetectorApp.__init__ will provide more detail

    main_window = PhishiDetectorApp()
    main_window.show()
    sys.exit(app.exec_())
