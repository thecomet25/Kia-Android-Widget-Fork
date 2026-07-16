import os
import copy
import logging
from functools import wraps
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask import Flask, request, jsonify

# NOTE: Custom DNS patching removed - the hyundai_kia_connect_api library v3.52.1+
# handles Cloudflare/IPv4 issues internally with its own socket patching
# NOTE: v4.0+ adds OTP/2FA support required as of 2026 by Kia Canada

# ── Constants ──
REGION_CODES = {
    1: "Europe",
    2: "Canada",
    3: "USA",
    4: "China",
    5: "Australia",
}
# Region codes: 1=Europe, 2=Canada, 3=USA, 4=China, 5=Australia
DEFAULT_REGION = 3 #USA
BRAND_KIA = 1
DEFAULT_BATTERY_CAPACITY_KWH = 84.0
CACHE_TTL_SECONDS = 30
MAX_REQUESTS_PER_MINUTE = 60

# ── Flask App Setup ──
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", os.urandom(24).hex())
app.config['JSON_SORT_KEYS'] = False

# ── Logging Configuration ──
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def _trimmed_env(name: str):
    raw = os.environ.get(name)
    if raw is None:
        return None

    trimmed = raw.strip()
    if trimmed != raw:
        logger.warning(f"{name} contained surrounding whitespace. Trimming it before use.")

    return trimmed or None


# ── Environment Variables ──
USERNAME = _trimmed_env('KIA_USERNAME')
PASSWORD = _trimmed_env('KIA_PASSWORD')
PIN = _trimmed_env('KIA_PIN')  # Keep as string to preserve leading zeros
SECRET_KEY = _trimmed_env("SECRET_KEY")
BATTERY_CAPACITY_KWH = float(os.environ.get("BATTERY_CAPACITY_KWH") or DEFAULT_BATTERY_CAPACITY_KWH)
region_env_raw = os.environ.get("KIA_REGION")
region_env = region_env_raw.strip() if region_env_raw else None
if region_env:
    try:
        REGION = int(region_env)
        if REGION not in REGION_CODES:
            raise ValueError
    except ValueError:
        raise ValueError(
            f"Invalid KIA_REGION '{region_env_raw}'. Valid options are: {sorted(REGION_CODES.keys())}"
        )
else:
    REGION = DEFAULT_REGION

# Debug: Log PIN length (not the actual PIN for security)
if PIN:
    logger.info(f"KIA_PIN length: {len(PIN)} characters")

# ── Global state ──
vehicle_manager = None
VEHICLE_ID = None
vehicle_state_cache = {
    "last_update": None,
    "data": None
}
rate_limit_store = {}

# ── OTP/2FA Support ──
# State tracking for OTP authentication process
otp_state = {
    "required": False,
    "sent": False,
    "verified": False,
    "error": None,
    "otp_request": None,  # Stores OTPRequest from library login (USA flow)
    "otpKey": None,  # OTP key from /mfa/sendotp (Canada flow)
    "userInfoUuid": None,  # User info UUID from /mfa/selverifmeth
    "mfaApiCode": "0107",  # Always "0107" for Canada
    "session": None,  # requests.Session to preserve cookies across MFA steps
    "headers": None,  # Headers used for MFA calls
    "rate_limited_until": 0,  # Timestamp: don't attempt login until this time
}

# ── Canada API Constants ──
_MFA_API_CODE = "0107"
_CANADA_API_BASE = "https://kiaconnect.ca/tods/api/"

# IMPORTANT: Use a STABLE device ID across all requests.
# Generating a random UUID per request makes Kia think each request is a new device,
# which triggers aggressive rate limiting (error 7901).
import hashlib as _hashlib
import uuid as _uuid
import base64 as _base64
_STABLE_DEVICE_ID_BASE = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36"
# Derive a stable UUID from the username so the device ID is consistent
_device_seed = os.environ.get("KIA_EMAIL", "") or os.environ.get("KIA_USERNAME", "") or "default"
_STABLE_DEVICE_UUID = str(_uuid.UUID(_hashlib.md5(_device_seed.encode()).hexdigest()))
_STABLE_DEVICE_ID = f"{_STABLE_DEVICE_ID_BASE}+{_STABLE_DEVICE_UUID}"

def _build_canada_headers():
    """Build headers matching the library's CCA API implementation."""
    return {
        'User-Agent': _STABLE_DEVICE_ID_BASE,
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-CA,en-US;q=0.8,en;q=0.5,fr;q=0.3',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Content-Type': 'application/json;charset=UTF-8',
        'from': 'CWP',
        'offset': '-5',
        'language': '0',
        'Origin': 'https://kiaconnect.ca',
        'Connection': 'keep-alive',
        'Referer': 'https://kiaconnect.ca/login',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Priority': 'u=0',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'client_id': 'HATAHSPACA0232141ED9722C67715A0B',
        'client_secret': 'CLISCR01AHSPA',
        'Deviceid': _base64.b64encode(_STABLE_DEVICE_ID.encode()).decode(),
    }

def manual_canada_send_otp(method="email"):
    """
    Steps 1-3 of Canada MFA flow.
    Based on PR #1033: https://github.com/Hyundai-Kia-Connect/hyundai_kia_connect_api/pull/1033

    Flow:
    1. Login → expect error 7110 (OTP required) OR success (device remembered)
    2. /mfa/selverifmeth → get userInfoUuid
    3. /mfa/sendotp → send OTP code, get otpKey

    Note: transactionId/xid is NOT used in MFA - data chains through request bodies.
    Session cookies ARE important and shared across all steps.
    """
    import requests
    import time

    # Use a session to preserve cookies across all MFA steps (CRITICAL!)
    session = requests.Session()
    headers = _build_canada_headers()

    logger.info(f"Using stable device UUID: {_STABLE_DEVICE_UUID}")

    current_time = time.time()

    # RATE LIMIT GUARD: If we recently got a 7901, refuse to hit the API.
    # This prevents us from resetting Kia's rate limit timer with every request.
    rate_limited_until = otp_state.get("rate_limited_until", 0)
    if current_time < rate_limited_until:
        wait_minutes = int((rate_limited_until - current_time) / 60) + 1
        raise Exception(
            f"Rate limit cooldown active. Do NOT retry for {wait_minutes} more minutes. "
            f"Each retry resets the timer! Just wait."
        )

    # ── Step 1: Login to trigger MFA (expect error 7110) ──
    logger.info("Step 1: Logging in to trigger MFA (expect error 7110)...")
    login_url = f"{_CANADA_API_BASE}v2/login"
    login_data = {
        "loginId": USERNAME,   # MUST be "loginId" not "userId" per library
        "password": PASSWORD,
    }

    # Single attempt - NO retries on 7901
    login_response = session.post(login_url, json=login_data, headers=headers, timeout=10)
    logger.info(f"Login response: {login_response.status_code}")

    if login_response.status_code != 200:
        raise Exception(f"Login failed with HTTP {login_response.status_code}")

    login_json = login_response.json()
    response_code = login_json.get("responseHeader", {}).get("responseCode")
    error_code = login_json.get("error", {}).get("errorCode")

    if response_code == 0:
        # Login succeeded WITHOUT OTP - device is remembered (within 90-day window)
        token_data = login_json.get("result", {}).get("token", {})
        logger.info("Login succeeded without OTP! Device is remembered.")
        otp_state["rate_limited_until"] = 0
        # Store tokens for use - no OTP flow needed
        return {
            "no_otp_needed": True,
            "token": token_data,
        }

    if error_code == "7901":
        # Rate limited - set 35-minute cooldown, do NOT retry
        cooldown_seconds = 35 * 60
        otp_state["rate_limited_until"] = current_time + cooldown_seconds
        cooldown_expires = time.strftime('%H:%M UTC', time.gmtime(current_time + cooldown_seconds))
        raise Exception(
            f"Rate limited (error 7901). Cooldown set for 35 minutes. "
            f"Do NOT retry until {cooldown_expires}. "
            f"Each login attempt resets the rate limit timer!"
        )

    if error_code != "7110":
        raise Exception(
            f"Expected error 7110 (OTP required) but got: "
            f"responseCode={response_code}, errorCode={error_code}, body={login_json}"
        )

    # Got error 7110 - OTP required, proceed to Step 2
    logger.info("Got error 7110 - OTP required. Proceeding to MFA flow...")
    otp_state["rate_limited_until"] = 0  # Clear any cooldown

    # ── Step 2: Select verification method → get userInfoUuid ──
    logger.info("Step 2: Calling /mfa/selverifmeth...")
    selverif_url = f"{_CANADA_API_BASE}mfa/selverifmeth"
    selverif_data = {
        "mfaApiCode": _MFA_API_CODE,
        "userAccount": USERNAME,
    }

    selverif_response = session.post(selverif_url, json=selverif_data, headers=headers, timeout=10)
    logger.info(f"selverifmeth response: {selverif_response.status_code}")
    selverif_json = selverif_response.json()
    logger.info(f"selverifmeth body: {str(selverif_json)[:500]}")

    if selverif_response.status_code != 200:
        raise Exception(f"selverifmeth failed: HTTP {selverif_response.status_code}")

    # Parse result wrapper (library format: response["result"]["userInfoUuid"])
    selverif_result = selverif_json.get("result", selverif_json)  # Fallback to root if no wrapper
    user_info_uuid = selverif_result.get("userInfoUuid")
    email_list = selverif_result.get("emailList", [])

    if not user_info_uuid:
        raise Exception(f"Missing userInfoUuid in response: {selverif_json}")

    logger.info(f"Got userInfoUuid: {user_info_uuid[:10]}..., emails: {email_list}")

    # ── Step 3: Send OTP ──
    logger.info(f"Step 3: Sending OTP via {method}...")
    sendotp_url = f"{_CANADA_API_BASE}mfa/sendotp"
    sendotp_data = {
        "otpMethod": "E" if method == "email" else "S",
        "mfaApiCode": _MFA_API_CODE,
        "userAccount": USERNAME,
        "userPhone": "",
        "userInfoUuid": user_info_uuid,
    }

    sendotp_response = session.post(sendotp_url, json=sendotp_data, headers=headers, timeout=10)
    logger.info(f"sendotp response: {sendotp_response.status_code}")
    sendotp_json = sendotp_response.json()
    logger.info(f"sendotp body: {str(sendotp_json)[:500]}")

    if sendotp_response.status_code != 200:
        raise Exception(f"sendotp failed: HTTP {sendotp_response.status_code}")

    # Parse result wrapper
    sendotp_result = sendotp_json.get("result", sendotp_json)
    otp_key = sendotp_result.get("otpKey")

    if not otp_key:
        raise Exception(f"Missing otpKey in response: {sendotp_json}")

    logger.info(f"OTP sent! otpKey: {otp_key[:20]}...")

    # Store state for verify step (shared session preserves cookies!)
    otp_state["otpKey"] = otp_key
    otp_state["userInfoUuid"] = user_info_uuid
    otp_state["session"] = session    # Preserve cookies for Steps 4-5
    otp_state["headers"] = headers    # Preserve headers for Steps 4-5

    return sendotp_json

def manual_canada_verify_otp(otp_code):
    """
    Steps 4-5 of Canada MFA flow.
    Based on PR #1033: https://github.com/Hyundai-Kia-Connect/hyundai_kia_connect_api/pull/1033

    Flow:
    4. /mfa/validateotp → validate code, get otpValidationKey
    5. /mfa/genmfatkn → generate tokens (accessToken, refreshToken in BODY)

    Returns (access_token, refresh_token, expire_in) tuple on success.

    Note: Does NOT require VehicleManager. Uses stored session from send_otp.
    """
    import requests

    if not otp_state.get("otpKey"):
        raise Exception("Missing otpKey. Call /otp/send first.")

    # Reuse session from send_otp if available (preserves cookies from Steps 1-3)
    session = otp_state.get("session") or requests.Session()
    headers = otp_state.get("headers") or _build_canada_headers()

    # ── Step 4: Validate OTP code ──
    logger.info("Step 4: Validating OTP with /mfa/validateotp...")
    validateotp_url = f"{_CANADA_API_BASE}mfa/validateotp"
    validateotp_data = {
        "otpNo": otp_code,           # MUST be "otpNo" not "otpValue" per library
        "otpKey": otp_state["otpKey"],
        "userAccount": USERNAME,
        "mfaApiCode": _MFA_API_CODE,  # Required: "0107" for Canada
    }

    validate_response = session.post(validateotp_url, json=validateotp_data, headers=headers, timeout=10)
    logger.info(f"validateotp response: {validate_response.status_code}")
    validate_json = validate_response.json()
    logger.info(f"validateotp body: {str(validate_json)[:500]}")

    if validate_response.status_code != 200:
        raise Exception(f"validateotp failed: HTTP {validate_response.status_code}")

    # Parse result wrapper
    validate_result = validate_json.get("result", validate_json)

    # Check for errors in response
    resp_code = validate_json.get("responseHeader", {}).get("responseCode")
    if resp_code == 1:
        error_info = validate_json.get("error", {})
        raise Exception(f"OTP validation failed: {error_info}")

    otp_validation_key = validate_result.get("otpValidationKey")
    verified = validate_result.get("verifiedOtp", False)

    if not otp_validation_key:
        raise Exception(f"Missing otpValidationKey in response: {validate_json}")

    logger.info(f"OTP validated! verifiedOtp={verified}, key: {otp_validation_key[:20]}...")

    # ── Step 5: Generate MFA tokens ──
    logger.info("Step 5: Generating tokens with /mfa/genmfatkn...")
    genmfatkn_url = f"{_CANADA_API_BASE}mfa/genmfatkn"
    genmfatkn_data = {
        "otpValidationKey": otp_validation_key,
        "mfaYn": "Y",              # Remember device for 90 days
        "mfaApiCode": _MFA_API_CODE,
        "userAccount": USERNAME,
        "otpEmail": USERNAME,      # Email address where OTP was sent
    }

    token_response = session.post(genmfatkn_url, json=genmfatkn_data, headers=headers, timeout=10)
    logger.info(f"genmfatkn response: {token_response.status_code}")
    token_json = token_response.json()
    logger.info(f"genmfatkn body: {str(token_json)[:500]}")

    if token_response.status_code != 200:
        raise Exception(f"genmfatkn failed: HTTP {token_response.status_code}")

    # Check for API-level error (e.g. 7725 = missing required fields)
    if token_json.get("responseHeader", {}).get("responseCode") == 1:
        error_info = token_json.get("error", {})
        raise Exception(f"genmfatkn failed: {error_info}")

    # Tokens come from response BODY (result.token), NOT from headers!
    token_result = token_json.get("result", token_json)
    token_data = token_result.get("token", {})
    access_token = token_data.get("accessToken")
    refresh_token = token_data.get("refreshToken")
    expire_in = token_data.get("expireIn", 86400)

    if not access_token or not refresh_token:
        raise Exception(f"Missing tokens in response body: {token_json}")

    logger.info(f"Tokens generated! accessToken: {access_token[:20]}..., expireIn: {expire_in}s")
    return access_token, refresh_token, expire_in

def _setup_vehicle_manager_with_token(access_token, refresh_token, expire_in=86400):
    """
    Create VehicleManager and set token from manual MFA flow.
    Called after successful OTP verification or when device is remembered.
    Does NOT call login() - we already have tokens.
    """
    global vehicle_manager, VEHICLE_ID
    from hyundai_kia_connect_api import VehicleManager
    from datetime import datetime, timezone, timedelta

    logger.info("Setting up VehicleManager with obtained tokens...")

    vehicle_manager = VehicleManager(
        region=REGION,
        brand=BRAND_KIA,
        username=USERNAME,
        password=PASSWORD,
        pin=str(PIN),
    )

    # Create Token and assign it - skip login entirely
    try:
        from hyundai_kia_connect_api.ApiImpl import Token
        token = Token(
            username=USERNAME,
            password=PASSWORD,
            access_token=access_token,
            refresh_token=refresh_token,
            valid_until=datetime.now(timezone.utc) + timedelta(seconds=expire_in),
            device_id=getattr(vehicle_manager.api, 'device_id', _STABLE_DEVICE_UUID),
            pin=PIN,
        )
        vehicle_manager.token = token
        logger.info(f"Token set on VehicleManager (expires in {expire_in}s)")
    except Exception as token_err:
        logger.error(f"Failed to create Token object: {token_err}")
        # Try setting access token directly on the API as fallback
        if hasattr(vehicle_manager, 'api') and hasattr(vehicle_manager.api, 'API_HEADERS'):
            vehicle_manager.api.API_HEADERS["accessToken"] = access_token
            logger.info("Set accessToken directly on API headers as fallback")

    # Fetch vehicle list (must be done before update - login() normally does this)
    try:
        logger.info("Fetching vehicle list after token setup...")
        vehicle_manager.initialize_vehicles()
        if vehicle_manager.vehicles:
            logger.info(f"Found {len(vehicle_manager.vehicles)} vehicle(s)")
            if VEHICLE_ID is None:
                env_vid = os.environ.get("VEHICLE_ID", "").strip()
                VEHICLE_ID = env_vid if env_vid else next(iter(vehicle_manager.vehicles.keys()))
                logger.info(f"VEHICLE_ID set to: {VEHICLE_ID}")
        else:
            logger.warning("No vehicles found after token setup")
    except Exception as init_err:
        logger.error(f"Failed to fetch vehicles: {init_err}", exc_info=True)

    # Update vehicle state (cached)
    try:
        logger.info("Updating vehicle state...")
        vehicle_manager.update_all_vehicles_with_cached_state()
    except Exception as update_err:
        logger.error(f"Failed to update vehicles: {update_err}", exc_info=True)


def init_vehicle_manager():
    """Initialize vehicle manager lazily on first request."""
    global vehicle_manager, VEHICLE_ID

    # If already initialized, return success
    if vehicle_manager is not None and VEHICLE_ID is not None:
        return True

    # If vehicle_manager exists but VEHICLE_ID is None, force re-initialization
    if vehicle_manager is not None and VEHICLE_ID is None:
        logger.warning("Vehicle manager exists but VEHICLE_ID is None. Forcing re-initialization...")
        vehicle_manager = None

    # Check credentials first
    if USERNAME is None or PASSWORD is None or PIN is None:
        logger.error("Missing credentials! Check KIA_USERNAME, KIA_PASSWORD, and KIA_PIN environment variables.")
        return False

    if not SECRET_KEY:
        logger.error("Missing SECRET_KEY environment variable.")
        return False

    try:
        # Initialize using VehicleManager exactly like working main.py
        if vehicle_manager is None:
            from hyundai_kia_connect_api import VehicleManager
            from hyundai_kia_connect_api.exceptions import AuthenticationError
            from hyundai_kia_connect_api.ApiImpl import OTPRequest, OTP_NOTIFY_TYPE
            import hyundai_kia_connect_api

            # Log library version for debugging
            lib_version = getattr(hyundai_kia_connect_api, '__version__', 'unknown')
            logger.info(f"hyundai_kia_connect_api version: {lib_version}")

            logger.info(
                f"Initializing Vehicle Manager (Region: {REGION} ({REGION_CODES.get(REGION, 'Unknown')}), "
                f"Brand: {BRAND_KIA})..."
            )
            logger.info(f"Using PIN with length: {len(PIN)} characters")

            vehicle_manager = VehicleManager(
                region=REGION,
                brand=BRAND_KIA,
                username=USERNAME,
                password=PASSWORD,
                pin=str(PIN)
                # NOTE: otp_handler is NOT a constructor parameter in v4.4.0
                # OTP is handled via send_otp() and verify_otp() methods
            )

            logger.info("Attempting to authenticate using manual device-trust login...")

            # Use manual Canada MFA flow with device trust - same as /otp/send
            # This allows device recognition to work, avoiding OTP when possible
            try:
                import requests
                import time

                session = requests.Session()
                headers = _build_canada_headers()

                logger.info(f"Using stable device UUID: {_STABLE_DEVICE_UUID}")

                # Check rate limit cooldown
                current_time = time.time()
                rate_limited_until = otp_state.get("rate_limited_until", 0)
                if current_time < rate_limited_until:
                    wait_minutes = int((rate_limited_until - current_time) / 60) + 1
                    logger.error(
                        f"Rate limit cooldown active. Wait {wait_minutes} more minutes. "
                        f"Use POST /otp/send when cooldown expires."
                    )
                    otp_state["required"] = True
                    otp_state["verified"] = False
                    return True

                # Step 1: Login with device trust params
                login_url = f"{_CANADA_API_BASE}v2/login"
                login_data = {
                    "loginId": USERNAME,
                    "password": PASSWORD,
                    "mfaYn": "Y",  # Enable device trust
                }

                login_response = session.post(login_url, json=login_data, headers=headers, timeout=10)
                logger.info(f"Manual login response: {login_response.status_code}")

                if login_response.status_code != 200:
                    raise Exception(f"Login failed with HTTP {login_response.status_code}")

                login_json = login_response.json()
                response_code = login_json.get("responseHeader", {}).get("responseCode")
                error_code = login_json.get("error", {}).get("errorCode")

                if response_code == 0:
                    # SUCCESS: Device is remembered! Set up token and continue.
                    token_data = login_json.get("result", {}).get("token", {})
                    logger.info("✓ Device is remembered - login succeeded without OTP!")
                    otp_state["rate_limited_until"] = 0
                    otp_state["required"] = False
                    otp_state["verified"] = True

                    # Set up token on the already-created VehicleManager
                    access_token = token_data.get("accessToken")
                    refresh_token = token_data.get("refreshToken")
                    expire_in = token_data.get("expireIn", 86400)

                    if not access_token or not refresh_token:
                        raise Exception(f"Missing tokens in response: {login_json}")

                    # Create Token and assign it
                    try:
                        from hyundai_kia_connect_api.ApiImpl import Token
                        from datetime import datetime, timezone, timedelta
                        token = Token(
                            username=USERNAME,
                            password=PASSWORD,
                            access_token=access_token,
                            refresh_token=refresh_token,
                            valid_until=datetime.now(timezone.utc) + timedelta(seconds=expire_in),
                            device_id=getattr(vehicle_manager.api, 'device_id', _STABLE_DEVICE_UUID),
                            pin=PIN,
                        )
                        vehicle_manager.token = token
                        logger.info(f"Token set on VehicleManager (expires in {expire_in}s)")
                    except Exception as token_err:
                        logger.error(f"Failed to create Token object: {token_err}")
                        # Fallback: set access token directly
                        if hasattr(vehicle_manager, 'api') and hasattr(vehicle_manager.api, 'API_HEADERS'):
                            vehicle_manager.api.API_HEADERS["accessToken"] = access_token
                            logger.info("Set accessToken directly on API headers as fallback")

                    # Now that we have a token, initialize vehicles
                    # (This is normally done by login() in the library)
                    logger.info("Fetching vehicle list after manual login...")
                    try:
                        vehicle_manager.initialize_vehicles()
                        if vehicle_manager.vehicles:
                            logger.info(f"Found {len(vehicle_manager.vehicles)} vehicle(s)")
                        else:
                            logger.warning("No vehicles found after initialization")
                    except Exception as init_err:
                        logger.error(f"Failed to fetch vehicles: {init_err}", exc_info=True)

                elif error_code == "7901":
                    # Rate limited - set 35-minute cooldown
                    cooldown_seconds = 35 * 60
                    otp_state["rate_limited_until"] = current_time + cooldown_seconds
                    cooldown_expires = time.strftime('%H:%M UTC', time.gmtime(current_time + cooldown_seconds))
                    logger.error(
                        f"Rate limited (error 7901). Cooldown set for 35 minutes until {cooldown_expires}. "
                        f"Use POST /otp/send when cooldown expires."
                    )
                    otp_state["required"] = True
                    otp_state["verified"] = False
                    return True

                elif error_code == "7110":
                    # OTP required - device not remembered
                    logger.warning("OTP required (error 7110). Device not in 90-day trust window.")
                    otp_state["rate_limited_until"] = 0
                    otp_state["required"] = True
                    otp_state["verified"] = False
                    otp_state["error"] = "OTP required - call POST /otp/send to start authentication"
                    logger.info("Use POST /otp/send to start manual MFA flow.")
                    return True

                else:
                    # Unexpected error
                    raise Exception(
                        f"Unexpected login response: responseCode={response_code}, errorCode={error_code}, body={login_json}"
                    )

            except Exception as auth_error:
                logger.error(f"Authentication error: {auth_error}")
                otp_state["error"] = str(auth_error)
                otp_state["required"] = True
                otp_state["verified"] = False
                logger.warning(
                    "Auth failed. Use POST /otp/send to start manual MFA flow if OTP is required."
                )
                return True

            logger.info("Updating vehicle states...")
            try:
                # Log before the call
                logger.info("Calling update_all_vehicles_with_cached_state()...")
                vehicle_manager.update_all_vehicles_with_cached_state()

                # Log the raw vehicles dict
                logger.info(f"Raw vehicles dict: {vehicle_manager.vehicles}")
                logger.info(f"Vehicles dict type: {type(vehicle_manager.vehicles)}")
                logger.info(f"Vehicles dict keys: {list(vehicle_manager.vehicles.keys()) if vehicle_manager.vehicles else 'EMPTY'}")
                logger.info(f"Connected! Found {len(vehicle_manager.vehicles)} vehicle(s).")
            except Exception as update_error:
                logger.error(f"Error during update_all_vehicles_with_cached_state: {update_error}", exc_info=True)
                raise

            if not vehicle_manager.vehicles:
                logger.error("No vehicles found in the account.")
                return False

            # Log vehicle details
            for vid, vehicle in vehicle_manager.vehicles.items():
                logger.info(f"Vehicle - ID: {vid}, Name: {vehicle.name}, Model: {vehicle.model}")

        # Set VEHICLE_ID if not already set
        if VEHICLE_ID is None:
            env_vehicle_id = os.environ.get("VEHICLE_ID", "").strip()
            if env_vehicle_id:
                VEHICLE_ID = env_vehicle_id
                logger.info(f"Using VEHICLE_ID from environment: {VEHICLE_ID}")
            else:
                if not vehicle_manager.vehicles:
                    logger.error("No vehicles found in the account.")
                    return False
                VEHICLE_ID = next(iter(vehicle_manager.vehicles.keys()))
                logger.info(f"No VEHICLE_ID provided. Auto-detected first vehicle: {VEHICLE_ID}")

        return True
    except Exception as e:
        logger.error(f"Failed to initialize vehicle manager: {e}")
        vehicle_manager = None
        VEHICLE_ID = None
        import traceback
        traceback.print_exc()
        return False

def get_cached_vehicle_state():
    """Get vehicle state with caching."""
    if vehicle_manager is None:
        raise RuntimeError("Vehicle manager not initialized")

    if VEHICLE_ID is None:
        raise RuntimeError("VEHICLE_ID not set")

    now = datetime.now()
    if (vehicle_state_cache["last_update"] is None or
        (now - vehicle_state_cache["last_update"]).total_seconds() > CACHE_TTL_SECONDS):
        logger.info("Cache expired or empty, refreshing vehicle states...")
        vehicle_manager.update_all_vehicles_with_cached_state()
        vehicle_state_cache["last_update"] = now

    logger.info(f"Getting vehicle with ID: {VEHICLE_ID}")
    return vehicle_manager.get_vehicle(VEHICLE_ID)

def check_rate_limit(client_id: str, max_requests: int = MAX_REQUESTS_PER_MINUTE) -> bool:
    """Simple rate limiting check."""
    now = datetime.now()
    minute_ago = now - timedelta(minutes=1)

    # Clean old entries
    rate_limit_store[client_id] = [
        ts for ts in rate_limit_store.get(client_id, []) if ts > minute_ago
    ]

    # Check limit
    if len(rate_limit_store.get(client_id, [])) >= max_requests:
        return False

    # Add current request
    if client_id not in rate_limit_store:
        rate_limit_store[client_id] = []
    rate_limit_store[client_id].append(now)

    return True

def refresh_token_if_needed():
    """Refresh token if needed."""
    if vehicle_manager is None:
        return
    try:
        vehicle_manager.check_and_refresh_token()
    except Exception as e:
        logger.warning(f"Token refresh check failed: {e}")

def require_auth(f):
    """Decorator to require authorization header and verified OTP."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not init_vehicle_manager():
            return jsonify({"error": "Service initialization failed"}), 503

        # Block vehicle actions if OTP is required but not yet verified
        if otp_state.get("required") and not otp_state.get("verified"):
            logger.warning(f"Request to {request.path} blocked: OTP not verified")
            return jsonify({
                "error": "OTP verification required before vehicle commands. Use POST /otp/send to start.",
                "otp_required": True
            }), 401

        # Block if VEHICLE_ID was never set (auth failed, no vehicles loaded)
        if VEHICLE_ID is None:
            logger.warning(f"Request to {request.path} blocked: VEHICLE_ID is None")
            return jsonify({"error": "Vehicle not initialized. Authentication may have failed."}), 503

        auth_header = request.headers.get("Authorization")
        if auth_header != SECRET_KEY:
            logger.warning(f"Unauthorized request to {request.path} from {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}), 403

        # Rate limiting
        client_id = request.remote_addr
        if not check_rate_limit(client_id):
            logger.warning(f"Rate limit exceeded for {client_id}")
            return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

        return f(*args, **kwargs)
    return decorated

# ── Request Logging ──
@app.before_request
def log_request_info():
    logger.info(f"Incoming request: {request.method} {request.url} from {request.remote_addr}")

# ── Health Check Endpoint ──
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for monitoring.
    Does NOT trigger login/init - just reports current state.
    """
    is_initialized = vehicle_manager is not None and VEHICLE_ID is not None
    otp_needed = otp_state.get("required", False) and not otp_state.get("verified", False)

    response = {
        "status": "healthy" if is_initialized else ("otp_required" if otp_needed else "not_initialized"),
        "timestamp": datetime.now(ZoneInfo("America/Toronto")).isoformat(),
        "vehicles_count": len(vehicle_manager.vehicles) if vehicle_manager and vehicle_manager.vehicles else 0,
        "vehicle_manager_initialized": vehicle_manager is not None,
        "vehicle_id_set": VEHICLE_ID is not None,
        "otp_required": otp_needed,
        "otp_verified": otp_state.get("verified", False),
    }

    if is_initialized and vehicle_manager and vehicle_manager.vehicles:
        response["vehicles"] = list(vehicle_manager.vehicles.keys())

    return jsonify(response), 200

# ── Root Endpoint ──
@app.route('/', methods=['GET'])
def root():
    """Root endpoint."""
    return jsonify({"status": "Welcome to the Kia Vehicle Control API"}), 200

# ── Diagnostic Endpoint ──
@app.route('/diagnostics', methods=['GET'])
def diagnostics():
    """Diagnostic endpoint to check environment configuration (no auth required)."""
    region_names = {1: "Europe", 2: "Canada", 3: "USA", 4: "China", 5: "Australia"}

    # Check credential format issues
    credential_warnings = []
    if USERNAME and ('@' not in USERNAME):
        credential_warnings.append("KIA_USERNAME should be an email address")

    pin_length = len(PIN) if PIN else 0
    if PIN and pin_length != 4:
        credential_warnings.append(f"KIA_PIN should be 4 digits, got length: {pin_length}")

    # Add info about PIN length to help debug
    pin_info = {
        "length": pin_length,
        "starts_with_zero": PIN.startswith('0') if PIN else False
    }

    return jsonify({
        "env_vars_set": {
            "KIA_USERNAME": USERNAME is not None and USERNAME != "",
            "KIA_PASSWORD": PASSWORD is not None and PASSWORD != "",
            "KIA_PIN": PIN is not None and PIN != "",
            "SECRET_KEY": SECRET_KEY is not None and SECRET_KEY != "",
            "VEHICLE_ID": os.environ.get("VEHICLE_ID", "") != "",
            "BATTERY_CAPACITY_KWH": os.environ.get("BATTERY_CAPACITY_KWH", "") != "",
            "KIA_REGION": os.environ.get("KIA_REGION", "") != ""
        },
        "configuration": {
            "region_code": REGION,
            "region_name": region_names.get(REGION, "Unknown"),
            "battery_capacity_kwh": BATTERY_CAPACITY_KWH,
            "brand": BRAND_KIA
        },
        "pin_info": pin_info,
        "global_state": {
            "vehicle_manager_initialized": vehicle_manager is not None,
            "vehicle_id_set": VEHICLE_ID is not None,
            "vehicle_id_value": VEHICLE_ID if VEHICLE_ID else None
        },
        "warnings": credential_warnings if credential_warnings else None
    }), 200

# ── OTP Endpoints (for 2FA authentication) ──
@app.route('/otp/send', methods=['POST'])
def send_otp():
    """
    Request OTP to be sent via email.
    Does NOT require VehicleManager for Canada - uses manual MFA flow.

    Body: {"method": "email"}
    Note: Canada only supports email OTP, not SMS.
    """
    global vehicle_manager

    data = request.get_json() or {}
    method = data.get("method", "email").lower()

    if method not in ["sms", "email"]:
        return jsonify({"error": "Method must be 'sms' or 'email'"}), 400

    try:
        logger.info(f"Requesting OTP via {method}...")

        # Check if we have library OTPRequest (USA) or need manual Canada flow
        if otp_state.get("otp_request") is not None:
            # USA region - use library's OTP support (requires VehicleManager)
            if vehicle_manager is None:
                logger.info("VehicleManager not initialized, initializing now...")
                if not init_vehicle_manager():
                    return jsonify({"error": "Failed to initialize vehicle manager"}), 503

            from hyundai_kia_connect_api.ApiImpl import OTP_NOTIFY_TYPE
            notify_type = OTP_NOTIFY_TYPE.EMAIL if method == "email" else OTP_NOTIFY_TYPE.SMS

            logger.info(f"Using USA OTP flow - otp_key: {otp_state['otp_request'].otp_key[:10]}...")
            result = vehicle_manager.api.send_otp(otp_state["otp_request"], notify_type)
            logger.info(f"send_otp() returned: {result}")

        else:
            # Canada region - use manual MFA flow (NO VehicleManager needed!)
            logger.info("Using manual Canada MFA flow (no VehicleManager init needed)...")
            result = manual_canada_send_otp(method)

            # Handle case where device is remembered (no OTP needed)
            if isinstance(result, dict) and result.get("no_otp_needed"):
                logger.info("Device is remembered - no OTP needed! Setting up tokens...")
                token_data = result.get("token", {})
                # Initialize vehicle manager with these tokens
                _setup_vehicle_manager_with_token(
                    token_data.get("accessToken"),
                    token_data.get("refreshToken"),
                    token_data.get("expireIn", 86400),
                )
                otp_state["verified"] = True
                otp_state["required"] = False
                return jsonify({
                    "status": "authenticated",
                    "message": "Device remembered - no OTP needed. API is ready to use.",
                    "region": "Canada (manual)",
                }), 200

            logger.info(f"Manual send_otp() returned: {str(result)[:200]}")

        otp_state["sent"] = True
        otp_state["required"] = True

        return jsonify({
            "status": "OTP sent",
            "method": method,
            "message": f"Check your {method} for the OTP code, then call POST /otp/verify with {{\"otp\": \"123456\"}}",
            "region": "USA (library)" if otp_state.get("otp_request") else "Canada (manual)",
        }), 200
    except Exception as e:
        logger.error(f"Failed to send OTP: {e}", exc_info=True)
        otp_state["error"] = str(e)
        return jsonify({"error": str(e), "type": type(e).__name__}), 500

@app.route('/otp/verify', methods=['POST'])
def verify_otp():
    """
    Verify the OTP code you received.

    Body: {"otp": "123456"}
    """
    global vehicle_manager

    data = request.get_json() or {}
    otp = data.get("otp", "").strip()

    if not otp:
        return jsonify({"error": "Missing 'otp' in request body"}), 400

    if not otp.isdigit():
        return jsonify({"error": "OTP must be numeric"}), 400

    try:
        logger.info(f"Verifying OTP code (length: {len(otp)})...")

        # Check if we have library OTPRequest (USA) or manual Canada OTP context
        if otp_state.get("otp_request") is not None:
            # USA region - use library's OTP support (requires VehicleManager)
            if vehicle_manager is None:
                logger.info("VehicleManager not initialized, initializing now...")
                if not init_vehicle_manager():
                    return jsonify({"error": "Failed to initialize vehicle manager"}), 503

            logger.info("Using USA OTP verification flow...")
            token = vehicle_manager.api.verify_otp_and_complete_login(
                username=USERNAME,
                password=PASSWORD,
                otp_code=otp,
                otp_request=otp_state["otp_request"],
                pin=PIN
            )
            logger.info(f"OTP verification successful! Token: {token.access_token[:20]}...")
            vehicle_manager.token = token

        elif otp_state.get("otpKey"):
            # Canada region - manual MFA verification (Steps 4-5)
            # Does NOT need VehicleManager - uses stored session from send_otp
            logger.info("Using manual Canada MFA verification flow...")
            access_token, refresh_token, expire_in = manual_canada_verify_otp(otp)
            logger.info(f"OTP verified! accessToken: {access_token[:20]}...")

            # Now set up VehicleManager with the obtained tokens
            _setup_vehicle_manager_with_token(access_token, refresh_token, expire_in)

        else:
            return jsonify({"error": "No OTP context available. Call /otp/send first."}), 400

        otp_state["verified"] = True
        otp_state["required"] = False
        otp_state["otp_request"] = None
        otp_state["otpKey"] = None
        otp_state["session"] = None
        otp_state["headers"] = None

        vehicles_found = 0
        if vehicle_manager and vehicle_manager.vehicles:
            vehicles_found = len(vehicle_manager.vehicles)

        return jsonify({
            "status": "OTP verified",
            "message": "Authentication complete. You can now use the API normally.",
            "vehicles_found": vehicles_found,
        }), 200
    except Exception as e:
        logger.error(f"Failed to verify OTP: {e}", exc_info=True)
        otp_state["error"] = str(e)
        return jsonify({"error": str(e), "type": type(e).__name__}), 500

@app.route('/otp/status', methods=['GET'])
def otp_status():
    """Check OTP authentication status."""
    return jsonify({
        "otp_required": otp_state["required"],
        "otp_sent": otp_state["sent"],
        "otp_verified": otp_state["verified"],
        "error": otp_state["error"],
        "vehicle_manager_initialized": vehicle_manager is not None,
        "instructions": "If OTP required: 1) POST /otp/send, 2) Check SMS/email, 3) POST /otp/verify with code"
    }), 200

# ── List Vehicles Endpoint ──
@app.route('/list_vehicles', methods=['GET'])
@require_auth
def list_vehicles():
    """List all vehicles in the account."""
    logger.info("Received request to /list_vehicles")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

        vehicles = vehicle_manager.vehicles

        if not vehicles:
            logger.warning("No vehicles found in the account")
            return jsonify({"error": "No vehicles found"}), 404

        vehicle_list = [
            {
                "name": v.name,
                "id": v.id,
                "model": v.model,
                "year": v.year
            }
            for v in vehicles.values()
        ]

        if not vehicle_list:
            logger.warning("No valid vehicles found in the account")
            return jsonify({"error": "No valid vehicles found"}), 404

        logger.info(f"Returning vehicle list: {vehicle_list}")
        return jsonify({"status": "Success", "vehicles": vehicle_list}), 200
    except Exception as e:
        logger.error(f"Error in /list_vehicles: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Vehicle Status Endpoint ──
@app.route('/status', methods=['POST'])
@require_auth
def vehicle_status():
    """Get current vehicle status."""
    logger.info("Received request to /status")

    try:
        refresh_token_if_needed()
        vehicle = get_cached_vehicle_state()

        pct = vehicle.ev_battery_percentage
        dur = vehicle.ev_estimated_current_charge_duration
        charging = bool(vehicle.ev_battery_is_charging)

        # ── Plug type detection ──
        # 0 = not plugged, 1 = DC (fast), 2 = AC (Level 2/portable)
        plug_type_raw = vehicle.ev_battery_is_plugged_in
        try:
            plug_type_int = int(plug_type_raw) if plug_type_raw is not None else 0
        except (ValueError, TypeError):
            plug_type_int = 0

        plugged_in = plug_type_int > 0
        plug_type_map = {0: None, 1: "DC", 2: "AC"}
        plug_type = plug_type_map.get(plug_type_int, None)

        # ── Charge limits ──
        charge_limit_ac = vehicle.ev_charge_limits_ac
        charge_limit_dc = vehicle.ev_charge_limits_dc

        # Active limit based on plug type
        if plug_type_int == 1:  # DC
            active_charge_limit = charge_limit_dc
        elif plug_type_int == 2:  # AC
            active_charge_limit = charge_limit_ac
        else:  # Not plugged in - show AC limit as default
            active_charge_limit = charge_limit_ac

        # ── Estimate charging power ──
        estimated_kw = None
        if charging and dur and dur > 0 and pct is not None and active_charge_limit:
            if pct < active_charge_limit:
                fraction = (active_charge_limit - pct) / 100
                estimated_kw = round((BATTERY_CAPACITY_KWH * fraction) / (dur / 60), 1)

        actual_kw = None
        try:
            current = float(vehicle.ev_charging_current)
            voltage = float(vehicle.ev_charging_voltage)
            actual_kw = round((current * voltage) / 1000, 1)
        except Exception:
            pass

        # ── ETA Calculation ──
        eta_time = eta_duration = None
        if charging and dur and dur > 0:
            now = datetime.now(ZoneInfo("America/Toronto"))
            eta_dt = now + timedelta(minutes=dur)
            eta_time = eta_dt.strftime("%-I:%M %p")
            h, m = divmod(dur, 60)
            eta_duration = f"{h}h {m}m remaining"

        # ── Response ──
        resp = {
            "battery_percentage": int(pct) if pct is not None else None,
            "battery_12v": int(vehicle.car_battery_percentage) if vehicle.car_battery_percentage is not None else None,
            "charge_duration": int(dur) if dur is not None else 0,
            "charging_eta": eta_time,
            "charging_duration_formatted": eta_duration,
            "estimated_charging_power_kw": estimated_kw,
            "actual_charging_power_kw": actual_kw,
            "is_charging": charging,
            "plugged_in": plugged_in,
            "plug_type": plug_type,  # "DC", "AC", or null
            "charge_limits": {
                "ac": charge_limit_ac,
                "dc": charge_limit_dc,
                "active": active_charge_limit,  # The limit that applies based on plug type
            },
            "is_locked": bool(vehicle.is_locked) if vehicle.is_locked is not None else None,
            "engine_running": bool(vehicle.engine_is_running) if vehicle.engine_is_running is not None else None,
            "doors": {
                "front_left": bool(int(vehicle.front_left_door_is_open)) if vehicle.front_left_door_is_open is not None else None,
                "front_right": bool(int(vehicle.front_right_door_is_open)) if vehicle.front_right_door_is_open is not None else None,
                "back_left": bool(int(vehicle.back_left_door_is_open)) if vehicle.back_left_door_is_open is not None else None,
                "back_right": bool(int(vehicle.back_right_door_is_open)) if vehicle.back_right_door_is_open is not None else None,
                "trunk": bool(vehicle.trunk_is_open) if vehicle.trunk_is_open is not None else None,
                "hood": bool(vehicle.hood_is_open) if vehicle.hood_is_open is not None else None
            }
        }

        return jsonify(resp), 200

    except Exception as e:
        import traceback
        logger.error(f"Error in /status: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ── Lock Status Endpoint ──
@app.route('/lock_status', methods=['GET'])
@require_auth
def lock_status():
    """Get vehicle lock status."""
    logger.info("Received request to /lock_status")

    try:
        refresh_token_if_needed()
        vehicle = get_cached_vehicle_state()
        is_locked = vehicle.is_locked

        logger.info(f"Lock status: {'Locked' if is_locked else 'Unlocked'}")
        return jsonify({"is_locked": is_locked}), 200

    except Exception as e:
        logger.error(f"Error in /lock_status: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Unlock Car Endpoint ──
@app.route('/unlock_car', methods=['POST'])
@require_auth
def unlock_car():
    """Unlock the vehicle."""
    logger.info("Received request to /unlock_car")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

        result = vehicle_manager.unlock(VEHICLE_ID)
        logger.info(f"Unlock result: {result}")

        return jsonify({"status": "Car unlocked", "result": result}), 200
    except Exception as e:
        logger.error(f"Error in /unlock_car: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Lock Car Endpoint ──
@app.route('/lock_car', methods=['POST'])
@require_auth
def lock_car():
    """Lock the vehicle."""
    logger.info("Received request to /lock_car")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

        result = vehicle_manager.lock(VEHICLE_ID)
        logger.info(f"Lock result: {result}")

        return jsonify({"status": "Car locked", "result": result}), 200
    except Exception as e:
        logger.error(f"Error in /lock_car: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Climate Presets ──
CLIMATE_PRESETS = {
    "winter": {
        "set_temp": 21,
        "defrost": True,
        "steering_wheel": 1,  # On
        "front_left_seat": 3,  # Driver - High
        "front_right_seat": 3,  # Passenger - High
        "rear_left_seat": 0,
        "rear_right_seat": 0,
        "heating": 1,
    },
    "summer": {
        "set_temp": 21,
        "defrost": False,
        "steering_wheel": 0,  # Off
        "front_left_seat": 0,
        "front_right_seat": 0,
        "rear_left_seat": 0,
        "rear_right_seat": 0,
        "heating": 0,
    },
    "springfall": {
        "set_temp": 21,
        "defrost": True,  # On for morning dew/frost
        "steering_wheel": 0,  # Off
        "front_left_seat": 0,
        "front_right_seat": 0,
        "rear_left_seat": 0,
        "rear_right_seat": 0,
        "heating": 0,
    },
}

# ── Custom Climate Start (with steering wheel & seat heater fix) ──
def _build_climate_payload(vehicle_manager, vehicle_id, options):
    """
    Build climate payload with heatingAccessory for steering wheel.
    The library's Canada implementation is missing this section.
    """

    vehicle = vehicle_manager.get_vehicle(vehicle_id)
    token = vehicle_manager.token  # Token is on vehicle_manager, not api

    # Convert temperature to hex format (library does this internally)
    # Formula: hex(temp * 2) with padding - e.g., 21°C -> 0x2A -> "2A"
    hex_temp = hex(int(options.set_temp * 2))[2:].upper().zfill(2)

    # Build the climate settings
    climate_settings = {
        "airCtrl": 1 if options.climate else 0,
        "defrost": options.defrost,
        "heating1": options.heating if options.heating else 0,
        "airTemp": {
            "value": hex_temp,
            "unit": 0,
            "hvacTempType": 1,
        },
        "igniOnDuration": options.duration,
        "seatHeaterVentCMD": {
            "drvSeatOptCmd": options.front_left_seat or 0,
            "astSeatOptCmd": options.front_right_seat or 0,
            "rlSeatOptCmd": options.rear_left_seat or 0,
            "rrSeatOptCmd": options.rear_right_seat or 0,
        },
        # Add heatingAccessory for steering wheel (missing from library's CA implementation)
        "heatingAccessory": {
            "steeringWheel": options.steering_wheel or 0,
            "sideMirror": 0,
            "rearWindow": 1 if options.defrost else 0,
        },
    }

    # For EV vehicles, wrap in remoteControl or hvacInfo
    # Check if vehicle is EV (has ev_battery_percentage attribute)
    is_ev = hasattr(vehicle, 'ev_battery_percentage') and vehicle.ev_battery_percentage is not None

    if is_ev:
        # Try hvacInfo first (newer EVs like EV6)
        payload = {
            "pin": str(token.pin),
            "hvacInfo": climate_settings,
        }
    else:
        payload = {
            "setting": climate_settings,
            "pin": str(token.pin),
        }

    return payload, is_ev


def _start_climate_custom(vehicle_manager, vehicle_id, options):
    """
    Custom climate start that includes heatingAccessory for steering wheel.
    Falls back to library method if this fails.
    """
    import requests

    api = vehicle_manager.api
    token = vehicle_manager.token  # Token is on vehicle_manager, not api

    payload, is_ev = _build_climate_payload(vehicle_manager, vehicle_id, options)

    logger.info(f"Custom climate payload (is_ev={is_ev}): {payload}")

    # Get the API URL and headers from the library
    base_url = api.API_URL
    headers = copy.deepcopy(api.API_HEADERS) if hasattr(api, 'API_HEADERS') else {}
    headers["accessToken"] = token.access_token
    headers["vehicleId"] = vehicle_id

    # The endpoint for starting climate
    if is_ev:
        endpoint = f"{base_url}rems/evc/rfon"
    else:
        endpoint = f"{base_url}rems/start"

    logger.info(f"Sending climate request to: {endpoint}")

    response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
    logger.info(f"Climate response status: {response.status_code}")
    logger.info(f"Climate response body: {response.text[:500]}")

    response.raise_for_status()
    return response.json()


# ── Start Climate Endpoint ──
@app.route('/start_climate', methods=['POST'])
@require_auth
def start_climate():
    """Start climate control with optional seasonal presets."""
    logger.info("Received request to /start_climate")

    try:
        from hyundai_kia_connect_api import ClimateRequestOptions

        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

        data = request.get_json() or {}
        logger.info(f"Incoming payload: {data}")

        # ── Check for preset ──
        preset = data.get("preset", "").lower()
        if preset:
            if preset not in CLIMATE_PRESETS:
                return jsonify({
                    "error": f"Invalid preset '{preset}'. Valid options: {list(CLIMATE_PRESETS.keys())}"
                }), 400
            # Use preset values, but allow overrides from request
            preset_values = CLIMATE_PRESETS[preset].copy()
            logger.info(f"Using preset '{preset}': {preset_values}")
            # Merge with any explicit overrides from request (except 'preset' itself)
            for key in preset_values:
                if key in data:
                    preset_values[key] = data[key]
            data = preset_values

        # ── Input Validation ──
        try:
            set_temp = float(data.get("set_temp", 21))
            if not 16 <= set_temp <= 30:
                return jsonify({"error": "Temperature must be between 16-30°C"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid temperature value"}), 400

        try:
            duration = int(data.get("duration", 10))
            if not 5 <= duration <= 30:
                return jsonify({"error": "Duration must be between 5-30 minutes"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid duration value"}), 400

        # Validate seat heating levels (0-3)
        for seat in ["front_left_seat", "front_right_seat", "rear_left_seat", "rear_right_seat"]:
            try:
                level = int(data.get(seat, 0))
                if not 0 <= level <= 3:
                    return jsonify({"error": f"{seat} must be between 0-3"}), 400
            except (ValueError, TypeError):
                return jsonify({"error": f"Invalid {seat} value"}), 400

        # Validate steering wheel heating (0-3)
        try:
            steering = int(data.get("steering_wheel", 0))
            if not 0 <= steering <= 3:
                return jsonify({"error": "steering_wheel must be between 0-3"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid steering_wheel value"}), 400

        # Create ClimateRequestOptions object
        climate_options = ClimateRequestOptions(
            climate=bool(data.get("climate", True)),
            set_temp=set_temp,
            defrost=bool(data.get("defrost", False)),
            heating=int(data.get("heating", 1)),
            duration=duration,
            front_left_seat=int(data.get("front_left_seat", 0)),
            front_right_seat=int(data.get("front_right_seat", 0)),
            rear_left_seat=int(data.get("rear_left_seat", 0)),
            rear_right_seat=int(data.get("rear_right_seat", 0)),
            steering_wheel=steering
        )

        # Try custom implementation first (includes heatingAccessory for steering wheel)
        use_custom = data.get("use_custom", True)  # Default to custom implementation
        result = None

        if use_custom:
            try:
                logger.info("Attempting custom climate start with heatingAccessory...")
                result = _start_climate_custom(vehicle_manager, VEHICLE_ID, climate_options)
                logger.info(f"Custom climate start succeeded: {result}")
            except Exception as custom_err:
                logger.warning(f"Custom climate start failed: {custom_err}, falling back to library method")
                result = None

        # Fall back to library method if custom failed or not requested
        if result is None:
            logger.info("Using library's start_climate method...")
            result = vehicle_manager.start_climate(VEHICLE_ID, climate_options)
            logger.info(f"Library start_climate result: {result}")

        return jsonify({
            "status": "Climate started",
            "preset": preset if preset else None,
            "settings": {
                "temperature": set_temp,
                "defrost": bool(data.get("defrost", False)),
                "steering_wheel": steering,
                "front_left_seat": int(data.get("front_left_seat", 0)),
                "front_right_seat": int(data.get("front_right_seat", 0)),
            },
            "result": result
        }), 200
    except Exception as e:
        logger.error(f"Error in /start_climate: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Stop Climate Endpoint ──
@app.route('/stop_climate', methods=['POST'])
@require_auth
def stop_climate():
    """Stop climate control."""
    logger.info("Received request to /stop_climate")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

        result = vehicle_manager.stop_climate(VEHICLE_ID)
        logger.info(f"Stop climate result: {result}")

        return jsonify({"status": "Climate stopped", "result": result}), 200
    except Exception as e:
        logger.error(f"Error in /stop_climate: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Debug Vehicle Endpoint ──
@app.route('/debug_vehicle', methods=['POST'])
@require_auth
def debug_vehicle():
    """Debug endpoint to view raw vehicle data."""
    logger.info("Received request to /debug_vehicle")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()
        vehicle = vehicle_manager.get_vehicle(VEHICLE_ID)

        # Access the raw private vehicle data
        raw_data = getattr(vehicle, "_vehicle_data", {})
        ev_status = raw_data.get("vehicleStatus", {}).get("evStatus", {})

        logger.info(f"Found evStatus keys: {list(ev_status.keys())}")

        return jsonify({
            "ev_status_raw": ev_status,
            "keys": list(ev_status.keys()),
        }), 200

    except Exception as e:
        logger.error(f"Error in /debug_vehicle: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Error Handlers ──
@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {e}", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

# ── Vercel Entry Point ──
# This is required for Vercel to properly handle the Flask app
if __name__ != "__main__":
    # When running in Vercel, this will be imported
    pass
