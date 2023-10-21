# Licensed under the MIT license. From https://github.com/JJTech0130/grandslam

import getpass
import hashlib
import hmac
import json
import locale
import plistlib as plist
import uuid
from base64 import b64decode, b64encode
from datetime import datetime
from random import randbytes

import pbkdf2
import requests
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Server to use for anisette generation
ANISETTE = False # Use local generation with AOSKit (macOS only)
# ANISETTE = "https://sign.rheaa.xyz/"
# ANISETTE = 'http://45.132.246.138:6969/'
#ANISETTE = "https://ani.sidestore.io/"
# ANISETTE = 'https://sideloadly.io/anisette/irGb3Quww8zrhgqnzmrx'
# ANISETTE = "http://jkcoxson.com:2052/"

#USER_AGENT = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"
USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

# Created here so that it is consistent
USER_ID = uuid.uuid4()
DEVICE_ID = uuid.uuid4()

# Configure SRP library for compatibility with Apple's implementation
srp.rfc5054_enable()
srp.no_username_in_x()

# Disable SSL Warning
import urllib3

urllib3.disable_warnings()

def build_client(emulated_device: str = "MacBookPro18,3", emulated_app: str = "accountsd") -> str:
        """'Client Information'
        String in the following format:
        <%MODEL%> <%OS%;%MAJOR%.%MINOR%(%SPMAJOR%,%SPMINOR%);%BUILD%> <%AUTHKIT_BUNDLE_ID%/%AUTHKIT_VERSION% (%APP_BUNDLE_ID%/%APP_VERSION%)>
        Where:
            MODEL: The model of the device (e.g. MacBookPro15,1 or 'PC'
            OS: The OS of the device (e.g. Mac OS X or Windows)
            MAJOR: The major version of the OS (e.g. 10)
            MINOR: The minor version of the OS (e.g. 15)
            SPMAJOR: The major version of the service pack (e.g. 0) (Windows only)
            SPMINOR: The minor version of the service pack (e.g. 0) (Windows only)
            BUILD: The build number of the OS (e.g. 19C57)
            AUTHKIT_BUNDLE_ID: The bundle ID of the AuthKit framework (e.g. com.apple.AuthKit)
            AUTHKIT_VERSION: The version of the AuthKit framework (e.g. 1)
            APP_BUNDLE_ID: The bundle ID of the app (e.g. com.apple.dt.Xcode)
            APP_VERSION: The version of the app (e.g. 3594.4.19)
        """

        model = emulated_device
        if emulated_device == "PC":
            # We're emulating a PC, so we run Windows (Vista?)
            os = "Windows"
            os_version = "6.2(0,0);9200"
        else:
            # We're emulating a Mac, so we run macOS Ventura
            os = "Mac OS X"
            os_version = "13.4.1;22F8"

        if emulated_app == "Xcode":
            app_bundle = "com.apple.dt.Xcode"
            app_version = "3594.4.19"
        elif emulated_app == "accountsd":
            app_bundle = "com.apple.accountsd"
            app_version = "113"
        else:
            app_bundle = "com.apple.iCloud"
            app_version = "7.21"

        if os == "Windows":
            authkit_bundle = "com.apple.AuthKitWin"
            authkit_version = "1"
        else:
            authkit_bundle = "com.apple.AOSKit"
            authkit_version = "282"

        return f"<{model}> <{os};{os_version}> <{authkit_bundle}/{authkit_version} ({app_bundle}/{app_version})>"
    
def _generate_cpd() -> dict:
    cpd = {
        # Many of these values are not strictly necessary, but may be tracked by Apple
        # I've chosen to match the AltServer implementation
        # Not sure what these are for, needs some investigation
        "bootstrap": True,  # All implementations set this to true
        "icscrec": True,  # Only AltServer sets this to true
        "pbe": False,  # All implementations explicitly set this to false
        "prkgen": True,  # I've also seen ckgen
        "svct": "iCloud",  # In certian circumstances, this can be 'iTunes' or 'iCloud'
        # Not included, but I've also seen:
        # 'capp': 'AppStore',
        # 'dc': '#d4c5b3',
        # 'dec': '#e1e4e3',
        # 'prtn': 'ME349',
    }

    cpd.update(generate_anisette_headers())
    return cpd

def _generate_meta_headers(serial: str = "0", user_id: uuid = uuid.uuid4(), device_id: uuid = uuid.uuid4()) -> dict:
    return {
        "X-Apple-I-Client-Time": datetime.utcnow().replace(microsecond=0).isoformat() + "Z", # Current timestamp in ISO 8601 format
        "X-Apple-I-TimeZone": str(datetime.utcnow().astimezone().tzinfo), # Abbreviation of the timezone of the device (e.g. EST)

        # Locale of the device (e.g. en_US)
        "loc": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-Locale": locale.getdefaultlocale()[0] or "en_US",

        "X-Apple-I-MD-RINFO": "17106176", # either 17106176 or 50660608

        "X-Apple-I-MD-LU": b64encode(str(user_id).upper().encode()).decode(), # 'Local User ID': Base64 encoding of an uppercase UUID
        "X-Mme-Device-Id": str(device_id).upper(), # 'Device Unique Identifier', uppercase UUID
        "X-Apple-I-SRL-NO": serial, # Serial number
    }

def _generate_local_anisette() -> dict:
    print("Using local anisette generation")
    """Generates anisette data using AOSKit locally"""

    import objc
    from Foundation import NSBundle, NSClassFromString  # type: ignore

    AOSKitBundle = NSBundle.bundleWithPath_(
        "/System/Library/PrivateFrameworks/AOSKit.framework"
    )
    objc.loadBundleFunctions(AOSKitBundle, globals(), [("retrieveOTPHeadersForDSID", b"")])  # type: ignore
    util = NSClassFromString("AOSUtilities")

    h = util.retrieveOTPHeadersForDSID_("-2")

    return {
        "X-Apple-I-MD": str(h["X-Apple-MD"]),
        "X-Apple-I-MD-M": str(h["X-Apple-MD-M"]),
    }

def _generate_remote_anisette(url: str) -> dict:
    print("Using remote anisette generation: " + url)
    h = json.loads(requests.get(url, timeout=5).text)
    return {
        "X-Apple-I-MD": h["X-Apple-I-MD"],
        "X-Apple-I-MD-M": h["X-Apple-I-MD-M"],
    }

def generate_anisette_headers() -> dict:
    if isinstance(ANISETTE, str) and ANISETTE.startswith("http"):
        a = _generate_remote_anisette(ANISETTE)
    else:
        a =_generate_local_anisette()
    
    a.update(_generate_meta_headers(user_id=USER_ID, device_id=DEVICE_ID))
    return a
    

def authenticated_request(parameters) -> dict:
    body = {
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "cpd": _generate_cpd(),
        },
    }
    body["Request"].update(parameters)
    # print(plist.dumps(body).decode('utf-8'))

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": USER_AGENT,
        "X-MMe-Client-Info": build_client(emulated_app="Xcode"),
    }

    resp = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        headers=headers,
        data=plist.dumps(body),
        verify=False,  # TODO: Verify Apple's self-signed cert
        timeout=5,
    )

    return plist.loads(resp.content)["Response"]


def check_error(r):
    # Check for an error code
    if "Status" in r:
        status = r["Status"]
    else:
        status = r

    if status["ec"] != 0:
        raise Exception(f"Error {status['ec']}: {status['em']}")
        #print(f"Error {status['ec']}: {status['em']}")
        #return True
    return False


def encrypt_password(password: str, salt: bytes, iterations: int) -> bytes:
    p = hashlib.sha256(password.encode("utf-8")).digest()
    return pbkdf2.PBKDF2(p, salt, iterations, hashlib.sha256).read(32)


def create_session_key(usr: srp.User, name: str) -> bytes:
    k = usr.get_session_key()
    if k is None:
        raise Exception("No session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()


def decrypt_cbc(usr: srp.User, data: bytes) -> bytes:
    extra_data_key = create_session_key(usr, "extra data key:")
    extra_data_iv = create_session_key(usr, "extra data iv:")
    # Get only the first 16 bytes of the iv
    extra_data_iv = extra_data_iv[:16]

    # Decrypt with AES CBC
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    # Remove PKCS#7 padding
    padder = padding.PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()


def trusted_second_factor(dsid, idms_token):
    identity_token = b64encode((dsid + ":" + idms_token).encode()).decode()

    headers = {
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        "Accept": "text/x-xml-plist",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": build_client(emulated_app="Xcode")
    }

    headers.update(generate_anisette_headers())
    
    # This will trigger the 2FA prompt on trusted devices
    # We don't care about the response, it's just some HTML with a form for entering the code
    # Easier to just use a text prompt
    requests.get(
        "https://gsa.apple.com/auth/verify/trusteddevice",
        headers=headers,
        verify=False,
        timeout=10,
    )

    # Prompt for the 2FA code. It's just a string like '123456', no dashes or spaces
    code = getpass.getpass("Enter 2FA code: ")
    # code = input("Enter 2FA code: ")
    headers["security-code"] = code

    # Send the 2FA code to Apple
    resp = requests.get(
        "https://gsa.apple.com/grandslam/GsService2/validate",
        headers=headers,
        verify=False,
        timeout=10,
    )
    r = plist.loads(resp.content)
    if check_error(r):
        return

    print("2FA successful")


def sms_second_factor(dsid, idms_token):
    # TODO: Figure out how to make SMS 2FA work correctly
    raise NotImplementedError("SMS 2FA is not yet implemented")
    identity_token = b64encode((dsid + ":" + idms_token).encode()).decode()

    headers = {
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        # "Accept": "text/x-xml-plist",
        "Accept": "application/x-buddyml",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": build_client(emulated_app="Xcode")
    }

    headers.update(generate_anisette_headers())

    body = {"serverInfo": {"phoneNumber.id": "1"}}

    # This will send the 2FA code to the user's phone over SMS
    # We don't care about the response, it's just some HTML with a form for entering the code
    # Easier to just use a text prompt
    requests.post(
        "https://gsa.apple.com/auth/verify/phone/put?mode=sms",
        data=plist.dumps(body),
        headers=headers,
        verify=False,
        timeout=5,
    )

    # Prompt for the 2FA code. It's just a string like '123456', no dashes or spaces
    code = input("Enter 2FA code: ")

    body = {
        "securityCode.code": code,
        "serverInfo": {"mode": "sms", "phoneNumber.id": "1"},
    }
    # headers["security-code"] = code

    # Send the 2FA code to Apple
    resp = requests.post(
        "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put",
        headers=headers,
        data=plist.dumps(body),
        verify=False,
        timeout=5,
    )
    print(resp.content.decode())
    # r = plist.loads(resp.content)
    # if check_error(r):
    #    return

    # print("2FA successful")


def authenticate(username, password):
    # Password is None as we'll provide it later
    usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = usr.start_authentication()

    r = authenticated_request(
        {
            "A2k": A,
            "ps": ["s2k", "s2k_fo"],
            # "ps": ["s2k"],
            "u": username,
            "o": "init",
        }
    )

    # Check for an error code
    if check_error(r):
        return

    if r["sp"] != "s2k":
        print(f"This implementation only supports s2k. Server returned {r['sp']}")
        return

    # Change the password out from under the SRP library, as we couldn't calculate it without the salt.
    usr.p = encrypt_password(password, r["s"], r["i"])  # type: ignore

    M = usr.process_challenge(r["s"], r["B"])

    # Make sure we processed the challenge correctly
    if M is None:
        print("Failed to process challenge")
        return

    r = authenticated_request(
        {
            "c": r["c"],
            "M1": M,
            "u": username,
            "o": "complete",
        }
    )

    if check_error(r):
        return

    # Make sure that the server's session key matches our session key (and thus that they are not an imposter)
    usr.verify_session(r["M2"])
    if not usr.authenticated():
        print("Failed to verify session")
        return

    spd = decrypt_cbc(usr, r["spd"])
    # For some reason plistlib doesn't accept it without the header...
    PLISTHEADER = b"""\
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
"""
    spd = plist.loads(PLISTHEADER + spd)

    if "au" in r["Status"] and r["Status"]["au"] == "trustedDeviceSecondaryAuth":
        print("Trusted device authentication required")
        # Replace bytes with strings
        for k, v in spd.items():
            if isinstance(v, bytes):
                spd[k] = b64encode(v).decode()
        trusted_second_factor(spd["adsid"], spd["GsIdmsToken"])
        return authenticate(username, password)
    elif "au" in r["Status"] and r["Status"]["au"] == "secondaryAuth":
        print("SMS authentication required")
        sms_second_factor(spd["adsid"], spd["GsIdmsToken"])
    elif "au" in r["Status"]:
        print(f"Unknown auth value {r['Status']['au']}")
        return
    else:
        # print("Assuming 2FA is not required")
        return spd