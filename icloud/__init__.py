import base64
import logging
import plistlib
import uuid

import requests

from emulated import nac

from . import gsa

logger = logging.getLogger("icloud")

USER_AGENT = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"


def login(
    username: str,
    password: str,
    delegates: set[str] = ["com.apple.private.ids"],
    grandslam: bool = True,
    anisette: str | bool = False,
):
    """
    Logs into Apple services listed in `delegates` and returns a dictionary of responses.
    Commonly used delegates are:
    - `com.apple.private.ids`
    - `com.apple.mobileme`

    `grandslam` configures if the new GrandSlam authentication flow is used. This is required for some delegates, and improves the 2FA experience.
    `anisette` configures which server to request anisette data from. If `False`, local anisette generation using AOSKit is attempted. This is not required if `grandslam` is `False`.
    """

    if grandslam:
        # TODO: Provide anisette preferences to gsa.authenticate
        g = gsa.authenticate(username, password)
        # Replace the password with the PET token
        password = g["t"]["com.apple.gs.idms.pet"]["token"]
        adsid = g["adsid"]
        logger.debug("Authenticated with GrandSlam")

    delegates = {delegate: {} for delegate in delegates}
    if "com.apple.private.ids" in delegates:
        delegates["com.apple.private.ids"]["protocol-version"] = "4"

    data = {
        "apple-id": username,
        "delegates": delegates,
        "password": password,
        "client-id": str(uuid.uuid4()),
    }
    data = plistlib.dumps(data)

    headers = {
        "X-Apple-ADSID": adsid,
        #"X-Mme-Nas-Qualify": base64.b64encode(nac.generate_validation_data()).decode(), # Only necessary with new prefpane URL
        "User-Agent": USER_AGENT,
        "X-Mme-Client-Info": gsa.build_client(
            emulated_app="accountsd"
        ),  # Otherwise we get MOBILEME_TERMS_OF_SERVICE_UPDATE on some accounts
    }
    headers.update(gsa.generate_anisette_headers())

    logger.debug("Making login request")
    r = requests.post(
        #"https://setup.icloud.com/setup/prefpane/login",
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
        auth=(username, password),
        data=data,
        headers=headers,
        verify=False,
    )

    # TODO: Error checking and parsing of this response
    return plistlib.loads(r.content)
