import requests
from requests.exceptions import ConnectionError
import random
import apns
import trio
import gateway_fetch
from base64 import b64decode, b64encode


from exceptions import *

import urllib3
urllib3.disable_warnings()

API_PORT = 8080

def register(push_token: bytes, no_parse, gateway: str | None, phone_ip: str) -> tuple[str, bytes]:
    """Forwards a registration request to the phone and returns the phone number, signature for the provided push token"""
    if gateway is None:
        print("Requesting device MCC+MNC for gateway detection...")

        try:
            mccmnc = requests.get(f"http://{phone_ip}:{API_PORT}/info", timeout=30).text
        except ConnectionError:

            raise GatewayConnectionError("Could not connect to device! Please open the Pypush SMS Helper App.")

        except Exception as e:

            raise GatewayError(f"ERROR: An unknown error occurred: '{e}'")

        print("MCC+MNC received! " + mccmnc)
        print("Determining gateway...")
        gateway = gateway_fetch.getGatewayMCCMNC(mccmnc)
    if gateway is not None:
        print("Gateway found!  " + str(gateway))
    else:

        raise GatewayError(f"No gateway was provided, and automatic gateway detection failed. Please run again with the --gateway flag.")

    token = push_token.hex().upper()
    req_id = random.randint(0, 2**32)
    sms = f"REG-REQ?v=3;t={token};r={req_id};"
    print("Sending message and waiting for response...")

    try:
        r = requests.get(f"http://{phone_ip}:{API_PORT}/register", params={"sms": sms, "gateway": gateway}, timeout=30)
    except Exception as e:
        raise GatewayError(f"ERROR: An unknown error occurred: '{e}'")

    if 'error' in r.text.lower():
        raise GatewayError(f"An error was thrown from PNRgateway Client: '{r.text}'")

        # POSSIBLE ERRORS FROM APP:

        # Error: timeout waiting for response from gateway (unlikely, timeout is implemented here too)
        # Error sending SMS
        # Error: sms parameter not found
        # Error: gateway parameter not found

    print('\033[92m', "Received response from device!", '\033[0m')

    if no_parse:
        print("Now do the next part and rerun with --pdu")
        exit()
    return parse_pdu(r.text, req_id)
    
    # if r.text.split("?")[0] != "REG-RESP":
    #     raise Exception(f"Failed to register: {r.text}")
    # #assert r.text.split("?")[0] == "REG-RESP"
    # resp_params = r.text.split("?")[1]
    # resp_params = resp_params.split(";")
    # resp_params = {param.split("=")[0]: param.split("=")[1] for param in resp_params}
    # assert resp_params["v"] == "3"
    # assert resp_params["r"] == str(req_id)

    # signature = bytes.fromhex(resp_params["s"])

    # return resp_params["n"], signature

def parse_pdu(r: str, req_id: int | None = None):
    if r.split("?")[0] != "REG-RESP":
        raise Exception(f"Failed to register: {r}")
    #assert r.text.split("?")[0] == "REG-RESP"
    resp_params = r.split("?")[1]
    resp_params = resp_params.split(";")
    resp_params = {param.split("=")[0]: param.split("=")[1] for param in resp_params}
    assert resp_params["v"] == "3"
    if req_id is not None:
        assert resp_params["r"] == str(req_id)

    signature = bytes.fromhex(resp_params["s"])

    return resp_params["n"], signature


# async def main():
#     # Open test.json
#     try:
#         with open("test.json", "r") as f:
#             test_json = f.read()
#             import json
#             test_json = json.loads(test_json)
#     except FileNotFoundError:
#         test_json = {}
    
#     creds = apns.PushCredentials(
#         test_json.get("push_key", ""),
#         test_json.get("push_cert", ""),
#         b64decode(test_json["push_token"]) if "push_token" in test_json else b"",
#     )

#     async with apns.APNSConnection.start(creds) as connection:
#         connection.credentials
#         #number, sig = register(connection.credentials.token)
#         if "register_sig" not in test_json:
#             try:
#                 number, sig = register(connection.credentials.token)
#                 test_json["register_sig"] = sig.hex()
#                 test_json["number"] = number
#             except Exception as e:
#                 print(e)
#                 sig = None
#                 number = None
#         else:
#             sig = bytes.fromhex(test_json["register_sig"])
#             number = test_json["number"]
#         if sig is not None and number is not None:
#             from ids import profile
#             phone_auth_keypair = profile.get_phone_cert(number, connection.credentials.token, [sig])
#             test_json["auth_key"] = phone_auth_keypair.key
#             test_json["auth_cert"] = phone_auth_keypair.cert

#     out_json = {
#         "push_key": creds.private_key,
#         "push_cert": creds.cert,
#         "push_token": b64encode(creds.token).decode("utf-8"),
#     }
#     test_json.update(out_json)

#     with open("test.json", "w") as f:
#         import json
#         f.write(json.dumps(test_json, indent=4))




# if __name__ == "__main__":
#     trio.run(main)
