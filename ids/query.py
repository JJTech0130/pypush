import gzip
import plistlib
import random
from base64 import b64encode

import apns
import bags
from . import USER_AGENT, KeyPair, signing


def _send_request(
    conn: apns.APNSConnection,
    bag_key: str,
    topic: str,
    body: bytes,
    keypair: KeyPair,
    username: str,
) -> bytes:
    body = gzip.compress(body, mtime=0)

    push_token = b64encode(conn.token).decode()

    # Sign the request
    # signature, nonce = _sign_payload(keypair.key, bag_key, "", push_token, body)

    headers = {
        "x-id-self-uri": "mailto:" + username,
        "User-Agent": USER_AGENT,
        "x-protocol-version": "1630",
    }
    signing.add_id_signature(headers, body, bag_key, keypair, push_token)

    # print(headers)

    msg_id = random.randbytes(16)

    req = {
        "cT": "application/x-apple-plist",
        "U": msg_id,
        "c": 96,
        "ua": USER_AGENT,
        "u": bags.ids_bag()[bag_key],
        "h": headers,
        "v": 2,
        "b": body,
    }

    conn.send_message(topic, plistlib.dumps(req, fmt=plistlib.FMT_BINARY))
    # resp = conn.wait_for_packet(0x0A)

    def check_response(x):
        if x[0] != 0x0A:
            return False
        resp_body = apns._get_field(x[1], 3)
        if resp_body is None:
            return False
        resp_body = plistlib.loads(resp_body)
        return resp_body["U"] == msg_id

    # Lambda to check if the response is the one we want
    # conn.incoming_queue.find(check_response)
    payload = conn.incoming_queue.wait_pop_find(check_response)
    # conn._send_ack(apns._get_field(payload[1], 4))
    resp = apns._get_field(payload[1], 3)
    return plistlib.loads(resp)


# Performs an IDS lookup
# conn: an active APNs connection. must be connected and have a push token. will be filtered to the IDS topic
# self: the user's email address
# keypair: a KeyPair object containing the user's private key and certificate
# topic: the IDS topic to query
# query: a list of URIs to query
def lookup(
    conn: apns.APNSConnection, self: str, keypair: KeyPair, topic: str, query: list[str]
) -> any:
    conn.filter([topic])
    query = {"uris": query}
    resp = _send_request(conn, "id-query", topic, plistlib.dumps(query), keypair, self)
    # resp = plistlib.loads(resp)
    # print(resp)
    resp = gzip.decompress(resp["b"])
    resp = plistlib.loads(resp)
    return resp
