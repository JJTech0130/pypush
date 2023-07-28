import gzip
import plistlib
import random
from base64 import b64encode

import apns
import bags

from ._helpers import KeyPair, PROTOCOL_VERSION
from . import signing


def lookup(
    conn: apns.APNSConnection,
    self_uri: str,
    id_keypair: KeyPair,
    query: list[str],
    topic,
) -> bytes:
    BAG_KEY = "id-query"

    conn.filter([topic])

    body = plistlib.dumps({"uris": query})
    body = gzip.compress(body, mtime=0)

    push_token = b64encode(conn.token).decode()

    headers = {
        "x-id-self-uri": self_uri,
        "x-protocol-version": PROTOCOL_VERSION,
    }
    signing.add_id_signature(headers, body, BAG_KEY, id_keypair, push_token)

    msg_id = random.randbytes(16)

    req = {
        "cT": "application/x-apple-plist",
        "U": msg_id,
        "c": 96,
        "u": bags.ids_bag()[BAG_KEY],
        "h": headers,
        "v": 2,
        "b": body,
    }

    conn.send_message(topic, plistlib.dumps(req, fmt=plistlib.FMT_BINARY))

    def check_response(x):
        if x[0] != 0x0A:
            return False
        resp_body = apns._get_field(x[1], 3)
        if resp_body is None:
            return False
        resp_body = plistlib.loads(resp_body)
        return resp_body.get('U') == msg_id

    # Lambda to check if the response is the one we want
    payload = conn.incoming_queue.wait_pop_find(check_response)
    resp = apns._get_field(payload[1], 3)
    resp = plistlib.loads(resp)
    resp = gzip.decompress(resp["b"])
    resp = plistlib.loads(resp)
    # Acknowledge the message
    #conn._send_ack(apns._get_field(payload[1], 4))

    if resp['status'] != 0:
        raise Exception(f'Query failed: {resp}')
    if not 'results' in resp:
        raise Exception(f'No results in response: {resp}')
    return resp['results']
