import gzip
import plistlib
import random
from base64 import b64encode

import apns
import bags
import logging

from ._helpers import KeyPair, PROTOCOL_VERSION
from . import signing


async def lookup(
    conn: apns.APNSConnection,
    self_uri: str,
    id_keypair: KeyPair,
    query: list[str],
    topic,
) -> bytes:
    BAG_KEY = "id-query"

    await conn.filter([topic])

    body = plistlib.dumps({"uris": query})
    body = gzip.compress(body, mtime=0)

    push_token = b64encode(conn.credentials.token).decode()

    headers = {
        "x-id-self-uri": self_uri,
        "x-protocol-version": PROTOCOL_VERSION,
    }

    if 'alloy' in topic:
        headers["x-id-sub-service"] = topic # Hack, if it has alloy in the name it's probably a sub-service
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

    await conn.send_notification(topic, plistlib.dumps(req, fmt=plistlib.FMT_BINARY))
    
    def check(payload: apns.APNSPayload):
        body = payload.fields_with_id(3)[0].value
        if body is None:
            return False
        body = plistlib.loads(body)
        return body.get('U') == msg_id

    payload = await conn.expect_notification(topic, check)

    resp = payload.fields_with_id(3)[0].value
    resp = plistlib.loads(resp)
    resp = gzip.decompress(resp["b"])
    resp = plistlib.loads(resp)

    if resp['status'] != 0:
        raise Exception(f'Query failed: {resp}')
    if not 'results' in resp:
        raise Exception(f'No results in response: {resp}')
    return resp['results']
