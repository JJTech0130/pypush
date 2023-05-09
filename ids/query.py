import gzip
import plistlib
import random
from base64 import b64encode

import apns
import bags

from ._helpers import USER_AGENT, KeyPair
from . import signing


def _send_request(
    conn: apns.APNSConnection,
    bag_key: str,
    topic: str,
    body: bytes,
    keypair: KeyPair,
    self_uri: str,
) -> bytes:
    body = gzip.compress(body, mtime=0)

    push_token = b64encode(conn.token).decode()

    # Sign the request
    # signature, nonce = _sign_payload(keypair.key, bag_key, "", push_token, body)

    headers = {
        "x-id-self-uri": self_uri,
        "User-Agent": USER_AGENT,
        "x-protocol-version": "1630",
    }
    print(headers)
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

    print(req)
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
def lookup_n(
    conn: apns.APNSConnection, self_uri: str, id_keypair: KeyPair, topic: str, query: list[str]
) -> any:
    conn.filter([topic])
    query = {"uris": query}
    resp = _send_request(conn, "id-query", topic, plistlib.dumps(query), id_keypair, self_uri)
    # resp = plistlib.loads(resp)
    # print(resp)
    resp = gzip.decompress(resp["b"])
    resp = plistlib.loads(resp)
    return resp

def lookup(conn: apns.APNSConnection, self_uri: str, id_keypair: KeyPair, topic: str, query: list[str]) -> any:
    import oldids
    #id_keypair = KeyPair("-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA6fNjLPobeiQEbeDzYResvK2oC9+MsGyog36jo1o7pm8AeIth\nSzZ7caM8ThM/37i9DGJyDsnl6yqg1SxhyW4Fm8Evq2Mm6eYh6YwzRvppQoFqXNQO\nrEgjpQAW+D31V5OvHRprwX6qDVRprNF8gtaGYYjTbQudzYwpzpCIwbUu+1IqfojF\ngzTR/bxfdTbJnlaqWbOjFF7WrSZrP18nGaVkbM3rBS7egRZH1WlG14gO31YNbNg3\ndzOz9hQJHehHfHrSyZam3h6nda8tA7LJzVpTGCo7PJMC4IVyvQf7S2N3BlMJ4cen\nemzaDIOW9b/FCuvENkY2LPuDIT1hQs3pOoWHSQIDAQABAoIBABPAmCLDwh6jnFkf\nmUTdEBlFCy9ncjQyFF83yb6gv3ELpa1HzVDhmnYLe2u3Hdk4eoOpaypa+wXKLVaa\nPu5YEvKl0q3EexRb+QiELQ8k1M7H6PBJ+iwrEhFcCtRuPMDmZ+5L3QWy+U4TTrHH\n5RyR2row6HLoPGxOlXgKhXVfZAZVbgsSG8dbbuoP+U9cCrSU5TH2yIa64Gm7XrvF\n0aEo+J6nMAzw4jUUYY/y8gCU89p5utNDpxXZNva8CO0GpkooZ0nDAOnUjytNpWow\nEXkta9xKBwPQ9FXk4tK0005U6s9lFbKm4HdeypX/teSmhaS3QshENL/zmMysOEpN\nxaIRPMECgYEA8O+h5POMutVufwnonzAq0yWxSDtx4Sj9kUNNflLV0T941TMKIZwp\nQmpBDgbt3ffATjRAdKwHEncHXWhPIf3oA0UgqZFdUEEboIXlNd+6unegGHfrrT/S\n5sOQgN9kyZ/z1IvRVxA9qj3shSFFw4p0gOShObc2NGCmJI7IXc6PumECgYEA+JPz\nCl0l0RCk+lL59YUOe9irhqwHeWo26vsPbnWn8mjN6RB6ZF3NeRFU8KaMf9Zb0eO7\nGnSku97AEgL/UkP1F9imrRI1Ci3jT/vGHyFpR0g8KfhAwZuBZBPavaZ52nW5tiDz\nILzxHJfg8xHXKPGl3T5r7ZzuIxmDPY7bFk6xBekCgYEAwviIQCg+l+qjcjZognmO\nDjQQVG2WaCitmWGnUjRiRuRgOdcFudEPKmmln15IGzmj6yUpi8CyMGUWFqaUcuNv\nX0YPemjh5FHrs2jm5UPZbY/khCh3FUnytz9GrqMYgnjn7fX/P78qx5s4zTrxo51l\nTfC172itepFDoY3R4ueHM8ECgYEAm3MqUhjeRVe7VC//0OJcpGZjHd0G747UuS44\nAEPju1x/KHj9kTZ4AHYuQDBnPKq40RExOOIpArPSOXFWagPFihwaX7E7Khp4RNSW\nmXEzfThXJ4fwNyMgT417BY7ONSfZ82O3p4mA3vi73EYT367+otUeeYHiCmEyCZUE\nvXaIjcECgYEAwYaoKAW8+dpUI8e40jg1FE4eWKo9HC/Gnn2rf0bTMz1qgtH6T9Fj\nvfcM9C8RM0ziXrU255fqqWGBNI3z8dq0mgH/CmU87vV4ldqd6Ej+37EC1drAtX4C\nxPIafLpiKa2aDPcw4FAG+nOGEfYIPbS9WT1Jmz/Qw3EUbNKtt6Ze1Ps=\n-----END RSA PRIVATE KEY-----", "-----BEGIN CERTIFICATE-----\nMIIHOTCCBiGgAwIBAgIQGaPYy+62Ee0Sd7oaf5gYAzANBgkqhkiG9w0BAQUFADBu\nMQswCQYDVQQGEwJVUzETMBEGA1UECgwKQXBwbGUgSW5jLjESMBAGA1UECwwJQXBw\nbGUgSURTMREwDwYDVQQPDAhpZGVudGl0eTEjMCEGA1UEAwwaQXBwbGUgSURTIElk\nZW50aXR5IENBIC0gUjEwHhcNMjMwNTA5MjIwODIzWhcNMjMwNjIzMjIwODU5WjCB\n2zELMAkGA1UEBhMCVVMxEzARBgNVBAoMCkFwcGxlIEluYy4xEjAQBgNVBAsMCU1l\nc3NlbmdlcjEOMAwGA1UEDwwFZHMtaWQxHTAbBgoJkiaJk/IsZAEBDA1EOjIwOTk0\nMzYwOTcxMXQwcgYDVQQFE2tiOjdDMDc4MjI2OTdGRDdGRTA5NDhGN0YzODAxOTJC\nNjZDQTkwNDJBNjEvQTI3QzFCMEM5MjE3OUFBQzk5N0U1Mzc0NUM5Q0JDNEZFMzhB\nNDFEMkQ4OUZFNkNCMzg1MThDREJDMTUwODZCNDCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAOnzYyz6G3okBG3g82EXrLytqAvfjLBsqIN+o6NaO6ZvAHiL\nYUs2e3GjPE4TP9+4vQxicg7J5esqoNUsYcluBZvBL6tjJunmIemMM0b6aUKBalzU\nDqxII6UAFvg99VeTrx0aa8F+qg1UaazRfILWhmGI020Lnc2MKc6QiMG1LvtSKn6I\nxYM00f28X3U2yZ5WqlmzoxRe1q0maz9fJxmlZGzN6wUu3oEWR9VpRteIDt9WDWzY\nN3czs/YUCR3oR3x60smWpt4ep3WvLQOyyc1aUxgqOzyTAuCFcr0H+0tjdwZTCeHH\np3ps2gyDlvW/xQrrxDZGNiz7gyE9YULN6TqFh0kCAwEAAaOCA2MwggNfMIIC2wYD\nVR0RBIIC0jCCAs6GHG1haWx0bzp1c2VyX3Rlc3QyQGljbG91ZC5jb22gLAYKKoZI\nhvdjZAYEBAMeAAMAAAACAAAABAAAAAEAAAABAAAAAAAABmgAAAAAoIICLAYKKoZI\nhvdjZAYEBwOCAhwARlVTUACPC3uexqw0O0//dpYLdkkocIFg/GhUJg5qX2F8IJ0Y\nqjx0LiR6qlqFCf1UHqVlqU3LtnTQnYYqG0kNje/DC9C2jC1J5+SGzit94eDfVM63\nUH+UpZQHX1J7NT2xjKQxjbvC9jnWHZMxTBvmwSZqHrrzql+rL840stJpopg335DQ\nsjUig9JgHwVYrxBUHGFMDFONZ4swNbjcOGKFT1KH1VaLAxFNrnL8U7m2h0PSG9Ur\nTXUrQFmLEOl5Jul2LAe0n84WAEwt/u3aZGY9SwQaHFz+64P7gWZpjC/q0ZvjbWiB\nxLc9L/qHm9282RA6e/ibn9C5a944GjNrmTy3FKEc7oL3Ru2XBZ5hlyAVBdTqgg8/\nLmT9SizbZ63Rt5Pct4slButdbecCq7phR46ATpgWLYjOx6NVw68G3cuC3hmXkTVW\ndVcJcikXC4c02YBiNqA2svViz32+QvCzQxvHEajC6+xOXEfFwq58S8/c+7HXJEIx\nnovNGWrcbzpCvSH1GankT1WjG5cQBPvUwnOQ58yvcma1FlQ7NU7JMDgPYqDUhhwZ\nhG9V+LRcGIGzLK9hsZQ39SQjAVqYJ23YPvNl3leaGJaiNgTgjccH6htTI5BBhDdM\nlBUooNEEmbrl0S6NB+OwI/5fWtic2T17J5HEM5mT3u9yC3reurv21hcG/R3rO04N\ni287i7848P039m0/cS0MFiOElmzAQgWgHwYKKoZIhvdjZAYECAMRABmj2MvuthHt\nEne6Gn+YGAOgLwYKKoZIhvdjZAYEBgMhAKJ8GwySF5qsmX5TdFycvE/jikHS2J/m\nyzhRjNvBUIa0MB8GA1UdIwQYMBaAFMZ7ab5JwEEOwMirMjI45D+RQIvaMB0GA1Ud\nDgQWBBSktWY28tqk62vLZOqMfXbkDszx6zAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB\n/wQEAwID+DAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZI\nhvcNAQEFBQADggEBAApIEISe9G6kdCwcWphSpiN1yGUP9WVhJTgUTvUgWl/e7Z1q\n4uVGNb2LsBEHXvI/rGL3qqVqSlt8b+GKqqxCSuL2G5ROoYn9wL/BuNCQJaa/SMqW\nA0Gz3uIA+fd/G+iYH31SP62DH/o6u7ctdG+pi5gjSCiBQcc8jTuOvWhSea6SfVC3\nqW7BBaxTSal/RWNll7A3RBCZS9vK7FZihDomGGH37YDNONTTr41k6FIH65X3pzy0\nFk5Jn/N/Ymhy5zcNPG1TBoXX2ZRWvfxuqMYP3+lfL15STJGQ65fnQNSSS6GkCGVm\nn3R7QDyy73xSTtEiBg28PUw/s2t+OR4lFuQr+KI=\n-----END CERTIFICATE-----")
    
    return oldids.lookup(conn, self_uri, id_keypair, topic, query)