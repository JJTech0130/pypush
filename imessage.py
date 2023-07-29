
# LOW LEVEL imessage function, decryption etc
# Don't handle APNS etc, accept it already setup

## HAVE ANOTHER FILE TO SETUP EVERYTHING AUTOMATICALLY, etc
# JSON parsing of keys, don't pass around strs??

import apns
import ids

import plistlib
from io import BytesIO

from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import gzip
import uuid
import random
import time 

from hashlib import sha1
import logging
logger = logging.getLogger("imessage")

NORMAL_NONCE = b"\x00" * 15 + b"\x01"

class BalloonBody:
    def __init__(self, type: str, data: bytes):
        self.type = type
        self.data = data

        # TODO : Register handlers based on type id

class iMessage:
    text: str = ""
    xml: str | None = None
    participants: list[str] = []
    sender: str | None = None
    id: str | None = None
    group_id: str | None = None
    body: BalloonBody | None = None

    _compressed: bool = True

    _raw: dict | None = None

    def from_raw(message: dict) -> 'iMessage':
        self = iMessage()

        self._raw = message

        self.text = message.get('t')
        self.xml = message.get('x')
        self.participants = message.get('p', [])
        if self.participants != []:
            self.sender = self.participants[-1]
        else:
            self.sender = None

        self.id = message.get('r')
        self.group_id = message.get('gid')

        if 'bid' in message:
            # This is a message extension body
            self.body = BalloonBody(message['bid'], message['b'])

        if 'compressed' in message: # This is a hack, not a real field
            self._compressed = message['compressed']

        return self

    def to_raw(self) -> dict:
        return {
            "t": self.text,
            "x": self.xml,
            "p": self.participants,
            "r": self.id,
            "gid": self.group_id,
            "compressed": self._compressed,
        }
    
    def __str__(self):
        if self._raw is not None:
            return str(self._raw)
        else:
            return f"iMessage({self.text} from {self.sender})"

class iMessageUser:

    def __init__(self, connection: apns.APNSConnection, user: ids.IDSUser):
        self.connection = connection
        self.user = user

    def _get_raw_message(self):
        """
        Returns a raw APNs message corresponding to the next conforming notification in the queue
        Returns None if no conforming notification is found
        """
        def check_response(x):
            if x[0] != 0x0A:
                return False
            if apns._get_field(x[1], 2) != sha1("com.apple.madrid".encode()).digest():
                return False
            resp_body = apns._get_field(x[1], 3)
            if resp_body is None:
                #logger.debug("Rejecting madrid message with no body")
                return False
            resp_body = plistlib.loads(resp_body)
            if "P" not in resp_body:
                #logger.debug(f"Rejecting madrid message with no payload : {resp_body}")
                return False
            return True
        
        payload = self.connection.incoming_queue.pop_find(check_response)
        if payload is None:
            return None
        id = apns._get_field(payload[1], 4)

        return payload

    def _parse_payload(payload: bytes) -> tuple[bytes, bytes]:
        payload = BytesIO(payload)

        tag = payload.read(1)
        print("TAG", tag)
        body_length = int.from_bytes(payload.read(2), "big")
        body = payload.read(body_length)
        
        signature_len = payload.read(1)[0]
        signature = payload.read(signature_len)

        return (body, signature)
    
    def _construct_payload(body: bytes, signature: bytes) -> bytes:
        payload = b"\x02" + len(body).to_bytes(2, "big") + body + len(signature).to_bytes(1, "big") + signature
        return payload

    def _encrypt_sign_payload(self, key: ids.identity.IDSIdentity, message: dict) -> dict[str, bytes]:
        # Dump the message plist
        compressed = message.get('compressed', False)
        message = plistlib.dumps(message, fmt=plistlib.FMT_BINARY)

        # Compress the message
        if compressed:
            message = gzip.compress(message, mtime=0)

        # Generate a random AES key
        aes_key = random.randbytes(16)

        # Encrypt the message with the AES key
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(NORMAL_NONCE))
        encrypted = cipher.encryptor().update(message)

        # Encrypt the AES key with the public key of the recipient
        recipient_key = ids._helpers.parse_key(key.encryption_public_key)
        rsa_body = recipient_key.encrypt(
             aes_key + encrypted[:100],
             padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
        )

        # Construct the payload
        body = rsa_body + encrypted[100:]
        sig = ids._helpers.parse_key(self.user.encryption_identity.signing_key).sign(body, ec.ECDSA(hashes.SHA1()))
        payload = iMessageUser._construct_payload(body, sig)

        return payload
    
    def _decrypt_payload(self, payload: bytes) -> dict:
        payload = iMessageUser._parse_payload(payload)

        body = BytesIO(payload[0])
        rsa_body = ids._helpers.parse_key(self.user.encryption_identity.encryption_key).decrypt(
            body.read(160),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

        logger.debug(f"RSA BODY LEN: {len(rsa_body)}")

        cipher = Cipher(algorithms.AES(rsa_body[:16]), modes.CTR(NORMAL_NONCE))
        decrypted = cipher.decryptor().update(rsa_body[16:] + body.read())
        
        # Try to gzip decompress the payload
        compressed = False
        try:
            decrypted = gzip.decompress(decrypted)
            compressed = True
        except:
            pass

        pl = plistlib.loads(decrypted)
        pl['compressed'] = compressed # This is a hack so that messages can be re-encrypted with the same compression

        return pl

    def _verify_payload(self, payload: bytes, sender: str, sender_token: str) -> bool:
        # Get the public key for the sender
        lookup = self.user.lookup([sender])[sender]

        sender_iden = None
        for identity in lookup['identities']:
            if identity['push-token'] == sender_token:
                sender_iden = identity
                break

        identity_keys = sender_iden['client-data']['public-message-identity-key']
        identity_keys = ids.identity.IDSIdentity.decode(identity_keys)

        sender_ec_key = ids._helpers.parse_key(identity_keys.signing_public_key)


        payload = iMessageUser._parse_payload(payload)

        try:
            # Verify the signature (will throw an exception if it fails)
            sender_ec_key.verify(
                payload[1],
                payload[0],
                ec.ECDSA(hashes.SHA1()),
            )
            return True
        except:
            return False

    def receive(self) -> iMessage | None:
        """
        Will return the next iMessage in the queue, or None if there are no messages
        """
        raw = self._get_raw_message()
        if raw is None:
            return None
        body = apns._get_field(raw[1], 3)
        body = plistlib.loads(body)
        print(f"Got body message {body}")
        payload = body["P"]
        decrypted = self._decrypt_payload(payload)
        if "p" in decrypted:
            #if not self._verify_payload(payload, decrypted["p"][-1], body["t"]):
            #    raise Exception("Failed to verify payload")
            pass
        else:
            logger.warning("Unable to verify, couldn't determine sender! Dropping message! (TODO work out a way to verify these anyway)")
            return self.receive() # Call again to get the next message
        return iMessage.from_raw(decrypted)
    
    KEY_CACHE: dict[bytes, tuple[bytes, bytes]] = {} # Mapping of push token : (public key, session token)
    USER_CACHE: dict[str, list[bytes]] = {} # Mapping of handle : [push tokens]
    def _cache_keys(self, participants: list[str]):
        # Look up the public keys for the participants, and cache a token : public key mapping
        lookup = self.user.lookup(participants)

        for key, participant in lookup.items():
            if not key in self.USER_CACHE:
                self.USER_CACHE[key] = []
            
            for identity in participant['identities']:
                if not 'client-data' in identity:
                    continue
                if not 'public-message-identity-key' in identity['client-data']:
                    continue
                if not 'push-token' in identity:
                    continue
                if not 'session-token' in identity:
                    continue

                self.USER_CACHE[key].append(identity['push-token'])

                print(identity)

                self.KEY_CACHE[identity['push-token']] = (identity['client-data']['public-message-identity-key'], identity['session-token'])
    
    def send(self, message: iMessage):
        # Set the sender, if it isn't already
        if message.sender is None:
            message.sender = self.user.handles[0] # TODO : Which handle to use?
        if message.sender not in message.participants:
            message.participants.append(message.sender)

        self._cache_keys(message.participants)

        # Set the group id, if it isn't already
        if message.group_id is None:
            message.group_id = str(uuid.uuid4()).upper() # TODO: Keep track of group ids?

        message_id = uuid.uuid4()
        if message.id is None:
            message.id = str(message_id).upper()

        # Turn the message into a raw message
        raw = message.to_raw()
        import base64
        bundled_payloads = []
        for participant in message.participants:
            for push_token in self.USER_CACHE[participant]:
                identity_keys = ids.identity.IDSIdentity.decode(self.KEY_CACHE[push_token][0])
                payload = self._encrypt_sign_payload(identity_keys, raw)

                bundled_payloads.append({
                    'tP': participant,
                    'D': not participant == message.sender, # TODO: Should this be false sometimes? For self messages?
                    'sT': self.KEY_CACHE[push_token][1],
                    #'sT': self.connection.token,
                    #'sT': base64.b64decode("jJ86jTYbv1mGVwO44PyfuZ9lh3o56QjOE39Jk8Z99N8="),
                    #'sT': b'\x06\x01(\x1b\xc8\x9d\x9b\x956\xf8\xb2m\xc14F\xffKLze\x04\xd4\x16\x9f\xd01\xd48d\xbf\xf1\x1f1\x1a',
                    'P': payload,
                    't': push_token
                })
        
        body = {
            'fcn': 1,
            'c': 100,
            'E': 'pair',
            'ua': '[macOS,13.4.1,22F82,MacBookPro18,3]',
            'v': 8,
            'i': 0, # TODO:??
            'U': message_id.bytes,
            'dtl': bundled_payloads,
            'sP': message.sender,
            #'oe': time.time_ns(),
            'e': time.time_ns()
            #'rc': 2
        }

        # body = {
        #     'sP': message.sender,
        #     'fcn': 1,
        #     'c': 100,
        #     'E': 'pair',
        #     'ua': '[macOS,13.4.1,22F82,MacBookPro18,3]',
        #     #'rc': 1,
        #     'v': 8,
        #     'i': 1903314481,
        #     #'oe': 1690650841881000000,
        #     'e': time.time_ns(),
        #     'dtl': [{'xx': 'xx', 'tP': 'mailto:testu3@icloud.com', 'D': False, 'sT': b'\x06\x01\x86\xde\xa3/\x9f\x87\x8e\x97\x1b\x02~\x19-\xdd\x0b\xe5_\x86\xa8\x94\x80\xf1]O\xe7\x88\xe1/\xc95\xb3\xd7\x1a\xd0', 'P': b'\x02\x01\x1d\x85Y1C\xc9\x12)t\xb8\x99 \xe7\x83\xbc\x9d\x18\'\xf0^\xb7\x9bG\x1e\x14\xd5\xc9.\x98\x1a\xd3\xc9<\xccvk\x95\xe2\xb3\xfd\x93P(\x87\xb2\xcf=Q\xbe@\x16\x9f\x1e\xdb.\xad\xe0\xcb\x83\xad\x8ex\x86`B\x1b\x1d\xfb\x04\x89"V\x94\xd9\xf5\x94c\x88O\t\x18uNK&\x89\x10\xe6\xa6\xa1\xf9\xaa\xd5\xba\x7f\x92\xe1\xaaK\x10\x895\xc1\x07\xd2\t\xf3\r\xae\x01\xd1\xac\xeep\x0fUhb\x98\xa2\xd1H?Dn\xeb\x85\xce\xbd\x97O\xc8\xb9\xf2\xe9\xecQ\x8c\x96V\xbdN\x1c\x83\xf5\xb9\xe4]\xb8X\xd7\x1d\xe8\xc4A\xae\x17>]*\xb7&Wn\xe9\xa29\xa2\xfdU\xcf\x8e^\x02R8\xbbuT\nP\x9e{:\xe8\\\x9f!\xba\x1a9dY\xe5F\x93\x8a\x9ds\xdbh\x87\xe5\xf9d\xac\x0ekA\x91?{\xda-\x99[\xc9\x9c\x03\xe8\xa1\x1fZut}\x18\x85\x97M\xf8\xc9\x00!\xde\xa0\xbe\x0f\xcb&M\xd8)\x9b\xfa1\x97\x99Iq\xf9\xa3\xdf\x1eQ.\xd3p\xdd\x84\x9a\xf3\x9cO\'\xac\xfa\x8b\x7f\xefA8\x7f\xc8r\xd1\xe3M\xf8\xda[\xa6\xbbPL\xd9H0F\x02!\x00\x95!C\x06\x81\xb6\xf6}:\xee\xedx\xd1mpJ(\x9c\xa3k(\xb5\x93\x01\xd3\r`\xc9dY\xf8\xa3\x02!\x00\x96\x9b\xa9\x9d\xd8\n\xeeRN,c74k\x0e\xd4\xc7\x03p\xb4\x00\xc4b\xaa\xc8\xdc\xe7X\xdf\xe4\x85\xa0', 't': b'\xc6\xe1}R\xc3\xde\xd29G\xf0DN\xf4+\xde\x91y{|\xb7\xb1\xd8\xbd\xb2\xc4\x86\xec@9\xa1\xc0\xac'}, {'tP': 'mailto:testu3@icloud.com', 'D': False, 'sT': b'\x06\x01n\xb0\xbe8\xd0\xc4\xddp\xdd\xc8c\xaaE\xc68z\x02-\xf1\x0b8\xb45)\xfd\x8b\x92\xcc:\xc6g\xefS\xcc', 'P': b'\x02\x01\x1dB)>\x11\x9b\x04d\x1b~\x81\xe2\xb2\xc8\xe9.\xe0\xceV\xd7g\x8bq\xc7\xe8\x9ee\x8e\x85\xf5\xd4\xf3\x95\xd7\xb4|K=8\xb7\x8f\x1b\x0b\x11\xabK\x16\x1aP\x88\xd5B\x9d;=\xd5\xd6\x13O\xc74{\xd9\xfd\xb8\x1c\xfa\xf1\\i\x1c\n3\x07\x7f\xb2\'\x80\xe8f\xa4kp\xfaX\x8a\x9609\xa6\x1dJ\xca\xee\xe0?\x078_9lL\x15A\x81\x14\xe5;"\x1b\xe9O\xabc\xd2\xf5*\x96\xbc\'\xdf10\xa5S\xb2\xae\x7f!K\x0fU\r\xf8o\x1a\xb1\xe7t\xea:\x0f\x9c\x0f\xe5X\xc2\x9e\xf4\xba&/-+,U*\x83/\x07\x01l\x00\xb0\x16m\x0b\x17\xbb\x07p\xfe\x04\xee48\xa1\xf7\xb83\x874\x9b\xb1\xc0y\xa5\x9c\x8c\xe7\xe4 /8`Uc\x85E\xda\xb9Cn]wFb\xfdz\xf1&Y\xbf\xfb8\x9d\xb4\xed\xd5\xeb\xf2\x1b\xec\x9b\xddk *[\xbf\n\xbb1\xf4%\xae\x80yz\xcf\xc6Q\xe3G\xae\xf9\x85\xda|\xe4u\xe6\x9a#_f\xeb(K\x8d\x12\x8a\x96AC=\x1d#Jm\xfe\x8bV\xae_=\xfc\x8a\xc42@\xa5\xb3"\x95\xa0G0E\x02!\x00\xb6\xde\xd9\x05\x1cf\x083\xd6w\xcd"F\x96\xfa\xf4\xedS\xffi\xc0\xc1\x9e\xf3T\xa1:\xb4\xc0?=\x0f\x02 \x11q\xd2\xb03\xd3\xfe\xa2u\xc6\xf8\n0\xbe\x0f\x0c\xa8\x9b\x9eB\xd90\x12\xd9a2\x944\xef\xc1\x96\x18', 't': b'\x96\xb0\xcc\xb6\xe5\xb3=,\x8b\x19\x18.\x1e@\n\xefL\x02\x0bv\x00>4!\x04\x1d\xceV\x0fI\x85y'}, {'tP': 'tel:+16106632676', 'D': True, 'sT': b'\x06\x01\xad\tn\x91\xbd\x96\x0emez\xc4\x08\xa0\xd8\x8e\xfe\x82\xb4\x08\xeew\xa5\xeb\x9d\xe3\xf07\xad\xae\xfaB\x8d3\xa9', 'P': b'\x02\x01\x1d\x8c\x1db\x81\x981%5\x0e\xae\x06\x9eg\x0fs\xf1odu\x90\xd5\xec\xe4\x0fY\t-m\xa2k\x15b\x0c\xfe\xd2\x148\x91T\xefjKOs\xa7k\xc8[Y\xf3\xfa\x12\x82\xc0#NG+^>\x88\xb9\x12\x0fV\xeb\xfa\x8a>\x05x\x8a\xbd\x1d\xdb\xe0\xd2GIY\xd6\xd91U\xf8c\xd9b\xeas\x94EB\x8a\xd7L\xea\x8e\x9e\x07\x8d(\xbd\xb8\xca3\x8fn\x89\xee\x1f\x9c\xb7b\xc6q\xca\xb9\xc6\xfd\xc7\x9d\x15\t\xe4|\x93\xfc\\\x16%\x04\xb7\xd1Y\x9b\x86Tr\x94W\xe8\x95\x82Rh?\xe2w\xd8\xeb\x8a\xf2\xc1eA\\\xdf:j\xc9(7\x02%\x8b\xc9\x96-y\xd1\x8c\xea\xb0p\xb5\xd1\x9cSOo\xa4y\x8c4)\xffh\x19o\x90\x07\xc3@\xf2\xb3\xca\xb3/:\xd22\x17K\x9d\x0b\x9b\xdb\x1aek/]\x10\xf2\xb5\xedX\xff\xdf\xfe\xde\xf9B\xf9\x18\x01\x07\xe4\x9bU\x02\x8aB?\x10\xc9\xab\x84H\xffW\\\xad\x1a[Xu\xfc\xbc8\x9dt\x0fw\xacF\xd8\x12A0 \xab\x992D\xcb\x9d+9U;\xb4\xbb\x90\\\x93\xc8\xefy\x08W[G|G0E\x02!\x00\xf3QW=\xeb\x07\xd3\xc6DK_\xbb\xe6\xc3\xfe"\x9d\xd1\xdf\xcd\\\x95Y"\xe5?\'\x0cC\xb7)R\x02 S~\x8f\x99\xc2U\xf0\x1f\xa1\xf9\x04\xba\xaa\xf7\x7f\xe6\x9a\xecv[\xc3\x9f\xa9*\x9b\xba\xa0\xef\x81F\xa8\xd5', 't': b'\x13j\xb1\xdaH\x94\xd0\xacg\xca\x17\x0b\x12\xb5\x07\x12uP\x00\x11\x1a\x11\x07\xcf\x10B\x12\x99L~\xe2>'}, {'tP': 'mailto:testu3@icloud.com', 'D': False, 'sT': b'\x06\x01i\x11\xf3\x91\xb0N\xb9\x9d\xdf.z\xd7\xa4\x8b\xd1E\x1a)\xb4\x8d\x90.Li\xd4\xf8\xfcg\xbc\x06A\xd5\xd6K', 'P': b'\x02\x01\x1d\x02&\xb3\xca\xad\x02\xf0\x04\xe1\xb1\x9e|df\xabSqY\x01_\xec`/\x9b\xc1\xe9\x01\x13\xce\x90\xa21\xbff|\xf2\x18\x15\r\xc7\xa9\xefo\xa7\x0e\xba\xd7Wa\xa9\xde\xed\x02\x00\xa23 =W\x01\r\xbe\x15\xc8BJH6\x91?\'f\xad^"(\x92\x0cN\x8fA\xfd;T\xd3\xa5\xd8\x14P\x10\x93\x9b\x07\x96\xc7)x\xe5\x8a~\xa2\xad\x12T\x03\x88\xe5a\x1c\xf7.\xc3So\xc6c\x83l\x1e\xb3\xc3\xd5\xc7\x0f\n\xa6H\x84\x8c\xa3\xdb\nR.j}\xba96\xd83o>\xe7*FL\xf2\x85N\x84\xfd\xba\xdb#F\x14\xad,(0\x9f\x83m\xca\x17\x8a\xd7\xb3\xfb`Y\xc6\xe7\xa0\x00\x1f\xee\x107\xc3Q[\xfa-\xf2\xe7\x88\xcfA\x9e\xd5R\x0bP\xb2\x96\xd0#]s\x13*\xda\xfa\xff\x91\x00\x83\x13$\x12\x00\x88J\xf3\xb1\xd3\xc5\xcdF\xc7fA\x99;l\xdb\xa8N\xea\xfe\x1ac\xa6D\xda7#\x1b\xbf\x88\r\x0cn\x8c+`\x83\xc7\xafdHxQ\xcbVF\x97\x86\xac\x1f\xf5\xd3@dL\x11\xa8\xd5y\xa3\x9fInk"\xd0w,\xfd2\xef\x0c0H0F\x02!\x00\xf8\x91+,\xe3I\xf6\x9e\xfe\x83\x1f\x97\xdbu\x98C\xd0\xe8%\xba\x89\x13 \xbaL4O\xdf]\x9b\xfc\xd1\x02!\x00\xef\xacC\xa7{\xd8\x1drJ`Z\xa4\x05$r\xbc\xce\xa6\x8b\x0c,\xda~\xa2\xd2\xe1\x1bD\xdfc\xb9=', 't': b'\xa6\xaf\xba\x8f0\x92\xfb]7\x929\xae\x81\xb5\x8c\xee8\x9f\xca\xfanm\xf8V^\xf7 M,ag#'}, {'D': True, 't': b"\x13\xd4'\x15\x87\xcf\x8dk\xe1\xde\x17\xba^\x9d\xed\xffy\xf8\xa9H\xda\xbc\xf8\x89S\r;\x92\xc3\xcf\x88\xb6", 'E': 'pair-ec', 'sT': b'\x06\x01\x94\x17\xc5\x17\x90\xf6\xb5@S\xcf\\\xb0&\x8b\xdf\x84Hn|W\xb8\xf0\xb8bq\xe7@\x87\xbd\x17\xf3 ,u', 'cdv': 1, 'tP': 'tel:+16106632676', 'P': b'\n\xf4\x01K;\xb3\x98\xf0\x08#m|\xc8PH\xf4\x9e\xb4\xe3Y\xd7\xa8|\x0f\xc3\xb54\xffD!\xb9\xac\xa9\x8d\xde\x9e\x95SB_w(M\xa3?\x9cG\xd5^OE\x82\xf8&|\xb7\xc3\xc7$\xb6\r\x08\x8a\xf3|4i\x80\x9d\xc8]!\x9e\xf2l\xacN\x13X\xfbQY\xd4@@uR\x0e\x15\xd9\x83\xb2\x0b9\\\xee\xaa\xd6\xdc\xe7W\xd7\x853\xc7;\x15\xb0\xd2N\xd1\x82\xf2IF\xff[\x8f\xaaVbW\x98\xef\xeav\xf6\xde6\x90\x08S\x84@\x00\xb1\xfdS6\xf2XA\x905\x82\xe0\xf4\x96\xad\xf0.t\x11\xf8\x07\xa3=\x17`\xbdC\x7f\xeb\x82\x80s\xf9I\xbb\r\xab\x94\xb7*\x10\xc7\xd9\xadW\x9c\x1e\x05\x08\xb4&\x14\x0c\x86\x12\'5[\xfa\xfe\xd1\xaeQT\xbd\x90\x1dA\xf0@\x04\xd2\x12\x84"v5\x03m\xaa\x9cY\xdes\x9b$\xf6\x87\xf6\xf6`\xd73\xe1\\q\x16\x8c\x7f\xa7\x00p\x93+\x94\xe8\xf8\t\xad\x8fw\xe5/\x12 \x00\xf9|J \x95\xf3F\xfa\xda;\xe1M\x02\xfe\xc9\x86\xdc\xa2`\xf6\xf0\x01\x8a\xc0\xb5\xa7\x81!\xf5\x8c\x94\x1a@\xd28\x9e}\x1b\x0e\xc5\xb5\xb67R\x81\xa0\xd1"\x85~h!\xd7\xb0\xd5F\xd3\xca\x88\x00y?\xbc\xd8\x04Y\xe7\xf7\xb06U\xe6\x9e\x9ad\x03x+$\xc2\x96a\x04\x0f\xce$\xe6\x80?:L!\xcc4tc\t\x9a\x06\x07\rlF\xdc#*\x0c'}, {'tP': 'mailto:testu3@icloud.com', 'D': False, 'sT': b'\x06\x01\\\x83)\x1c\xc2J\x0e1\x12\xbf\xa8A|\xfb-\xbc\xf8*\xce\xe2\xe0m\xd8\x14W\x94\xfe\xd6\x07\x1c\xd8Y\x00\x85', 'P': b'\x02\x01\x1d#\xf0\xfd\xf0\xcd\x9a?1"@2\xc2\xfa\xb3p\x0bx\xb5\x9d?\xb1\xe8\xbe\x88\xa3P\xe6Z\x1d,%\xa4l\x029\t\x1a\x07\x15,\xd5\xa7XN7z\xdc\xf1\xca\xe3\xc64\xf0\xcf\xca^+l\xa0T\xcb\'\xa8\x99\xa5p]\xdc\xf8\x93Mb-\xb4\xc2\xef\xb4\x10\xe9\x9e\x9b\x0c_\xd8"\x98\xf0\xdd^\x0eCeEn\x00\x14[\xef:G\x91\xa9\xc8N\xb9\x1b\xe3\xf2\xb3gr\xaa\x02\x0bk\xa4-\x88a>[\xbc4hvf\xe0k+\xed\xe5k\xb3\x1e\x04\xd2\xcct\x1c\x92:\xd8U\x1d7\x1e\xe3\xcfd&\xde\xf2`\x81\xf53?\xca\x86\x98n\xd7\x13\xae\x18\xc1\x16 m\xe7dE\xe2n\xff\xb8\xc2\xe0\xc3\xe8\x1e\xd1\x02/\x8e\x87\xa8.[9_\xb3[\x84\xa2\xef\xeaT\xcf)>\x19bK\n\x98\xd6\xd8\x10\xce\xe5\xba\xd9\x9d\xbb\xb9\x0e\xf5\'B\x9e\xdbU\xfaY\x9f\xd6\xb9\x88\x94X\xb0\x0c\x0e\x91\xaec\xde\x17\xe2Oi~K5\x18\xbf\xd6J"K\x91>\xac\x1b\x9de\x92J\xd4e\xd6Gd\x148xI\x1d\x9bU\x1f\xf3\x90\x81\xf5e\xf6\x01m\x8a\xbe\xb5\xbcKH0F\x02!\x00\xa1Q\x19\xa8j\x03x\xa8\xd6\xe1\xafW\xac\xce\x12\x02y\xe8\x1f1\xab\x98IW\xb0\x87Sl\xd1lI0\x02!\x00\xa8\xf2\x0f\x80\xa2\x0c\x05\x08\xdd\xf2\xc7\xb0\x86\x99\xf8#\xea\xf2\x8a\x8eq<\xbe\xddy%\x13\xae\x8f\xdfv\xa2', 't': b'F\xcfh]\x0em\x80;\xf7\x91\x1eDW|\x9f?\x84\x82\xa7M\x0e\x92*\x8em\xdc\xfe\x04\x9a5\x1c\x13'}, {'tP': 'mailto:testu3@icloud.com', 'D': False, 'sT': b'\x06\x01(\x05o\xb8\x12\x93x\xeb\xfa\xf0\x91\xf0N`\x9dBcZ\x82p?\xfc*\x12|8\n\n\xf3\xcb\xdd\xead\x10', 'P': b'\x02\x01\x1d\x90\xbc\x1d\xdf}\x06@\xb0\xd7\x1f\x9c\xa3L\tOK\xa2z\xa3\x0e0E\x95G\xad\xb7\xa40\x93\xa0"\xa9$Z\xed\xca\xd47\xf2\xdc\x18\x16O!\xb8&\xb2\xcbp;~#\x91;\x0c\xa5<u\x96\x19~\x1dzE\xda\xf4\n\xd0D\x92\xb1V\xdd\xc8\x9c\xa5\xc8\xa1\xbc\xa1\xe7s\xad\xc9\xee\x90\x8e\x99(\xbe\xf5\x91\xf8\xd0\xdd\x06\x12\x8b\xf3z\x11\x10\xf4PT\x03\'\xf3<\x12\x89\x19ob4\x08\x97\x02\xbc{E\xc5\x8d\xc5\xa6E\x13)\xd8\x87E[D\xfb\xe8\x8e\xeb\x08Lu\t\x872\xffb\xef\x8a>4\xa2Y\xf7c\xeeP~\x83\xd4\xc7\xb1~\x7f\x81\x07\xa9L\xbf\x05\x12\xfaG\xaa\x0b\xb3\xe7\xcf\x05\xed\x90\x19|\xd1)\xd2\xd8a?\x8a\x85y\xfb^\x82\xf8\x92\x98X \xd1\xfb\xdd\x17\xfaF\x19\xec\x10\xbcJ\xf8N\xb2^\xf1\xb3\x97\xb0w{\xab\\\xf9w\xd7\x06,\xfb\x13\xfdV\x12\x8d\x01V\x16\xd6\x99\x81)\x8d\xe5\x83\xb9\xed\xe0\rFu%J%)\xf2\r@\xe1ku\x14\x0e_:fp\xdb\xea24~aC\xfc\xd7\xa0C\xdc\xb9\xf3\x83\xf8\x95_\xad\xbc\x93G0E\x02!\x00\xb7\x17)\x87\xea\xe7\xa8\xa1Z\xa8\x18S\x9ag\x0b\xcdL\x1b\x14yV\x0bb\x94\x9emm\x08\x9a\xa9\xf4\x86\x02 *O\xd7\x86\x18#\xd1\x9c6\x8c\xd1\xeaYG\xcb\xa8\xa2\x97\xd9\x15\x92\xab7^XR\xec\xfb\xd0\xf6,\x07', 't': b'\x81\xe4D\xe0\xcc\x12\x99\xef\xc0Ik`L\xdb\xbe\xd0\xa0\xf7\xe1\x9a2\xc5i\xd2q\xab\xfc\x05\xd1f,0'}, {'tP': 'tel:+16106632676', 'D': True, 'sT': b"\x06\x01'\x0cb\x95\xcf/i\x92\xb5%\xe8\xaa/\xd4\xc9R\x06\xf0\xd9F\xe3\x87m\x932\x11\x0c\xf0*V\xfc\xf7K\xd8", 'P': b'\x02\x01\x1d\xa6v?\x86\xe1P\t\x07G\xe7\x980\x12X\xa1\xbaF\x01\xe0\x8a\xf0~\x8a\xb1\x9a\xf8\xa8\xd4s\r\xd7c\xbdd\x86\xbc\x85\xb28 }C\x88@\x02\x9f \x9a\x98(\x1e\xbbO\xa0\x05\xd7\xf3i\xbdy\xef K\xa9M\xf4\xd0\xf4\x04\xdb?X\xa3\xbcQ\xc8Z0\xbc\xaa\x9d\xfd\xd4\xa1?7\x19 \x1c\xdfE\xf6K>\xc3\x04\xa6"\xa9_\x7f\xc8\xbdf\xa8\x91\xfa-?c\xe4\x98\x8c%\xa5\xa4<\x87\x8b\x9d\xeat\x99Dn3\x8b)\xb6\xe5Z\x1f\xcerP\n\xba\\\xa3dh\x02\x1a\xcf\xe6\xe0oc\xf4:\xd7\xa5\xd1\xb6\xa6\xe2\x9e\x19\xc8\x14\x90<7\x00\x9b\xaed\x030\x88{)\xa4\x0c\x82\xf7E\xf6\xda\xea\xd4\xe7$/\x99\xbd\xe4DZ\x8a0k`\xd2\xaab4\xdb\xd2M\xd6\xb2\xcaB\xe9\x91\x86\xe09\xac\xc6\x90\xc8W\xc0\x12\x95\xa6z\x03\x8b\xb1I\x85\xe9\xbf\xdcZF\\\x0b\xa7\x13\xa8}\x81\x01n\xa0\xcf\x8a\xeba\x19\xcf\xc5v$\x10\x0c\x99\x11\xb6\xd2\xfb\xa0\xfe\x89\x9c\x0f3\r" \x96?S\xbf\x95\x0f\xeeP>M+.\xe6\rj\xd0\xfa?\x8fS\xbeH0F\x02!\x00\xa6\xa5\xca\x16\x84y\xaeg\x13\x8c\x0bW\x8c\x14\xcc."\'\xbf\xfa\xcf\xf5\xaa\xb9\x85\x86\xbc\x81\xe0-\xfb\x10\x02!\x00\x92\x03S\xc8\x06\xfb\xfd\x15\xb7\xf7\x81\x05\xad\xc7Md\xcd\r7\x99)\x147\xd5\x95\xefW\xbe\x01\xe9\xe2\x0e', 't': b'\xa7\xfd\xaf\xac\xdf\x13 \x92m\x9eD\xe9l\x9b\x1c\xca&\xc3K\x8d\xabs(\xe0\xcc\x1e]WEV\x9d*'}, {'tP': 'mailto:testu3@icloud.com', 'D': False, 'sT': b'\x06\x01G\xa6]\xdep_\xe5\xc4I=\x98,\x85\xccW\x9c\xdb\xdb`/\xc5J\xf0\xb9MD/\x0e.\xe3\xfa\x95_\xa1', 'P': b'\x02\x01\x1dA\xcd\xafa\x8e\x8c\x82\x85\xe6PW\xf3\xf8\xc4\xabK\x8b\xb0\x1cCb\x17\xa1\xb2\xed\x82_2\xdb\x99\xc6\xddu\xca\x07hw!\x08\xf2\xe2\n\x0f\'9\xb5\x11Z\xe4K\xd7\x94j\xfa\x05g\xa7\x8d*\xe5L\xf4\x86` \xf5\x94\x98\xae\x85\xe4 \xaa\xeb\x1c6\x97&sD\x00\xb2\xa6!\xb5\xf1ZiO=\xc6,\x19K\x0caC\x0b\xb8\x05\x1e\x9f6w\xaa\x9d\xed^;\t\x86\xf7\x9b\xbc\xde\r\x9d>\x03\x00\xd8\x96\x00/\x05\x0b\xbf\xf9\xad;\x98\xc2\xc2\xd9*\xfc:-\x90\x17l\xac\x17_d\r*\xbdNe"\xb0O\xbd\x93\x80$\xdc:\xc0(\x1ds\nvY\xc3H[\xb2\xbe\xa1\x18\xde\xc6\x08\xfa\x9dh\xc54SNZa\x97\xa55X\xa8\xf1\xfb\xdd\xd9\xea\x83\xb0\xa5J\x7f\x19>\t\xec\xc2D5\x0e{yLd5\x96n\xe4*\xf1s\x02\xa9\xf0\xdcu)\r\xe6w\x00\xd1\xeb\xfb\x96\xa9\xd7\xfb\xe8.\x93\xb1 xm\xe2K_\x8c\x1c\x8c\xaf`\xa7\xf2\xe9a\x9e\xfbj\xf7\xde\xa1\x04;\xa4s\x92Dti\xd8\xa5\xe8\xf2\x9d\x8f#\x84q\x86\x97\xd7 \xf4\xd0&G0E\x02 \x05e\xa2\xf8\x0bR\xba\xa67N\xf0CbQ\n_E\x8e\x8d\xeb\x86\xe4r\x8bz\x11O\x02\x95m\xa4\x0b\x02!\x00\xf7X\xe1U`\xfe\xd3p:H\xf6\xd8\x02RT\xddkh\xa8s\xce\xc7j[uw\xb0\x9b\x19%\xcc\x13', 't': b'k\xfaU\xe7\x81KC\xd0\xa7\t\x13\xcd:\xcb&\xb1\xd4 \xda\n\xf1\x97\xee\x01~!\xf7\x01\xd2\xf0\xbb '}, {'tP': 'mailto:testu3@icloud.com', 'D': False, 'sT': b'\x06\x01\xb2\xbceF/L|\x83n\xa8K\x9c-\xb1\x8d\xe2\x89\xe9\xfc\xa09\xb7\xdbg\xba\xc1\xb8\x96X\xd1\xe3%w|', 'P': b'\x02\x01\x1d\xc1g9\x141\x1aR\xda\xde}^c\x1e9\xdam\xd4\xe9V\x0eR}\xb3\x11\xea\xf2\x84\x1a$A\xb2[!\xe0\xaa\x0b\x96\xd1\xd6\x8d(]\x02\x93\xbf,\xbe\x89\x8e\xfd&\x91\t\xc8\xfa\xb7\xf9\xe4\xf1\x80O\x93@\xd3\xd5\xb9\xe8se\xdb\x06\x0e\xe1\x08E\x96\x02\xd3\x87\xe6\x0e\x92\xa7^\xd4\xa1\xb3\xeb\xb9\xf8\xf3\xcc\xf3\x8fi\x1e\x8fwI\x87\x83v\x07I\xae2\xad<\xe1zm\x19"\xcc\xdeE<5p4\xd8\xf1\x8bq\xb0\xb4\xb8\x94\xb17\x9f\xdf\xd5\xd9\xebXK?\xa3G\xe8\xdf[\x9b\xbcP&)\x17\xe0n\xb7\xd5\xe2\x06\xcd3\x84\x18\x99\xb5\xf5\x89p\xc5\xe0=\xba\t_\xa8ZqI\xf5tf]\xde\xc4\xe7\xc8\xb4\x923\x8fd\x1e\xa6\xd2\xa9\x83\xa7\x05\xa9\xbcO\x8er\xcd\xf2\'E\xac!.\x80\x9d\x7f\x14\xe3\x98\x9bt\x0ef\xe0\xb3\x8d\xf4\xb7fU\xd3\xbfd\xba\xbf\n\xf1\xa4\xd5\x82_\xb4\x1b#\xae\xe3\x96\x1e\xf5\xd35\xdcB\x1f\x1b\xa0\x8b\r\x18\x8e\x93\xf1\xf2\x0e\xd3\xcd\xca\xf8P\xb5B\xd0l\x8aU\x87\xcd\x11\xf1\xb8\x16\x9f\xcf\xa7\xb8\x8cpE0\x9b\xeb\xf3G0E\x02!\x00\xedsa\xcb\x96A=\x1dv\xde\x1c3#\x04\x05<,T\xe5\xc6\x8f\x94q\x9a\xce\xe5\x82\xa0\xa4q\x02\xbc\x02 G\xe7\x80\x1c\r\xe2\xa3\xe9\xc5\xd1\xf3J*q\x91]K\xbd\x88\xd6h\xc0\xd6z\xb0f\x9c\xae\x0e\xc6\xa8\x7f', 't': b'\x8c\x9f:\x8d6\x1b\xbfY\x86W\x03\xb8\xe0\xfc\x9f\xb9\x9fe\x87z9\xe9\x08\xce\x13\x7fI\x93\xc6}\xf4\xdf'}],
        #     #'dtl': [{}],
        #     #'U': b'Qk\xfb7\x91\xe5N\xf0\xbb\xd6\x8eu\th\xe0U'
        #     'U': message_id.bytes,
        # }

        

        print(body)

        body = plistlib.dumps(body, fmt=plistlib.FMT_BINARY)

        self.connection.send_message("com.apple.madrid", body)

        def check_response(x):
            if x[0] != 0x0A:
                return False
            if apns._get_field(x[1], 2) != sha1("com.apple.madrid".encode()).digest():
                return False
            resp_body = apns._get_field(x[1], 3)
            if resp_body is None:
                return False
            resp_body = plistlib.loads(resp_body)
            if 'c' not in resp_body or resp_body['c'] != 255:
                return False
            return True

        num_recv = 0
        while True:
            if num_recv == len(bundled_payloads) -1:
                break
            payload = self.connection.incoming_queue.wait_pop_find(check_response)
            if payload is None:
                continue

            resp_body = apns._get_field(payload[1], 3)
            resp_body = plistlib.loads(resp_body)
            logger.error(resp_body)
            num_recv += 1



        # # Encrypt the message for each participant
        # lookup = self.user.lookup(message.participants[:-1])
        # for participant in message.participants[:-1]:            
        #     for identity in lookup[participant]['identities']:
        #         if 'client-data' in identity and 'public-message-identity-key' in identity['client-data'] and 'push-token' in identity:
        #             push_token = identity['push-token']
        #             identity_keys = ids.identity.IDSIdentity.decode(identity['client-data']['public-message-identity-key'])
        #             payload = self._encrypt_sign_payload(identity_keys, raw)
        #             #import time
        #             body = {
        #                 "t": self.connection.token,
        #                 "P": payload,
        #                 "c": 100,
        #                 "E": "pair",
        #                 "sP": self.user.handles[0],
        #                 "tP": participant,
        #                 "U": mid.bytes,
        #                 'v': 8,
        #                 #'D': True,
        #                 'e': time.time_ns(),
        #                 #'htu': True
        #                 #'e': 1,
        #                 # missing 'e'????
        #             }
        #             logger.debug(f"body {body}")
        #             body = plistlib.dumps(body, fmt=plistlib.FMT_BINARY)
        #             from base64 import b64encode
        #             logger.debug(f"Sending message to {participant} with payload {body} and token {b64encode(push_token)}")
        #             self.connection.send_message("com.apple.madrid", body)

        #             # Wait for a response
        #             def check_response(x):
        #                 if x[0] != 0x0A:
        #                     return False
        #                 if apns._get_field(x[1], 2) != sha1("com.apple.madrid".encode()).digest():
        #                     return False
        #                 resp_body = apns._get_field(x[1], 3)
        #                 if resp_body is None:
        #                     return False
        #                 resp_body = plistlib.loads(resp_body)
        #                 return True
                    
        #             # Wait for a few sec to wait for it
        #             for i in range(10):
        #                 payload = self.connection.incoming_queue.wait_pop_find(check_response)
        #                 if payload is not None:
        #                     break
        #                 time.sleep(0.1)

        #             if payload is None:
        #                 raise Exception("Failed to send message")
                    
        #             # Check the response
        #             resp_body = apns._get_field(payload[1], 3)
        #             resp_body = plistlib.loads(resp_body)
        #             logger.error(resp_body)
                    

        logger.error(f"Sent {message}")

    def testing(self, message: iMessage):
        # Set the group id, if it isn't already
        if message.group_id is None:
            message.group_id = str(uuid.uuid4()).upper() # TODO: Keep track of group ids?
        mid = uuid.uuid4()
        message.id = str(mid).upper()

        # Turn the message into a raw message
        raw = message.to_raw()

        payload = self._encrypt_sign_payload(self.user.encryption_identity, raw)

        body = {
            "t": self.connection.token,
            "P": payload,
            "c": 101,
            "E": "pair",
            "sP": self.user.handles[0],
            "tP": self.user.handles[0],
            "U": mid.bytes,
            'v': 1,
            'D': True,
            'e': time.time_ns(),
            'htu': True
        }

        #body = {'t': b"\xe5^\xc0c\xe8\xa4\x1e\xbe\x03\x89'\xea\xd5m\x94\x05\xae\xf5\x1bqK\x1aJTH\xa4\xeb8\xb8<\xd7)", 'e': 1690644797594380146, 'tP': 'mailto:testu3@icloud.com', 'U': b'\xbcL\x1fL\x84\x85E\xb8\xb2\x1c\x8d+\xd7\x02-\x0b', 'v': 8, 'P': b"\x02\x01\x1cQT\x03Y\xe4\xa2l;\x8b\x89'#\xb2\xde}\xa5\xc8#\x0b\xeer\xa7\xfc\xf7W\xc5\x9f\xf0\x98\x8dve\xd8?\x04,v\xb1B?@\xce\x15\x1c,\x90\xb6\x91\x96\xe2/\xae?\x86+%\xa30T\x0b[\x90\xde$ED/\xf2\x88#{\xb3\x1d|@\x0fG\xfaV\xc8\x85#\xc45\xcf\x8d\xfd\x96B\x9c\x04\x19\xac\xa0vu\xa1h|A!\x9d\x1a\xd8\xf9\xe9\xe9\xe3\xdf\xe0\xbd\x19}\xcb\xdd\x0b,\xcc\x06S\x9d\x8cag\x82\xb2sa\x9c\xb2%\x16\xfc?\x86\xf6\xcc\x8c\xce\x06\xdf\xe1G\xc5\xf5@\xcc'\x8c\xdcj\xcfpbC\xf6\xcbl\xa4\xde\x8a\xb14\xf1s\x0f\x84\x98\\\xb9~):\x8d\xa6g\xed\tEv\xda\x0e\xc6\x84~d\xf8\x83\xb8\xc9\xec>.(\xa6\x10U\xb6\x80Zr\xbc\xf4\x1c@nc,\x9a\xc5'\x99z\x9c\xc9\xc5-\xba\xe1\xb7\xf1p\xf7\xe4\xa4/am\xde\xecB\xd9(\xec\x1e\xe5\x8f\xd8\xfa7\xca\xa6\xec\xf9\x8b\xeb\xb0\xad\x14*\x05\x17\xb5a0<\x193\xbf\xfc\x12\xcfxf{\xd7\xef\x93\xa3nS\x07\xc9;\xac'!\xb7\x14\x03\xeflZ[G0E\x02!\x00\xb5\x08\xfb\x11\xd5o\x05\xa9\xb2\xa64H\xab/\xcf7;\x97c54a\xea\xc8\x16\x91R\xc2D\x82W\xbf\x02  \nZ\xe6\x9a\xcf\x9do\x17\x9b\xa4\x1d\x11\xf8\x1a\x8c/\t\xf7\xedb\x98,\x8c?\xd2\xb8q\xee\xe5V\xf4", 'sP': 'mailto:testu3@icloud.com', 'E': 'pair', 'htu': True, 'c': 100}


        print(body)


        body = plistlib.dumps(body, fmt=plistlib.FMT_BINARY)

        self.connection.send_message("com.apple.madrid", body)

        #body2 = plistlib.loads(body)
        #dec = self._decrypt_payload(body2['P'])

        #print(dec)

        def check_response(x):
            if x[0] != 0x0A:
                return False
            if apns._get_field(x[1], 2) != sha1("com.apple.madrid".encode()).digest():
                return False
            resp_body = apns._get_field(x[1], 3)
            if resp_body is None:
                return False
            resp_body = plistlib.loads(resp_body)
            return True

        for i in range(10):
            payload = self.connection.incoming_queue.wait_pop_find(check_response)
            if payload is not None:
                break
            time.sleep(0.1)


        resp_body = apns._get_field(payload[1], 3)
        resp_body = plistlib.loads(resp_body)
        logger.error(resp_body)



        # # Encrypt the message for each participant
        # lookup = self.user.lookup(message.participants[:-1])
        # for participant in message.participants[:-1]:            
        #     for identity in lookup[participant]['identities']:
        #         if 'client-data' in identity and 'public-message-identity-key' in identity['client-data'] and 'push-token' in identity:
        #             push_token = identity['push-token']
        #             identity_keys = ids.identity.IDSIdentity.decode(identity['client-data']['public-message-identity-key'])
        #             payload = self._encrypt_sign_payload(identity_keys, raw)
        #             body = {
        #                 "t": self.connection.token,
        #                 "P": payload,
        #                 "c": 100,
        #                 "E": "pair",
        #                 "sP": self.user.handles[0],
        #                 "tP": participant,
        #                 "U": mid.bytes,
        #                 'v': 8,
        #                 'D': True,
        #                 'e': time.time_ns(),
        #                 'htu': True
        #                 #'e': 1,
        #                 # missing 'e'????
        #             }
        #             logger.debug(f"body {body}")
        #             body = plistlib.dumps(body, fmt=plistlib.FMT_BINARY)
        #             from base64 import b64encode
        #             logger.debug(f"Sending message to {participant} with payload {body} and token {b64encode(push_token)}")
        #             self.connection.send_message("com.apple.madrid", body)

        #             # Wait for a response
        #             def check_response(x):
        #                 if x[0] != 0x0A:
        #                     return False
        #                 if apns._get_field(x[1], 2) != sha1("com.apple.madrid".encode()).digest():
        #                     return False
        #                 resp_body = apns._get_field(x[1], 3)
        #                 if resp_body is None:
        #                     return False
        #                 resp_body = plistlib.loads(resp_body)
        #                 return True
                    
        #             # Wait for a few sec to wait for it
        #             for i in range(10):
        #                 payload = self.connection.incoming_queue.wait_pop_find(check_response)
        #                 if payload is not None:
        #                     break
        #                 time.sleep(0.1)

        #             if payload is None:
        #                 raise Exception("Failed to send message")
                    
        #             # Check the response
        #             resp_body = apns._get_field(payload[1], 3)
        #             resp_body = plistlib.loads(resp_body)
        #             logger.error(resp_body)
                    

        # logger.error(f"Sent {message}")