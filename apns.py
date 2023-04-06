from __future__ import annotations

class Fields:
    @staticmethod
    def from_bytes(data: bytes) -> Fields:
        fields = {}

        while len(data) > 0:
            field = data[0]
            length = int.from_bytes(data[1:3], "big")
            value = data[3:3 + length]

            fields[field] = value

            data = data[3 + length:]

        return Fields(fields)

    def __init__(self, fields: dict[int, bytes]):
        self.fields = fields

    def to_bytes(self) -> bytes:
        buffer = bytearray()

        for field, value in self.fields.items():
            buffer.append(field)
            buffer.extend(len(value).to_bytes(2, "big"))
            buffer.extend(value)

        return buffer

    # Debug formating
    def __str__(self) -> str:
        return f"{self.fields}"

# Define number to command name mapping
COMMANDS = {
    0x7: "Connect",
    0x8: "ConnectResponse",
    0x9: "PushTopics",
    0x0A: "PushNotification",
    0x0B: "Acknowledge",
}

class Payload:
    @staticmethod
    def from_stream(stream) -> Payload|None:
        command = int.from_bytes(stream.read(1), "big")
        if command == 0:
            return None # We reached the end of the stream
        length = int.from_bytes(stream.read(4), "big")
        fields = Fields.from_bytes(stream.read(length))

        return Payload(command, fields)
    
    @staticmethod
    def from_bytes(data: bytes) -> Payload:
        # Convert it to bytes for cleaner printing
        data = bytes(data)
        command = data[0]
        length = int.from_bytes(data[1:5], "big")
        fields = Fields.from_bytes(data[5:5 + length])

        return Payload(command, fields)
    
    def __init__(self, command: int, fields: Fields):
        self.command = command
        self.fields = fields

    def to_bytes(self) -> bytes:
        buffer = bytearray()

        buffer.append(self.command)

        fields = self.fields.to_bytes()

        buffer.extend(len(fields).to_bytes(4, "big"))
        buffer.extend(fields)

        return buffer

    # Debug formating
    def __str__(self) -> str:
        return f"{COMMANDS[self.command]}: {self.fields}"
    
import courier
from hashlib import sha1

class APNSConnection(): 
    def __init__(self, token: bytes=None, private_key=None, cert=None):
        self.sock, self.private_key, self.cert = courier.connect(private_key, cert)
        self.token = token

        self._connect()
    
    def _connect(self):
        if self.token is None:
            payload = Payload(7, Fields({2: 0x01.to_bytes()}))
        else:
            payload = Payload(7, Fields({1: self.token, 2: 0x01.to_bytes()}))
        
        self.sock.write(payload.to_bytes())

        resp = Payload.from_stream(self.sock)

        if resp.command != 8 or resp.fields.fields[1] != 0x00.to_bytes():
            raise Exception("Failed to connect")
        
        if 3 in resp.fields.fields:
            self.token = resp.fields.fields[3]

    def filter(self, topics: list[str]):
        payload = Payload(9, Fields({1: self.token, 2: b"".join([sha1(topic.encode()).digest() for topic in topics])}))

        self.sock.write(payload.to_bytes())

    

if __name__ == "__main__":
    import courier
    import base64

    sock = courier.connect()

    # Try and read the token from the file
    try:
        with open("token", "r") as f:
            r = f.read()
            if r == "":
                raise FileNotFoundError
            payload = Payload(7, Fields({1: base64.b64decode(r), 2: 0x01.to_bytes()}))
    except FileNotFoundError:
        payload = Payload(7, Fields({2: 0x01.to_bytes()}))

    # Send the connect request (with or without the token)
    sock.write(payload.to_bytes())

    # Read the response
    resp = Payload.from_stream(sock)
    # Check if the response is valid
    if resp.command != 8 or resp.fields.fields[1] != 0x00.to_bytes():
        raise Exception("Failed to connect")
    
    # If there's a new token, save it
    if 3 in resp.fields.fields:
        with open("token", "wb") as f:
            f.write(base64.b64encode(resp.fields.fields[3]))

    # Send the push topics request
