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
    
if __name__ == "__main__":
    import courier
    sock = courier.connect()
    payload = Payload(7, Fields({2: 0x01.to_bytes()}))
    sock.write(payload.to_bytes())
    print("recieved: ", Payload.from_stream(sock))
    print("recieved: ", Payload.from_stream(sock))
    sock.close()
# with socket.create_connection((COURIER_HOST, COURIER_PORT)) as sock:
#     with context.wrap_socket(sock, server_hostname=COURIER_HOST) as ssock:
#         payload = Payload(7, Fields({2: 0x01.to_bytes()}))
#         #print(payload)
#         #print(payload.to_bytes())
#         #print(Payload.from_bytes(payload.to_bytes()))
#         ssock.write(payload.to_bytes())
#         print("recieved: ", Payload.from_stream(ssock))
#         print("recieved: ", Payload.from_stream(ssock))