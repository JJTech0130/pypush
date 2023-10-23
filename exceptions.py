
class GatewayError(Exception):
    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return self.reason


class GatewayConnectionError(Exception):
    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return self.reason


class DecodeError(Exception):
    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return self.reason


class InvalidResponseError(Exception):
    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return self.reason