from . import ids_pb2, _helpers

import logging
logger = logging.getLogger("ids")

def parse_loggable_data(data: bytes):
    # Parse as a LoggableData
    loggable_data = ids_pb2.KeyTransparencyLoggableData()
    loggable_data.ParseFromString(data)
    #print(loggable_data)

    logger.debug(f"LoggableData: {loggable_data}")
    
    identity = ids_pb2.NgmPublicIdentity()
    identity.ParseFromString(loggable_data.ngmPublicIdentity)

    key = _helpers.parse_compact_key(identity.publicKey)

    return key

def create_loggable_data():
    """
    This function must create the key so we know it fits in the compact format
    """

    pub, key = _helpers.create_compact_key()

    identity = ids_pb2.NgmPublicIdentity()
    identity.publicKey = pub

    loggable_data = ids_pb2.KeyTransparencyLoggableData()
    loggable_data.ngmPublicIdentity = identity.SerializeToString()



    return loggable_data.SerializeToString(), key

    