import ids
from ids import encryption

from rich.logging import RichHandler
import logging
logging.basicConfig(
    level=logging.NOTSET, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)

# Set sane log levels
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("py.warnings").setLevel(logging.ERROR)  # Ignore warnings from urllib3
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("jelly").setLevel(logging.INFO)
logging.getLogger("nac").setLevel(logging.INFO)
logging.getLogger("apns").setLevel(logging.INFO)
logging.getLogger("albert").setLevel(logging.INFO)
logging.getLogger("ids").setLevel(logging.DEBUG)
logging.getLogger("bags").setLevel(logging.INFO)
logging.getLogger("imessage").setLevel(logging.INFO)

logging.captureWarnings(True)

test = "0a220a200d6cbecaf7e8b2896b181eb92c64f8e20abf8de145d6f354cbd99964d16d6beb100c180522450801124104e3e7592e7a570f9d95c2c5d99e4305a0952ea94457a9fba9aa1a86380eeee68f2512a30d01e1bb974d9a19169444cd76ebef656d3fb3ef7a4d237e61920f4fab"
test2 = b'\n"\n \rl\xbe\xca\xf7\xe8\xb2\x89k\x18\x1e\xb9,d\xf8\xe2\n\xbf\x8d\xe1E\xd6\xf3T\xcb\xd9\x99d\xd1mk\xeb\x10\x0c\x18\x05"E\x08\x01\x12A\x04\xe3\xe7Y.zW\x0f\x9d\x95\xc2\xc5\xd9\x9eC\x05\xa0\x95.\xa9DW\xa9\xfb\xa9\xaa\x1a\x868\x0e\xee\xe6\x8f%\x12\xa3\r\x01\xe1\xbb\x97M\x9a\x19\x16\x94D\xcdv\xeb\xefem?\xb3\xefzM#~a\x92\x0fO\xab'
print(test2.hex())
test3 = b'\n"\n \xa0F\x01\xf7x]\xbb\x11<\x98y\xba\xd3<\xec\xa2s\x95\x02\xc4\x17\x95\xfc\x83!\x88\x96P\xa9\x01\xc2\x9c\x10\x0c\x18\x05'
test = bytes.fromhex(test)
#encryption.parse_loggable_data(test)
print(encryption.parse_loggable_data(test2))
print(encryption.parse_loggable_data(test3))

print(encryption.create_loggable_data()[0])