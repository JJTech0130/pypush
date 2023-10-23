from base64 import b64encode
import emulated.nac

vd = emulated.nac.generate_validation_data()
vd = b64encode(vd).decode()
print(vd)