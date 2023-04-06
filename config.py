import requests
import plistlib

#CONFIG_URL = "http://init-p01st.push.apple.com/bag"
CONFIG_URL = "https://init.push.apple.com/bag"

def get_config():

    r = requests.get(CONFIG_URL, verify=False)
    if r.status_code != 200:
        raise Exception("Failed to get config")
    
    # Parse the config as a plist
    config = plistlib.loads(r.content)

    # Parse the nested "bag" as a plist
    #config["bag"] = plistlib.loads(config["bag"])

    return config

if __name__ == "__main__":
    config = get_config()
    print(config)