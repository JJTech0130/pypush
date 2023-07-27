import plistlib

import requests
import logging
logger = logging.getLogger("bags")

OLD_APNS_BAG = None
def apns_init_bag_old():
    global OLD_APNS_BAG

    if OLD_APNS_BAG is not None:
        return OLD_APNS_BAG
    
    r = requests.get("https://init.push.apple.com/bag", verify=False)
    if r.status_code != 200:
        raise Exception("Failed to get APNs init bag")

    # Parse the config as a plist
    bag = plistlib.loads(r.content)

    logger.debug("Received APNs old-style init bag")

    OLD_APNS_BAG = bag

    return bag


# This is the same as the above, but the response has a signature which we unwrap
APNS_BAG = None
def apns_init_bag():
    global APNS_BAG

    if APNS_BAG is not None:
        return APNS_BAG
    
    r = requests.get("http://init-p01st.push.apple.com/bag", verify=False)
    if r.status_code != 200:
        raise Exception("Failed to get APNs init bag 2")

    content = plistlib.loads(r.content)
    bag = plistlib.loads(content["bag"])

    logger.debug("Received APNs new init bag")

    APNS_BAG = bag

    return bag


IDS_BAG = None
def ids_bag():
    global IDS_BAG

    if IDS_BAG is not None:
        return IDS_BAG
    
    r = requests.get(
        "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3", verify=False
    )
    if r.status_code != 200:
        raise Exception("Failed to get IDS bag")

    # Parse the config as a plist
    content = plistlib.loads(r.content)
    # Load the inner bag
    bag = plistlib.loads(content["bag"])

    logger.debug("Recieved IDS bag")

    IDS_BAG = bag

    return bag


if __name__ == "__main__":
    # config = get_config()
    # print(config)
    # print(apns_init_bag_2())
    # print(apns_init_bag_2() == apns_init_bag())
    bag = ids_bag()
    for key in bag:
        # print(key)
        # print(bag[key])
        if type(bag[key]) == str:
            if "http" in bag[key]:
                print(key, bag[key])
