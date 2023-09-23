import requests, random, plistlib, zipfile
from io import BytesIO

appleplist = None

def getMasterList():
    global appleplist
    if (appleplist is None):
        appleplist = plistlib.loads(requests.get("https://itunes.apple.com/WebObjects/MZStore.woa/wa/com.apple.jingle.appserver.client.MZITunesClientCheck/version?languageCode=en").content)
    return appleplist

def getGatewayMCCMNC(MCCMNC):
    gateways = getGatewaysMCCMNC(MCCMNC)
    if gateways is None:
        return None
    return gateways[random.randrange(0, len(gateways))]

def getGatewaysMCCMNC(MCCMNC):
    bundles = getBundlesMCCMNC(MCCMNC)
    gateway = None
    if bundles is None:
        return
    for bundle in bundles:
        gateway = getGatewayFromBundle(parseBundle(bundle["Bundle"]))
        if gateway is not None:
            break
    return gateway

def getBundlesMCCMNC(MCCMNC):
    appleplist = getMasterList()
    bundlelist = []
    if MCCMNC in appleplist["MobileDeviceCarriersByMccMnc"]:
        mmo = appleplist["MobileDeviceCarriersByMccMnc"][MCCMNC]
        if "BundleName" in mmo:
            bundle = getBundleByName(mmo["BundleName"])
            if bundle is not None:
                bundlelist.append({"Name": mmo["BundleName"], "Bundle": bundle})
        if "MVNOs" in mmo:
            for mv in mmo["MVNOs"]:
                if "BundleName" in mv:
                    bundle = getBundleByName(mv["BundleName"])
                    if bundle is not None:
                        bundlelist.append({"Name": mv["BundleName"], "Bundle": bundle})
        return bundlelist
    else:
        return None

def getGatewayFromBundle(bundledict):
    applecarrierplist = bundledict
    if "PhoneNumberRegistrationGatewayAddress" in applecarrierplist:
        regnum = applecarrierplist["PhoneNumberRegistrationGatewayAddress"]
        if (type(regnum) == str):
            regnum = [regnum]
        return regnum
    return None

def parseBundle(bundle):
    bundlebytes = BytesIO(bundle)
    bundlezip = zipfile.ZipFile(bundlebytes)
    carrierpath = [path for path in bundlezip.namelist() if path.startswith("Payload/") and path.endswith("/carrier.plist")][0]
    applecarrierplist = plistlib.load(bundlezip.open(carrierpath, "r"))
    return applecarrierplist

def getBundleByName(BundleName):
    appleplist = getMasterList()
    if BundleName in appleplist["MobileDeviceCarrierBundlesByProductVersion"]:
        x = BundleName
        greatestver = "0"
        for y in appleplist["MobileDeviceCarrierBundlesByProductVersion"][x]:
            try:
                inty = float(y)
            except:
                continue
            if (inty > float(greatestver)):
                greatestver = y
        if greatestver != "0":
            return requests.get(appleplist["MobileDeviceCarrierBundlesByProductVersion"][x][greatestver]["BundleURL"]).content
        else:
            return None
    return None