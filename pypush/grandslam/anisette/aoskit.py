import objc
from Foundation import NSBundle, NSClassFromString  # type: ignore

AOSKitBundle = NSBundle.bundleWithPath_(
    "/System/Library/PrivateFrameworks/AOSKit.framework"
)
objc.loadBundleFunctions(AOSKitBundle, globals(), [("retrieveOTPHeadersForDSID", b"")])  # type: ignore
util = NSClassFromString("AOSUtilities")

h = util.retrieveOTPHeadersForDSID_("-2")

o = {
    "X-Apple-I-MD": str(h["X-Apple-MD"]),
    "X-Apple-I-MD-M": str(h["X-Apple-MD-M"]),
}
print(o)
    # h["X-Apple-I-MD"] = str(h["X-Apple-MD"])
    # h["X-Apple-I-MD-M"] = str(h["X-Apple-MD-M"])
    # print(o)
    #return o