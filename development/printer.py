import plistlib
import zlib
from base64 import b64decode, b64encode
from hashlib import sha1

# Taken from debug logs of apsd
enabled_topics = "(com.apple.icloud-container.com.apple.avatarsd, com.icloud.askpermission, com.apple.icloud-container.com.apple.Safari, com.apple.itunesstored, com.apple.icloud-container.clouddocs.com.apple.CloudDocs.health, com.apple.passd.usernotifications, com.apple.icloud-container.com.apple.donotdisturbd, com.apple.icloud-container.clouddocs.iCloud.com.reddit.reddit, com.apple.mobileme.fmf3, com.apple.icloud-container.com.apple.cloudpaird, com.apple.icloud-container.clouddocs.com.apple.Pages, com.apple.appstored-testflight, com.apple.askpermissiond, com.apple.icloud-container.com.apple.willowd, com.me.cal, com.apple.icloud-container.com.apple.suggestd, com.apple.icloud-container.clouddocs.F3LWYJ7GM7.com.apple.garageband10, com.apple.icloud-container.clouddocs.com.apple.CloudDocs.container-metadata, com.apple.icloud-container.com.apple.callhistory.sync-helper, com.apple.icloud-container.com.apple.syncdefaultsd, com.apple.icloud-container.com.apple.SafariShared.Settings, com.apple.pay.services.products.prod, com.apple.icloud-container.com.apple.StatusKitAgent, com.apple.icloud-container.com.apple.siriknowledged, com.me.contacts, com.apple.icloud-container.com.apple.TrustedPeersHelper, com.apple.icloud-container.clouddocs.iCloud.com.apple.iBooks, com.apple.icloud-container.clouddocs.iCloud.dk.simonbs.Scriptable, com.apple.icloud-container.clouddocs.com.apple.ScriptEditor2, com.icloud.family, com.apple.idmsauth, com.apple.watchList, com.apple.icloud-container.clouddocs.com.apple.TextEdit, com.apple.icloud-container.com.apple.VoiceMemos, com.apple.sharedstreams, com.apple.pay.services.apply.prod, com.apple.icloud-container.com.apple.SafariShared.CloudTabs, com.apple.wallet.sharing.qa, com.apple.appstored, com.apple.icloud-container.clouddocs.3L68KQB4HG.com.readdle.CommonDocuments, com.apple.icloud-container.clouddocs.com.apple.CloudDocs.pp-metadata, com.me.setupservice, com.apple.icloud-container.com.apple.amsengagementd, com.apple.icloud-container.com.apple.appleaccount.beneficiary.private, com.apple.icloud-container.com.apple.appleaccount.beneficiary, com.apple.icloud-container.clouddocs.com.apple.mail, com.apple.icloud-container.com.apple.appleaccount.custodian, com.apple.icloud-container.com.apple.securityd, com.apple.icloud-container.com.apple.iBooksX, com.apple.icloud-container.clouddocs.com.apple.QuickTimePlayerX, com.apple.icloud-container.clouddocs.com.apple.TextInput, com.apple.icloud-container.com.apple.icloud.fmfd, com.apple.tv.favoriteTeams, com.apple.pay.services.ownershipTokens.prod, com.apple.icloud-container.com.apple.passd, com.apple.amsaccountsd, com.apple.pay.services.devicecheckin.prod.us, com.apple.storekit, com.apple.icloud-container.com.apple.keyboardservicesd, paymentpass.com.apple, com.apple.aa.setupservice, com.apple.icloud-container.clouddocs.com.apple.shoebox, com.apple.icloud-container.clouddocs.F3LWYJ7GM7.com.apple.mobilegarageband, com.apple.icloud-container.com.apple.icloud.searchpartyuseragent, com.apple.icloud-container.clouddocs.iCloud.com.apple.configurator.ui, com.apple.icloud-container.com.apple.gamed, com.apple.icloud-container.clouddocs.com.apple.Keynote, com.apple.icloud-container.com.apple.willowd.homekit, com.apple.amsengagementd.notifications, com.apple.icloud.presence.mode.status, com.apple.aa.idms, com.apple.icloud-container.clouddocs.iCloud.com.apple.MobileSMS, com.apple.gamed, com.apple.icloud-container.clouddocs.iCloud.is.workflow.my.workflows, com.apple.icloud-container.clouddocs.iCloud.md.obsidian, com.apple.icloud-container.clouddocs.com.apple.CloudDocs, com.apple.wallet.sharing, com.apple.icloud-container.clouddocs.iCloud.com.apple.iBooks.iTunesU, com.apple.icloud.presence.shared.experience, com.apple.icloud-container.com.apple.imagent, com.apple.icloud-container.com.apple.financed, com.apple.pay.services.account.prod, com.apple.icloud-container.com.apple.assistant.assistantd, com.apple.pay.services.ck.zone.prod, com.apple.icloud-container.com.apple.security.cuttlefish, com.apple.icloud-container.clouddocs.com.apple.iBooks.cloudData, com.apple.peerpayment, com.icloud.quota, com.apple.pay.provision, com.apple.icloud-container.com.apple.upload-request-proxy.com.apple.photos.cloud, com.apple.icloud-container.com.apple.appleaccount.custodian.private, com.apple.icloud-container.clouddocs.com.apple.Preview, com.apple.maps.icloud, com.apple.icloud-container.com.apple.reminders, com.apple.icloud-container.com.apple.SafariShared.WBSCloudBookmarksStore, com.apple.idmsauthagent, com.apple.icloud-container.clouddocs.com.apple.Numbers, com.apple.bookassetd, com.apple.pay.auxiliary.registration.requirement.prod, com.apple.icloud.fmip.voiceassistantsync)"
opportunistic_topics = "(com.apple.madrid, com.apple.icloud-container.com.apple.photos.cloud, com.apple.private.alloy.ded, com.apple.private.ac, com.apple.private.alloy.coreduet.sync, com.apple.private.alloy.sms, com.apple.private.alloy.ids.cloudmessaging, com.apple.private.alloy.maps, com.apple.private.alloy.facetime.mw, com.apple.private.alloy.facetime.sync, com.apple.private.alloy.maps.eta, com.apple.private.alloy.thumper.keys, com.apple.private.alloy.phonecontinuity, com.apple.private.alloy.continuity.tethering, com.apple.private.alloy.biz, com.apple.private.alloy.tips, com.apple.private.alloy.keytransparency.accountkey.pinning, com.apple.private.alloy.nearby, com.apple.private.alloy.itunes, com.apple.private.alloy.status.keysharing, com.apple.private.alloy.facetime.video, com.apple.private.alloy.screentime.invite, com.apple.private.alloy.proxiedcrashcopier.icloud, com.apple.private.alloy.classroom, com.apple.private.alloy.carmelsync, com.apple.ess, com.apple.private.alloy.facetime.lp, com.apple.private.alloy.icloudpairing, com.apple.private.alloy.accounts.representative, com.apple.private.alloy.gamecenter.imessage, com.apple.private.alloy.photostream, com.apple.private.alloy.electrictouch, com.apple.private.alloy.messagenotification, com.apple.private.alloy.avconference.icloud, com.apple.private.alloy.fmd, com.apple.private.alloy.usagetracking, com.apple.private.alloy.fmf, com.apple.private.alloy.home.invite, com.apple.private.alloy.phone.auth, com.apple.private.alloy.quickrelay, com.apple.private.alloy.copresence, com.apple.private.alloy.home, com.apple.private.alloy.digitalhealth, com.apple.private.alloy.multiplex1, com.apple.private.alloy.screensharing.qr, com.apple.private.alloy.contextsync, com.apple.private.alloy.facetime.audio, com.apple.private.alloy.willow.stream, com.apple.private.ids, com.apple.private.alloy.continuity.activity, com.apple.private.alloy.gamecenter, com.apple.private.alloy.clockface.sharing, com.apple.private.alloy.safeview, com.apple.private.alloy.continuity.unlock, com.apple.private.alloy.continuity.encryption, com.apple.private.alloy.facetime.multi, com.apple.private.alloy.notes, com.apple.private.alloy.screentime, com.apple.private.alloy.willow, com.apple.private.alloy.accessibility.switchcontrol, com.apple.private.alloy.status.personal, com.apple.triald, com.apple.private.alloy.screensharing, com.apple.private.alloy.gelato, com.apple.private.alloy.safari.groupactivities, com.apple.private.alloy.applepay, com.apple.private.alloy.amp.potluck, com.apple.private.alloy.sleep.icloud, com.apple.icloud-container.com.apple.knowledge-agent)"
paused_topics = "(com.apple.icloud-container.company.thebrowser.Browser, com.apple.icloud-container.com.apple.sociallayerd, com.apple.icloud.fmip.app.push, com.apple.iBooksX, company.thebrowser.Browser, com.apple.icloud-container.com.apple.Maps, com.apple.mobileme.fmf2, com.apple.findmy, com.apple.iWork.Numbers, com.apple.jalisco, com.apple.iWork.Pages, com.apple.Notes, com.apple.Maps, com.apple.icloud-container.com.apple.Notes, com.apple.dt.Xcode, com.apple.sagad, com.apple.icloud.presence.channel.management, com.apple.icloud-container.com.apple.protectedcloudstorage.protectedcloudkeysyncing, com.apple.TestFlight, com.apple.icloud-container.com.apple.news, com.apple.music.social, com.apple.icloud-container.com.apple.iWork.Numbers, com.apple.news, com.apple.tilt, com.apple.icloud-container.com.apple.findmy, com.apple.icloud-container.com.apple.iWork.Pages)"

# Parse the topics into a list
enabled_topics = enabled_topics[1:-1].split(", ")
opportunistic_topics = opportunistic_topics[1:-1].split(", ")
paused_topics = paused_topics[1:-1].split(", ")

topics = enabled_topics + opportunistic_topics + paused_topics

# Calculate the SHA1 hash of each topic
topics_lookup = [(topic, sha1(topic.encode()).digest()) for topic in topics]


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def _lookup_topic(hash: bytes):
    for topic_lookup in topics_lookup:
        if topic_lookup[1] == hash:
            return topic_lookup[0]
    return None


# Returns the value of the first field with the given id
def _get_field(fields: list[tuple[int, bytes]], id: int) -> bytes:
    for field_id, value in fields:
        if field_id == id:
            return value
    return None


def _p_filter(prefix, fields: list[tuple[int, bytes]]):
    enabled = []
    ignored = []
    oppertunistic = []
    paused = []

    token = ""

    for field in fields:
        if field[0] == 1:
            token = b64encode(field[1])
            # print(f"Push Token: {b64encode(field[1])}")
        elif field[0] == 2:
            enabled.append(_lookup_topic(field[1]))
        elif field[0] == 3:
            ignored.append(_lookup_topic(field[1]))
        elif field[0] == 4:
            oppertunistic.append(_lookup_topic(field[1]))
        elif field[0] == 5:
            paused.append(_lookup_topic(field[1]))
        else:
            pass  # whatever, there's a 6 but it's not documented
            # print(f"Unknown field ID: {field[0]}")

    # Remove None values
    enabled = [topic.strip() for topic in enabled if topic is not None]
    ignored = [topic.strip() for topic in ignored if topic is not None]
    oppertunistic = [topic.strip() for topic in oppertunistic if topic is not None]
    paused = [topic.strip() for topic in paused if topic is not None]

    enabled = ", ".join(enabled)
    ignored = ", ".join(ignored)
    oppertunistic = ", ".join(oppertunistic)
    paused = ", ".join(paused)

    if not enabled:
        enabled = "None"
    if not ignored:
        ignored = "None"
    if not oppertunistic:
        oppertunistic = "None"
    if not paused:
        paused = "None"

    # Trim the list of topics
    if len(enabled) > 100:
        enabled = enabled[:100] + "..."
    if len(ignored) > 100:
        ignored = ignored[:100] + "..."
    if len(oppertunistic) > 100:
        oppertunistic = oppertunistic[:100] + "..."
    if len(paused) > 100:
        paused = paused[:100] + "..."
    # (Token: {token.decode()})
    print(
        f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.OKCYAN}Filter{bcolors.ENDC} {bcolors.WARNING}Enabled{bcolors.ENDC}: {enabled} {bcolors.FAIL}Ignored{bcolors.ENDC}: {ignored} {bcolors.OKBLUE}Oppertunistic{bcolors.ENDC}: {oppertunistic} {bcolors.OKGREEN}Paused{bcolors.ENDC}: {paused}"
    )


import apns


def pretty_print_payload(
    prefix, payload: tuple[int, list[tuple[int, bytes]]]
) -> bytes | None:
    id = payload[0]

    if id == 9:
        _p_filter(prefix, payload[1])
    elif id == 8:
        token_str = ""
        if _get_field(payload[1], 3):
            token_str = f"{bcolors.WARNING}Token{bcolors.ENDC}: {b64encode(_get_field(payload[1], 3)).decode()}"
        print(
            f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.OKCYAN}Connected{bcolors.ENDC} {token_str} {bcolors.OKBLUE}{_get_field(payload[1], 1).hex()}{bcolors.ENDC}"
        )
    elif id == 7:
        print(
            f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.OKCYAN}Connect Request{bcolors.ENDC}",
            end="",
        )
        if _get_field(payload[1], 1):
            print(
                f" {bcolors.WARNING}Token{bcolors.ENDC}: {b64encode(_get_field(payload[1], 1)).decode()}",
                end="",
            )
        if _get_field(payload[1], 0x0C):
            print(f" {bcolors.OKBLUE}SIGNED{bcolors.ENDC}", end="")
        if (
            _get_field(payload[1], 0x5)
            and int.from_bytes(_get_field(payload[1], 0x5)) & 0x4
        ):
            print(f" {bcolors.FAIL}ROOT{bcolors.ENDC}", end="")
        print()

        # for field in payload[1]:
        #    print(f"Field ID: {field[0]}")
        #    print(f"Field Value: {field[1]}")

        # 65 (user) or 69 (root)

        for i in range(len(payload[1])):
            # if payload[1][i][0] == 5:
            # if payload[1][i][1] == b'\x00\x00\x00A': # user
            #    payload[1][i][1] = b'\x00\x00\x00E'
            # elif payload[1][i][1] == b'\x00\x00\x00E': # root
            #    payload[1][i][1] = b'\x00\x00\x00A'
            # else:
            #    print("Unknown field value: ", payload[1][i][1])
            if payload[1][i][0] == 1:
                pass
                # payload[1][i] = (None, None)
                # payload[1][i] = (1, b64decode("D3MtN3e18QE8rve3n92wp+CwK7u/bWk/5WjQUOBN640="))

        out = apns._serialize_payload(payload[0], payload[1])
        # return out
    elif id == 0xC:
        print(
            f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.OKCYAN}Keep Alive{bcolors.ENDC}"
        )
    elif id == 0xD:
        print(
            f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.OKCYAN}Keep Alive Ack{bcolors.ENDC}"
        )
    elif id == 0x14:
        print(
            f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.OKCYAN}Set State{bcolors.ENDC}: {_get_field(payload[1], 1).hex()}"
        )
    elif id == 0x1D or id == 0x20:
        print(
            f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.WARNING}PubSub ??{bcolors.ENDC}"
        )
    elif id == 0xE:
        print(
            f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.WARNING}Token Confirmation{bcolors.ENDC}"
        )
    elif id == 0xA:
        topic = ""
        # topic = _lookup_topic(_get_field(payload[1], 1))
        # if it has apsd -> APNs in the prefix, it's an outgoing notification
        if "apsd -> APNs" in prefix:
            print(
                f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.OKBLUE}OUTGOING Notification{bcolors.ENDC}",
                end="",
            )
            topic = _lookup_topic(_get_field(payload[1], 1))
            # topic = _lookup_topic(_get_field(payload[1], 1))
            # if b"bplist" in _get_field(payload[1], 3):
            #     print(f" {bcolors.OKCYAN}Binary{bcolors.ENDC}", end="")
            # if topic == "com.apple.madrid":
            #     print(f" {bcolors.FAIL}Madrid{bcolors.ENDC}", end="")
            #     import plistlib
            #     plist = plistlib.loads(_get_field(payload[1], 3))
            #     #payload = plist["P"]
            #     #print(f" {bcolors.WARNING}Payload{bcolors.ENDC}: {payload}", end="")

            #     for key in plist:
            #         print(f" {bcolors.OKBLUE}{key}{bcolors.ENDC}: {plist[key]}", end="")

        else:
            print(
                f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.OKCYAN}Notification{bcolors.ENDC}",
                end="",
            )
            topic = _lookup_topic(_get_field(payload[1], 2))
            # if b"bplist" in _get_field(payload[1], 3):
            #    print(f" {bcolors.OKBLUE}Binary{bcolors.ENDC}", end="")
            # print(f" {bcolors.WARNING}Topic{bcolors.ENDC}: {_lookup_topic(_get_field(payload[1], 2))}")

        print(f" {bcolors.WARNING}Topic{bcolors.ENDC}: {topic}", end="")

        if topic == "com.apple.madrid":
            print(f" {bcolors.FAIL}Madrid{bcolors.ENDC}", end="")
            orig_payload = payload
            payload = plistlib.loads(_get_field(payload[1], 3))

            # print(payload)
            if "cT" in payload and False:
                # It's HTTP over APNs
                if "hs" in payload:
                    print(
                        f" {bcolors.WARNING}HTTP Response{bcolors.ENDC}: {payload['hs']}",
                        end="",
                    )
                else:
                    print(f" {bcolors.WARNING}HTTP Request{bcolors.ENDC}", end="")
                # print(f" {bcolors.WARNING}HTTP{bcolors.ENDC} {payload['hs']}", end="")
                if "u" in payload:
                    print(f" {bcolors.OKCYAN}URL{bcolors.ENDC}: {payload['u']}", end="")
                print(
                    f" {bcolors.FAIL}Content Type{bcolors.ENDC}: {payload['cT']}",
                    end="",
                )
                if "h" in payload:
                    print(
                        f" {bcolors.FAIL}Headers{bcolors.ENDC}: {payload['h']}", end=""
                    )
                if "b" in payload:
                    # What am I really supposed to put in WBITS? Got this from a random SO answer
                    # print(payload["b"])
                    body = zlib.decompress(payload["b"], 16 + zlib.MAX_WBITS)
                    if b"plist" in body:
                        body = plistlib.loads(body)
                    print(f" {bcolors.FAIL}Body{bcolors.ENDC}: {body}", end="")
            #if not "cT" in payload:
            for key in payload:
                print(f" {bcolors.OKBLUE}{key}{bcolors.ENDC}: {payload[key]}")

            if 'dtl' in payload:
                print("OVERRIDE DTL")
                payload['dtl'][0].update({'sT': b64decode("jJ86jTYbv1mGVwO44PyfuZ9lh3o56QjOE39Jk8Z99N8=")})

                # Re-serialize the payload
                payload = plistlib.dumps(payload, fmt=plistlib.FMT_BINARY)
                # Construct APNS message
                # Get the original fields except 3
                fields = orig_payload[1]
                fields = [field for field in fields if field[0] != 3]
                # Add the new field
                fields.append((3, payload))
                payload = apns._serialize_payload(0xA, fields)

                # Use the override payload

                #print(payload, orig_payload)
                #print(payload == orig_payload)
                return payload

        print()

        # print(f" {bcolors.WARNING}{bcolors.ENDC}: {payload['cT']}")

        # for field in payload[1]:
        #    print(f"Field ID: {field[0]}")
        #    print(f"Field Value: {field[1]}")
    elif id == 0xB:
        print(
            f"{bcolors.OKGREEN}{prefix}{bcolors.ENDC}: {bcolors.OKCYAN}Notification Ack{bcolors.ENDC} {bcolors.OKBLUE}{_get_field(payload[1], 8).hex()}{bcolors.ENDC}"
        )
    else:
        print(prefix, f"Payload ID: {hex(payload[0])}")
        for field in payload[1]:
            print(f"Field ID: {field[0]}")
            print(f"Field Value: {field[1]}")


if __name__ == "__main__":
    print(f"{bcolors.OKGREEN}Enabled:{bcolors.ENDC}")
