from dataclasses import dataclass
from hashlib import sha1
from typing import Optional, Union

from anyio.abc import ByteStream, ObjectStream

from pypush.apns._protocol import command, fid
from pypush.apns.transport import Packet

# fmt: off
KNOWN_TOPICS = {'dev.jjtech.pypush.tests', 'com.apple.private.alloy.notes', 'com.apple.icloud-container.clouddocs.F3LWYJ7GM7.com.apple.garageband10', 'com.apple.private.alloy.screentime', 'com.apple.icloud-container.com.apple.appleaccount.custodian', 'com.apple.icloud-container.clouddocs.iCloud.com.apple.configurator.ui', 'com.apple.icloud-container.com.apple.VoiceMemos', 'com.apple.icloud-container.com.apple.SafariShared.Settings', 'com.apple.private.alloy.status.keysharing', 'com.apple.private.alloy.electrictouch', 'com.apple.private.alloy.icloudpairing', 'com.apple.icloud.presence.shared.experience', 'com.apple.icloud-container.com.apple.knowledge-agent', 'com.apple.private.alloy.thumper.keys', 'com.apple.pay.services.ck.zone.prod', 'com.apple.sharedstreams', 'com.apple.jalisco', 'com.apple.private.alloy.ded', 'com.apple.icloud-container.com.apple.cloudpaird', 'com.apple.private.alloy.multiplex1', 'com.apple.private.alloy.nearby', 'com.me.contacts', 'com.apple.TestFlight', 'com.icloud.family', 'com.apple.icloud-container.com.apple.iWork.Pages', 'com.apple.bookassetd', 'com.apple.tv.favoriteTeams', 'com.apple.icloud-container.com.apple.Safari', 'com.apple.mobileme.fmf3', 'com.apple.icloud-container.clouddocs.iCloud.com.apple.iBooks.iTunesU', 'com.apple.private.alloy.applepay', 'com.apple.private.alloy.willow', 'com.apple.idmsauth', 'com.apple.icloud-container.com.apple.iWork.Numbers', 'com.apple.icloud-container.clouddocs.F3LWYJ7GM7.com.apple.mobilegarageband', 'com.apple.private.alloy.maps', 'com.apple.private.alloy.phonecontinuity', 'com.apple.private.alloy.avconference.icloud', 'com.apple.pay.services.apply.prod', 'com.apple.private.alloy.facetime.multi', 'com.apple.icloud-container.clouddocs.com.apple.TextInput', 'com.apple.icloud-container.clouddocs.iCloud.com.reddit.reddit', 'com.apple.icloud-container.clouddocs.com.apple.Numbers', 'com.apple.icloud.fmip.voiceassistantsync', 'com.apple.icloud-container.com.apple.avatarsd', 'com.apple.private.ac', 'company.thebrowser.Browser', 'com.apple.itunesstored', 'com.apple.icloud-container.com.apple.icloud.fmfd', 'com.apple.private.alloy.screentime.invite', 'com.apple.icloud-container.com.apple.donotdisturbd', 'com.apple.icloud-container.clouddocs.com.apple.TextEdit', 'com.apple.appstored', 'com.apple.icloud-container.clouddocs.com.apple.CloudDocs.container-metadata', 'com.apple.private.alloy.screensharing', 'com.apple.private.alloy.accessibility.switchcontrol', 'com.apple.private.alloy.screensharing.qr', 'com.apple.private.alloy.amp.potluck', 'com.apple.icloud-container.com.apple.siriknowledged', 'com.apple.private.alloy.gamecenter', 'com.apple.appstored-testflight', 'com.apple.private.alloy.messagenotification', 'com.apple.passd.usernotifications', 'com.apple.icloud-container.clouddocs.com.apple.Pages', 'com.apple.private.alloy.safeview', 'com.apple.findmy', 'com.apple.pay.auxiliary.registration.requirement.prod', 'com.apple.aa.idms', 'com.apple.private.alloy.ids.cloudmessaging', 'com.apple.icloud-container.com.apple.icloud.searchpartyuseragent', 'com.icloud.quota', 'com.apple.icloud-container.com.apple.upload-request-proxy.com.apple.photos.cloud', 'com.apple.private.alloy.usagetracking', 'com.apple.icloud-container.com.apple.syncdefaultsd', 'com.apple.private.alloy.continuity.tethering', 'com.apple.idmsauthagent', 'com.apple.sagad', 'com.apple.pay.services.ownershipTokens.prod', 'com.apple.private.alloy.sms', 'com.apple.Notes', 'com.apple.icloud-container.com.apple.SafariShared.WBSCloudBookmarksStore', 'com.apple.icloud-container.com.apple.reminders', 'com.apple.private.alloy.classroom', 'com.apple.news', 'com.apple.icloud-container.com.apple.imagent', 'com.apple.pay.services.products.prod', 'com.apple.private.alloy.fmf', 'com.apple.amsaccountsd', 'com.apple.private.alloy.itunes', 'com.apple.icloud-container.clouddocs.iCloud.com.apple.iBooks', 'com.apple.private.alloy.gelato', 'com.apple.icloud-container.com.apple.willowd', 'com.apple.icloud-container.clouddocs.com.apple.CloudDocs', 'com.apple.icloud-container.com.apple.protectedcloudstorage.protectedcloudkeysyncing', 'com.apple.icloud-container.com.apple.Notes', 'com.me.cal', 'com.apple.peerpayment', 'com.apple.icloud-container.clouddocs.iCloud.is.workflow.my.workflows', 'com.apple.private.alloy.facetime.sync', 'com.apple.icloud-container.com.apple.news', 'com.apple.icloud-container.com.apple.TrustedPeersHelper', 'com.apple.private.alloy.home.invite', 'com.apple.private.alloy.coreduet.sync', 'com.apple.private.alloy.contextsync', 'com.apple.private.alloy.fmd', 'com.apple.private.alloy.status.personal', 'com.apple.icloud-container.com.apple.assistant.assistantd', 'com.apple.private.alloy.sleep.icloud', 'com.apple.icloud-container.com.apple.security.cuttlefish', 'com.apple.wallet.sharing', 'com.apple.icloud-container.clouddocs.3L68KQB4HG.com.readdle.CommonDocuments', 'com.apple.pay.provision', 'com.apple.icloud-container.com.apple.StatusKitAgent', 'com.apple.icloud-container.clouddocs.com.apple.Preview', 'com.apple.icloud-container.com.apple.gamed', 'com.apple.askpermissiond', 'com.apple.private.alloy.gamecenter.imessage', 'com.apple.private.alloy.safari.groupactivities', 'com.apple.icloud-container.com.apple.Maps', 'com.apple.private.alloy.willow.stream', 'com.apple.pay.services.devicecheckin.prod.us', 'com.apple.icloud.presence.mode.status', 'com.apple.ess', 'com.apple.private.alloy.accounts.representative', 'com.apple.icloud-container.clouddocs.com.apple.QuickTimePlayerX', 'com.apple.private.alloy.facetime.audio', 'com.apple.private.alloy.continuity.unlock', 'com.apple.icloud-container.clouddocs.iCloud.md.obsidian', 'com.apple.icloud-container.clouddocs.iCloud.com.apple.MobileSMS', 'com.apple.iWork.Numbers', 'com.apple.pay.services.account.prod', 'com.apple.private.alloy.quickrelay', 'com.apple.iBooksX', 'com.apple.madrid', 'com.apple.private.alloy.continuity.activity', 'com.apple.icloud-container.com.apple.keyboardservicesd', 'com.apple.icloud-container.clouddocs.com.apple.CloudDocs.health', 'com.apple.icloud-container.com.apple.suggestd', 'com.apple.icloud-container.clouddocs.com.apple.Keynote', 'com.apple.private.alloy.home', 'com.apple.private.alloy.photostream', 'com.apple.icloud-container.com.apple.iBooksX', 'com.apple.private.alloy.digitalhealth', 'com.apple.icloud-container.clouddocs.iCloud.dk.simonbs.Scriptable', 'com.apple.private.alloy.copresence', 'com.apple.private.alloy.continuity.encryption', 'com.apple.icloud-container.com.apple.passd', 'com.apple.icloud-container.com.apple.findmy', 'com.apple.icloud-container.com.apple.financed', 'com.apple.icloud-container.com.apple.photos.cloud', 'com.apple.private.alloy.proxiedcrashcopier.icloud', 'com.apple.private.alloy.tips', 'com.apple.icloud-container.com.apple.appleaccount.beneficiary.private', 'com.apple.watchList', 'com.apple.icloud-container.com.apple.willowd.homekit', 'com.apple.icloud-container.clouddocs.com.apple.CloudDocs.pp-metadata', 'com.apple.icloud-container.com.apple.SafariShared.CloudTabs', 'com.apple.private.alloy.facetime.lp', 'com.apple.icloud-container.com.apple.appleaccount.beneficiary', 'com.apple.aa.setupservice', 'com.apple.icloud.fmip.app.push', 'com.apple.icloud.presence.channel.management', 'com.apple.icloud-container.clouddocs.com.apple.ScriptEditor2', 'com.apple.private.alloy.facetime.mw', 'com.apple.Maps', 'com.apple.icloud-container.clouddocs.com.apple.mail', 'com.apple.mobileme.fmf2', 'com.me.setupservice', 'paymentpass.com.apple', 'com.apple.music.social', 'com.apple.icloud-container.clouddocs.com.apple.iBooks.cloudData', 'com.apple.iWork.Pages', 'com.apple.private.alloy.carmelsync', 'com.apple.private.alloy.maps.eta', 'com.apple.icloud-container.clouddocs.com.apple.shoebox', 'com.apple.dt.Xcode', 'com.apple.private.alloy.facetime.video', 'com.apple.icloud-container.com.apple.sociallayerd', 'com.apple.private.alloy.keytransparency.accountkey.pinning', 'com.apple.wallet.sharing.qa', 'com.apple.icloud-container.com.apple.appleaccount.custodian.private', 'com.apple.private.alloy.phone.auth', 'com.apple.icloud-container.com.apple.amsengagementd', 'com.apple.amsengagementd.notifications', 'com.apple.maps.icloud', 'com.apple.storekit', 'com.apple.triald', 'com.icloud.askpermission', 'com.apple.private.alloy.biz', 'com.apple.tilt', 'com.apple.icloud-container.com.apple.callhistory.sync-helper', 'com.apple.private.ids', 'com.apple.private.alloy.clockface.sharing', 'com.apple.gamed', 'com.apple.icloud-container.company.thebrowser.Browser', 'com.apple.icloud-container.com.apple.securityd'}
KNOWN_TOPICS_LOOKUP = {sha1(topic.encode()).digest():topic for topic in KNOWN_TOPICS}
# fmt: on


@dataclass
class Command:
    @classmethod
    def from_packet(cls, packet: Packet):
        raise NotImplementedError

    def to_packet(self) -> Packet:
        raise NotImplementedError


@command
@dataclass
class ConnectCommand(Command):
    PacketType = Packet.Type.Connect

    push_token: Optional[bytes] = fid(1)
    state: Optional[int] = fid(2)
    flags: int = fid(5, byte_len=4)
    certificate: Optional[bytes] = fid(12)
    nonce: Optional[bytes] = fid(13)
    signature: Optional[bytes] = fid(14)

    interface: Optional[int] = fid(6, default=None)
    carrier_name: Optional[str] = fid(8, default=None)
    os_version: Optional[str] = fid(9, default=None)
    os_build: Optional[str] = fid(10, default=None)
    hardware_version: Optional[str] = fid(11, default=None)
    protocol_version: Optional[int] = fid(16, default=11, byte_len=2)
    redirect_count: Optional[int] = fid(17, default=None, byte_len=2)
    dns_resolve_time: Optional[int] = fid(19, default=None, byte_len=2)
    tls_handshake_time: Optional[int] = fid(20, default=None, byte_len=2)
    timestamp: Optional[int] = fid(22, default=None, byte_len=8)
    unknown26: Optional[bytes] = fid(26, default=None)


@command
@dataclass
class ConnectAck(Command):
    PacketType = Packet.Type.ConnectAck

    status: int = fid(1)
    token: Optional[bytes] = fid(3)
    max_message_size: int = fid(4, byte_len=2)
    unknown5: bytes = fid(5)
    capabilities: bytes = fid(6)
    large_message_size: Optional[int] = fid(8, byte_len=2)
    timestamp: int = fid(10, byte_len=8)
    region: Optional[str] = fid(11)
    timestamp2: Optional[int] = fid(12, byte_len=8)
    unknown19: Optional[bytes] = fid(19)


@command
@dataclass
class NoStorageCommand(Command):
    PacketType = Packet.Type.NoStorage
    token: bytes = fid(1)


@command
@dataclass(repr=False)
class FilterCommand(Command):
    PacketType = Packet.Type.FilterTopics

    token: bytes = fid(1)
    enabled_topic_hashes: Optional[list[bytes]] = fid(2)
    ignored_topic_hashes: Optional[list[bytes]] = fid(3, default=None)
    opportunistic_topic_hashes: Optional[list[bytes]] = fid(4, default=None)
    paused_topic_hashes: Optional[list[bytes]] = fid(5, default=None)
    non_waking_topic_hashes: Optional[list[bytes]] = fid(6, default=None)
    unknown12: Optional[bytes] = fid(12, default=None)

    def _lookup_hashes(self, hashes: Optional[list[bytes]]):
        return (
            [
                KNOWN_TOPICS_LOOKUP[hash] if hash in KNOWN_TOPICS_LOOKUP else hash
                for hash in hashes
            ]
            if hashes
            else []
        )

    @property
    def enabled_topics(self):
        return self._lookup_hashes(self.enabled_topic_hashes)

    @property
    def ignored_topics(self):
        return self._lookup_hashes(self.ignored_topic_hashes)

    @property
    def opportunistic_topics(self):
        return self._lookup_hashes(self.opportunistic_topic_hashes)

    @property
    def paused_topics(self):
        return self._lookup_hashes(self.paused_topic_hashes)

    @property
    def non_waking_topics(self):
        return self._lookup_hashes(self.non_waking_topic_hashes)

    def __repr__(self):
        return f"FilterCommand(token={self.token}, enabled_topics={self.enabled_topics}, ignored_topics={self.ignored_topics}, opportunistic_topics={self.opportunistic_topics}, paused_topics={self.paused_topics}, non_waking_topics={self.non_waking_topics})"


@command
@dataclass
class KeepAliveCommand(Command):
    PacketType = Packet.Type.KeepAlive

    connection_method: Optional[str] = fid(1, default=None)
    ios_version: Optional[str] = fid(2, default=None)
    ios_build: Optional[str] = fid(3, default=None)
    device_model: Optional[str] = fid(4, default=None)
    unknown5: Optional[int] = fid(5, default=None, byte_len=2)
    unknown6: Optional[str] = fid(6, default=None)
    unknown9: Optional[int] = fid(9, default=None, byte_len=1)
    unknown10: Optional[int] = fid(10, default=None, byte_len=1)


@command
@dataclass
class KeepAliveAck(Command):
    PacketType = Packet.Type.KeepAliveAck
    unknown: Optional[int] = fid(1)


@command
@dataclass
class Unknown29Command(Command):
    PacketType = Packet.Type.Unknown29
    unknown1: Optional[bytes] = fid(1)
    unknown2: Optional[bytes] = fid(2)
    unknown3: Optional[bytes] = fid(3)
    unknown4: Optional[bytes] = fid(4)

    def __repr__(self):
        return f"Unknown29Command(ignored)"


@command
@dataclass
class Unknown30Command(Command):
    PacketType = Packet.Type.Unknown30
    unknown1: Optional[bytes] = fid(1)
    unknown2: Optional[bytes] = fid(2)
    unknown3: Optional[bytes] = fid(3)
    unknown4: Optional[bytes] = fid(4)

    def __repr__(self):
        return f"Unknown30Command(ignored)"


@command
@dataclass
class Unknown32Command(Command):
    PacketType = Packet.Type.Unknown32
    unknown1: Optional[bytes] = fid(1)
    unknown2: Optional[bytes] = fid(2)
    unknown3: Optional[bytes] = fid(3)
    unknown4: Optional[bytes] = fid(4)
    unknown5: Optional[bytes] = fid(5)

    def __repr__(self):
        return f"Unknown32Command(ignored)"


@command
@dataclass
class SetStateCommand(Command):
    PacketType = Packet.Type.SetState

    state: int = fid(1)
    unknown2: int = fid(2, byte_len=4)


@command
@dataclass
class SendMessageCommand(Command):
    PacketType = Packet.Type.SendMessage

    payload: bytes = fid(3)
    id: bytes = fid(4)

    topic: Optional[Union[str, bytes]] = None
    token: Optional[bytes] = None
    outgoing: Optional[bool] = None

    expiry: Optional[int] = fid(5, byte_len=4, default=None)
    timestamp: Optional[int] = fid(6, byte_len=8, default=None)
    unknown7: Optional[bytes] = fid(7, default=None)
    unknown9: Optional[int] = fid(9, byte_len=1, default=None)
    unknown13: Optional[int] = fid(13, byte_len=1, default=None)
    unknown15: Optional[bytes] = fid(15, default=None)
    unknown21: Optional[bytes] = fid(21, default=None)
    unknown28: Optional[bytes] = fid(28, default=None)
    unknown29: Optional[bytes] = fid(29, default=None)

    _token_topic_1: bytes = fid(1, default=None, repr=False)
    _token_topic_2: bytes = fid(2, default=None, repr=False)

    def __post_init__(self):
        if not (
            self.topic is not None
            and self.token is not None
            and self.outgoing is not None
        ) and not (self._token_topic_1 is not None and self._token_topic_2 is not None):
            raise ValueError("topic, token, and outgoing must be set.")

        if self.outgoing == True:
            assert self.topic and self.token
            self._token_topic_1 = (
                sha1(self.topic.encode()).digest()
                if isinstance(self.topic, str)
                else self.topic
            )
            self._token_topic_2 = self.token
        elif self.outgoing == False:
            assert self.topic and self.token
            self._token_topic_1 = self.token
            self._token_topic_2 = (
                sha1(self.topic.encode()).digest()
                if isinstance(self.topic, str)
                else self.topic
            )
        else:
            assert self._token_topic_1 and self._token_topic_2
            if len(self._token_topic_1) == 20:  # SHA1 hash, topic
                self.topic = (
                    KNOWN_TOPICS_LOOKUP[self._token_topic_1]
                    if self._token_topic_1 in KNOWN_TOPICS_LOOKUP
                    else self._token_topic_1
                )
                self.token = self._token_topic_2
                self.outgoing = True
            else:
                self.topic = (
                    KNOWN_TOPICS_LOOKUP[self._token_topic_2]
                    if self._token_topic_2 in KNOWN_TOPICS_LOOKUP
                    else self._token_topic_2
                )
                self.token = self._token_topic_1
                self.outgoing = False


@command
@dataclass
class SendMessageAck(Command):
    PacketType = Packet.Type.SendMessageAck

    id: bytes = fid(4)
    status: int = fid(8)
    token: Optional[bytes] = fid(1, default=None)
    unknown6: Optional[bytes] = fid(6, default=None)


@dataclass
class UnknownCommand(Command):
    id: Packet.Type
    fields: list[Packet.Field]

    @classmethod
    def from_packet(cls, packet: Packet):
        return cls(id=packet.id, fields=packet.fields)

    def to_packet(self) -> Packet:
        return Packet(id=self.id, fields=self.fields)


# Factory function to create Command instances from Packets
def command_from_packet(packet: Packet) -> Command:
    command_classes: dict[Packet.Type, type[Command]] = {
        Packet.Type.Connect: ConnectCommand,
        Packet.Type.KeepAlive: KeepAliveCommand,
        Packet.Type.ConnectAck: ConnectAck,
        Packet.Type.FilterTopics: FilterCommand,
        Packet.Type.NoStorage: NoStorageCommand,
        Packet.Type.KeepAliveAck: KeepAliveAck,
        Packet.Type.Unknown29: Unknown29Command,
        Packet.Type.Unknown30: Unknown30Command,
        Packet.Type.Unknown32: Unknown32Command,
        Packet.Type.SetState: SetStateCommand,
        Packet.Type.SendMessage: SendMessageCommand,
        Packet.Type.SendMessageAck: SendMessageAck,
        # Add other mappings here...
    }
    command_class = command_classes.get(packet.id, None)
    if command_class:
        return command_class.from_packet(packet)
    else:
        return UnknownCommand.from_packet(packet)


@dataclass
class CommandStream(ObjectStream[Command]):
    transport_stream: ObjectStream[Packet]

    async def send(self, command: Command) -> None:
        await self.transport_stream.send(command.to_packet())

    async def receive(self) -> Command:
        return command_from_packet(await self.transport_stream.receive())

    async def aclose(self) -> None:
        await self.transport_stream.aclose()

    async def send_eof(self) -> None:
        await self.transport_stream.send_eof()
