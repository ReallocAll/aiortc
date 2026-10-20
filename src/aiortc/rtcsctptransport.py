import asyncio
import enum
import hmac
import logging
import math
import os
import time
from collections import deque
from collections.abc import Callable, Coroutine, Iterator, Sequence
from dataclasses import dataclass, field
from struct import pack, unpack_from
from typing import Deque, Optional, Union, cast

from google_crc32c import value as crc32c
from pyee.asyncio import AsyncIOEventEmitter

from .exceptions import InvalidStateError
from .rtcconfiguration import SctpLimits
from .rtcdatachannel import RTCDataChannel, RTCDataChannelParameters
from .rtcdtlstransport import RTCDtlsTransport
from .utils import random32, uint16_add, uint16_gt, uint32_gt, uint32_gte

logger = logging.getLogger(__name__)

# local constants
COOKIE_LENGTH = 24
COOKIE_LIFETIME = 60
MAX_STREAMS = 65535

# packet and chunk constants
SCTP_COMMON_HEADER_LENGTH = 12
SCTP_CHUNK_HEADER_LENGTH = 4
SCTP_DATA_CHUNK_HEADER_LENGTH = 16
# SCTP packet must contain at least one chunk.
SCTP_PACKET_MINIMUM_LENGTH = SCTP_COMMON_HEADER_LENGTH + SCTP_CHUNK_HEADER_LENGTH
# The maximum size of an SCTP packet, including the common header, which
# still fits the minimum IPv6 MTU once UDP and DTLS overhead is subtracted.
# See https://issues.webrtc.org/issues/42222640
SCTP_MAX_PACKET_LENGTH = 1189
# The maximum amount of user data in a DATA chunk. As chunks are padded to
# a multiple of 4 bytes, round down to stay within the packet size.
USERDATA_MAX_LENGTH = (
    (SCTP_MAX_PACKET_LENGTH - SCTP_COMMON_HEADER_LENGTH - SCTP_DATA_CHUNK_HEADER_LENGTH)
    // 4
    * 4
)

# The maximum message size we advertise in our SDP.
LOCAL_MAX_MESSAGE_SIZE = 262144

# The maximum message size to assume if the remote party does not
# advertise one, see RFC 8841 - section 6.
REMOTE_DEFAULT_MAX_MESSAGE_SIZE = 65536

# protocol constants
SCTP_CAUSE_INVALID_STREAM = 0x0001
SCTP_CAUSE_STALE_COOKIE = 0x0003

SCTP_DATA_LAST_FRAG = 0x01
SCTP_DATA_FIRST_FRAG = 0x02
SCTP_DATA_UNORDERED = 0x04

SCTP_MAX_ASSOCIATION_RETRANS = 10
SCTP_MAX_BURST = 4
SCTP_MAX_INIT_RETRANS = 8
SCTP_RTO_ALPHA = 1 / 8
SCTP_RTO_BETA = 1 / 4
SCTP_RTO_INITIAL = 3.0
SCTP_RTO_MIN = 1
SCTP_RTO_MAX = 60
SCTP_TSN_MODULO = 2**32

RECONFIG_MAX_STREAMS = 135

# parameters
SCTP_STATE_COOKIE = 0x0007
SCTP_STR_RESET_OUT_REQUEST = 0x000D
SCTP_STR_RESET_RESPONSE = 0x0010
SCTP_STR_RESET_ADD_OUT_STREAMS = 0x0011
SCTP_SUPPORTED_CHUNK_EXT = 0x8008
SCTP_PRSCTP_SUPPORTED = 0xC000

# data channel constants
DATA_CHANNEL_ACK = 2
DATA_CHANNEL_OPEN = 3

DATA_CHANNEL_RELIABLE = 0x00
DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT = 0x01
DATA_CHANNEL_PARTIAL_RELIABLE_TIMED = 0x02
DATA_CHANNEL_RELIABLE_UNORDERED = 0x80
DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED = 0x81
DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED = 0x82

WEBRTC_DCEP = 50
WEBRTC_STRING = 51
WEBRTC_BINARY = 53
WEBRTC_STRING_EMPTY = 56
WEBRTC_BINARY_EMPTY = 57

DataChannelQueue = Deque[tuple[RTCDataChannel, int, bytes, Optional["_SendCredit"]]]


@dataclass(eq=False)
class _SendCredit:
    size: int
    chunks: int
    active: bool = True


class SctpSendReservation:
    """Capacity for one atomic sequence of messages on a data channel."""

    def __init__(
        self,
        transport: "RTCSctpTransport",
        channel: RTCDataChannel,
        sizes: tuple[int, ...],
    ) -> None:
        self._transport = transport
        self._channel = channel
        self._sizes = sizes
        self._bytes = sum(max(1, size) for size in sizes)
        self._chunks = sum(
            (max(1, size) + USERDATA_MAX_LENGTH - 1) // USERDATA_MAX_LENGTH
            for size in sizes
        )
        self._active = False

    def send_nowait(self, messages: Sequence[Union[bytes, str]]) -> None:
        self._transport._check_send_channel(self._channel)
        if not self._active:
            raise InvalidStateError("Send reservation is no longer active")
        if not messages or len(messages) > len(self._sizes):
            raise ValueError("Message sequence exceeds its send reservation")
        prepared = []
        for data, bound in zip(messages, self._sizes):
            protocol, user_data = self._transport._data_channel_encode(data)
            size = 0 if data == b"" or data == "" else len(user_data)
            if size > bound:
                raise ValueError("Message exceeds its send reservation")
            prepared.append((protocol, user_data))
        self._transport._commit_reservation(self, prepared)

    def release(self) -> None:
        if self._active:
            self._active = False
            self._transport._send_reservations.discard(self)
            self._transport._send_bytes -= self._bytes
            self._transport._send_chunks -= self._chunks
            self._transport._send_messages -= len(self._sizes)
            self._transport._wake_senders()


def chunk_type(chunk: "Chunk") -> str:
    return chunk.__class__.__name__


def decode_params(body: bytes) -> list[tuple[int, bytes]]:
    params = []
    pos = 0
    while pos <= len(body) - 4:
        param_type, param_length = unpack_from("!HH", body, pos)
        params.append((param_type, body[pos + 4 : pos + param_length]))
        pos += param_length + padl(param_length)
    return params


def encode_params(params: list[tuple[int, bytes]]) -> bytes:
    body = b""
    padding = b""
    for param_type, param_value in params:
        param_length = len(param_value) + 4
        body += padding
        body += pack("!HH", param_type, param_length) + param_value
        padding = b"\x00" * padl(param_length)
    return body


def padl(length: int) -> int:
    m = length % 4
    return 4 - m if m else 0


def tsn_minus_one(a: int) -> int:
    return (a - 1) % SCTP_TSN_MODULO


def tsn_plus_one(a: int) -> int:
    return (a + 1) % SCTP_TSN_MODULO


class Chunk:
    type = -1

    def __init__(self, flags: int = 0, body: bytes = b"") -> None:
        self.flags = flags
        self.body = body

    def __bytes__(self) -> bytes:
        body = self.body
        data = pack("!BBH", self.type, self.flags, len(body) + 4) + body
        data += b"\x00" * padl(len(body))
        return data

    def __repr__(self) -> str:
        return f"{chunk_type(self)}(flags={self.flags})"


class BaseParamsChunk(Chunk):
    def __init__(self, flags: int = 0, body: Optional[bytes] = None) -> None:
        self.flags = flags
        if body:
            self.params = decode_params(body)
        else:
            self.params = []

    @property
    def body(self) -> bytes:  # type: ignore
        return encode_params(self.params)


class AbortChunk(BaseParamsChunk):
    type = 6


class CookieAckChunk(Chunk):
    type = 11


class CookieEchoChunk(Chunk):
    type = 10


class DataChunk(Chunk):
    type = 0

    _acked: bool
    _abandoned: bool
    _book_size: int
    _expiry: Optional[float]
    _fast_retransmitted: bool
    _max_retransmits: Optional[int]
    _misses: int
    _retransmit: bool
    _sent_count: int
    _sent_time: Optional[float]

    def __init__(self, flags: int = 0, body: Optional[bytes] = None) -> None:
        self.flags = flags
        if body:
            (self.tsn, self.stream_id, self.stream_seq, self.protocol) = unpack_from(
                "!LHHL", body
            )
            self.user_data = body[12:]
        else:
            self.tsn = 0
            self.stream_id = 0
            self.stream_seq = 0
            self.protocol = 0
            self.user_data = b""

    def __bytes__(self) -> bytes:
        length = SCTP_DATA_CHUNK_HEADER_LENGTH + len(self.user_data)
        data = (
            pack(
                "!BBHLHHL",
                self.type,
                self.flags,
                length,
                self.tsn,
                self.stream_id,
                self.stream_seq,
                self.protocol,
            )
            + bytes(self.user_data)
        )
        if length % 4:
            data += b"\x00" * padl(length)
        return data

    def __repr__(self) -> str:
        return (
            f"DataChunk(flags={self.flags}, tsn={self.tsn}, "
            f"stream_id={self.stream_id}, stream_seq={self.stream_seq})"
        )


class ErrorChunk(BaseParamsChunk):
    type = 9


class ForwardTsnChunk(Chunk):
    type = 192

    def __init__(self, flags: int = 0, body: Optional[bytes] = None) -> None:
        self.flags = flags
        self.streams: list[tuple[int, int]] = []
        if body:
            self.cumulative_tsn = unpack_from("!L", body, 0)[0]
            pos = 4
            while pos < len(body):
                self.streams.append(
                    cast(tuple[int, int], unpack_from("!HH", body, pos))
                )
                pos += 4
        else:
            self.cumulative_tsn = 0

    @property
    def body(self) -> bytes:  # type: ignore
        body = pack("!L", self.cumulative_tsn)
        for stream_id, stream_seq in self.streams:
            body += pack("!HH", stream_id, stream_seq)
        return body

    def __repr__(self) -> str:
        return (
            f"ForwardTsnChunk(cumulative_tsn={self.cumulative_tsn}, "
            f"streams={self.streams})"
        )


class HeartbeatChunk(BaseParamsChunk):
    type = 4


class HeartbeatAckChunk(BaseParamsChunk):
    type = 5


class BaseInitChunk(Chunk):
    def __init__(self, flags: int = 0, body: Optional[bytes] = None) -> None:
        self.flags = flags
        if body:
            (
                self.initiate_tag,
                self.advertised_rwnd,
                self.outbound_streams,
                self.inbound_streams,
                self.initial_tsn,
            ) = unpack_from("!LLHHL", body)
            self.params = decode_params(body[16:])
        else:
            self.initiate_tag = 0
            self.advertised_rwnd = 0
            self.outbound_streams = 0
            self.inbound_streams = 0
            self.initial_tsn = 0
            self.params = []

    @property
    def body(self) -> bytes:  # type: ignore
        body = pack(
            "!LLHHL",
            self.initiate_tag,
            self.advertised_rwnd,
            self.outbound_streams,
            self.inbound_streams,
            self.initial_tsn,
        )
        body += encode_params(self.params)
        return body


class InitChunk(BaseInitChunk):
    type = 1


class InitAckChunk(BaseInitChunk):
    type = 2


class ReconfigChunk(BaseParamsChunk):
    type = 130


class SackChunk(Chunk):
    type = 3

    def __init__(self, flags: int = 0, body: Optional[bytes] = None) -> None:
        self.flags = flags
        self.gaps = []
        self.duplicates = []
        if body:
            (
                self.cumulative_tsn,
                self.advertised_rwnd,
                nb_gaps,
                nb_duplicates,
            ) = unpack_from("!LLHH", body)
            pos = 12
            for i in range(nb_gaps):
                self.gaps.append(unpack_from("!HH", body, pos))
                pos += 4
            for i in range(nb_duplicates):
                self.duplicates.append(unpack_from("!L", body, pos)[0])
                pos += 4
        else:
            self.cumulative_tsn = 0
            self.advertised_rwnd = 0

    def __bytes__(self) -> bytes:
        length = 16 + 4 * (len(self.gaps) + len(self.duplicates))
        data = pack(
            "!BBHLLHH",
            self.type,
            self.flags,
            length,
            self.cumulative_tsn,
            self.advertised_rwnd,
            len(self.gaps),
            len(self.duplicates),
        )
        for gap in self.gaps:
            data += pack("!HH", *gap)
        for tsn in self.duplicates:
            data += pack("!L", tsn)
        return data

    def __repr__(self) -> str:
        return (
            f"SackChunk(flags={self.flags}, advertised_rwnd={self.advertised_rwnd}, "
            f"cumulative_tsn={self.cumulative_tsn}, gaps={self.gaps})"
        )


class ShutdownChunk(Chunk):
    type = 7

    def __init__(self, flags: int = 0, body: Optional[bytes] = None) -> None:
        self.flags = flags
        if body:
            self.cumulative_tsn = unpack_from("!L", body)[0]
        else:
            self.cumulative_tsn = 0

    @property
    def body(self) -> bytes:  # type: ignore
        return pack("!L", self.cumulative_tsn)

    def __repr__(self) -> str:
        return (
            f"ShutdownChunk(flags={self.flags}, cumulative_tsn={self.cumulative_tsn})"
        )


class ShutdownAckChunk(Chunk):
    type = 8


class ShutdownCompleteChunk(Chunk):
    type = 14


CHUNK_CLASSES = [
    DataChunk,
    InitChunk,
    InitAckChunk,
    SackChunk,
    HeartbeatChunk,
    HeartbeatAckChunk,
    AbortChunk,
    ShutdownChunk,
    ShutdownAckChunk,
    ErrorChunk,
    CookieEchoChunk,
    CookieAckChunk,
    ShutdownCompleteChunk,
    ReconfigChunk,
    ForwardTsnChunk,
]
CHUNK_TYPES = dict((cls.type, cls) for cls in CHUNK_CLASSES)


def parse_packet(data: bytes) -> tuple[int, int, int, list[Chunk]]:
    length = len(data)

    # Check the packet is long enough to accomodate the common header
    # and one chunk's header.
    if length < SCTP_PACKET_MINIMUM_LENGTH:
        raise ValueError(
            f"SCTP packet length is less than {SCTP_PACKET_MINIMUM_LENGTH} bytes"
        )

    source_port, destination_port, verification_tag = unpack_from("!HHL", data)

    # Verify the checksum matches.
    checksum = unpack_from("<L", data, 8)[0]
    if checksum != crc32c(data[0:8] + b"\x00\x00\x00\x00" + data[12:]):
        raise ValueError("SCTP packet has invalid checksum")

    chunks: list[Chunk] = []
    pos = SCTP_COMMON_HEADER_LENGTH
    while pos <= length - SCTP_CHUNK_HEADER_LENGTH:
        chunk_type, chunk_flags, chunk_length = unpack_from("!BBH", data, pos)

        # Check the chunk length:
        # - It must be at least as long as the chunk header.
        # - It must not exceed the remaining packet data.
        if chunk_length < SCTP_CHUNK_HEADER_LENGTH or pos + chunk_length > length:
            raise ValueError(
                f"SCTP chunk has an invalid length of {chunk_length} bytes"
            )
        chunk_body = data[pos + SCTP_CHUNK_HEADER_LENGTH : pos + chunk_length]
        chunk_cls = CHUNK_TYPES.get(chunk_type)
        if chunk_cls:
            chunks.append(chunk_cls(flags=chunk_flags, body=chunk_body))
        pos += chunk_length + padl(chunk_length)
    return source_port, destination_port, verification_tag, chunks


def serialize_packet(
    source_port: int, destination_port: int, verification_tag: int, chunk: Chunk
) -> bytes:
    header = pack("!HHL", source_port, destination_port, verification_tag)
    data = bytes(chunk)
    checksum = crc32c(header + b"\x00\x00\x00\x00" + data)
    return header + pack("<L", checksum) + data


# RFC 6525


@dataclass
class StreamResetOutgoingParam:
    request_sequence: int
    response_sequence: int
    last_tsn: int
    streams: list[int] = field(default_factory=list)

    def __bytes__(self) -> bytes:
        data = pack(
            "!LLL", self.request_sequence, self.response_sequence, self.last_tsn
        )
        for stream in self.streams:
            data += pack("!H", stream)
        return data

    @classmethod
    def parse(cls, data: bytes) -> "StreamResetOutgoingParam":
        request_sequence, response_sequence, last_tsn = unpack_from("!LLL", data)
        streams = []
        for pos in range(12, len(data), 2):
            streams.append(unpack_from("!H", data, pos)[0])
        return cls(
            request_sequence=request_sequence,
            response_sequence=response_sequence,
            last_tsn=last_tsn,
            streams=streams,
        )


@dataclass
class StreamAddOutgoingParam:
    request_sequence: int
    new_streams: int

    def __bytes__(self) -> bytes:
        data = pack("!LHH", self.request_sequence, self.new_streams, 0)
        return data

    @classmethod
    def parse(cls, data: bytes) -> "StreamAddOutgoingParam":
        request_sequence, new_streams, reserved = unpack_from("!LHH", data)
        return cls(request_sequence=request_sequence, new_streams=new_streams)


@dataclass
class StreamResetResponseParam:
    response_sequence: int
    result: int

    def __bytes__(self) -> bytes:
        return pack("!LL", self.response_sequence, self.result)

    @classmethod
    def parse(cls, data: bytes) -> "StreamResetResponseParam":
        response_sequence, result = unpack_from("!LL", data)
        return cls(response_sequence=response_sequence, result=result)


RECONFIG_PARAM_TYPES: dict[
    int,
    Union[
        type[StreamResetOutgoingParam],
        type[StreamResetResponseParam],
        type[StreamAddOutgoingParam],
    ],
] = {
    13: StreamResetOutgoingParam,
    16: StreamResetResponseParam,
    17: StreamAddOutgoingParam,
}


class InboundStream:
    def __init__(
        self,
        *,
        max_message_size: Optional[int] = None,
        on_remove: Optional[Callable[[DataChunk], None]] = None,
    ) -> None:
        self.reassembly: list[DataChunk] = []
        self.sequence_number = 0
        self._max_message_size = max_message_size
        self._on_remove = on_remove

    def add_chunk(self, chunk: DataChunk) -> None:
        if not self.reassembly or uint32_gt(chunk.tsn, self.reassembly[-1].tsn):
            self.reassembly.append(chunk)
            return

        for i, rchunk in enumerate(self.reassembly):
            # should never happen, the chunk should have been eliminated
            # as a duplicate when _mark_received() is called
            assert rchunk.tsn != chunk.tsn, "duplicate chunk in reassembly"

            if uint32_gt(rchunk.tsn, chunk.tsn):
                self.reassembly.insert(i, chunk)
                break

    def pop_messages(self) -> Iterator[tuple[int, int, bytes]]:
        pos = 0
        start_pos = None
        message_size = 0
        while pos < len(self.reassembly):
            chunk = self.reassembly[pos]
            if start_pos is None:
                ordered = not (chunk.flags & SCTP_DATA_UNORDERED)
                if not (chunk.flags & SCTP_DATA_FIRST_FRAG):
                    if ordered:
                        break
                    else:
                        pos += 1
                        continue
                if ordered and uint16_gt(chunk.stream_seq, self.sequence_number):
                    break
                expected_tsn = chunk.tsn
                start_pos = pos
                message_size = 0
            elif chunk.tsn != expected_tsn:
                if ordered:
                    break
                else:
                    start_pos = None
                    pos += 1
                    continue

            message_size += len(chunk.user_data)
            if (
                self._max_message_size is not None
                and message_size > self._max_message_size
            ):
                raise ConnectionError("SCTP assembled message limit exceeded")
            if chunk.flags & SCTP_DATA_LAST_FRAG:
                removed = self.reassembly[start_pos : pos + 1]
                user_data = b"".join([c.user_data for c in removed])
                self.reassembly = (
                    self.reassembly[:start_pos] + self.reassembly[pos + 1 :]
                )
                if ordered and chunk.stream_seq == self.sequence_number:
                    self.sequence_number = uint16_add(self.sequence_number, 1)
                if self._on_remove is not None:
                    for removed_chunk in removed:
                        self._on_remove(removed_chunk)
                pos = start_pos
                message_size = 0
                yield (chunk.stream_id, chunk.protocol, user_data)
            else:
                pos += 1

            expected_tsn = tsn_plus_one(expected_tsn)

    def prune_chunks(self, tsn: int) -> int:
        """
        Prune chunks up to the given TSN.
        """
        pos = -1
        size = 0
        for i, chunk in enumerate(self.reassembly):
            if uint32_gte(tsn, chunk.tsn):
                pos = i
                size += len(chunk.user_data)
            else:
                break

        removed = self.reassembly[: pos + 1]
        self.reassembly = self.reassembly[pos + 1 :]
        if self._on_remove is not None:
            for chunk in removed:
                self._on_remove(chunk)
        return size


@dataclass
class RTCSctpCapabilities:
    """
    The :class:`RTCSctpCapabilities` dictionary provides information about the
    capabilities of the :class:`RTCSctpTransport`.
    """

    maxMessageSize: int
    """
    The maximum size of data that the implementation can send or
    0 if the implementation can handle messages of any size.

    """


class RTCSctpTransport(AsyncIOEventEmitter):
    """
    The :class:`RTCSctpTransport` interface includes information relating to
    Stream Control Transmission Protocol (SCTP) transport.

    :param transport: An :class:`RTCDtlsTransport`.
    """

    def __init__(
        self,
        transport: RTCDtlsTransport,
        port: int = 5000,
        *,
        limits: Optional[SctpLimits] = None,
    ) -> None:
        if transport.state == "closed":
            raise InvalidStateError

        super().__init__()
        self._association_state = self.State.CLOSED
        self.__log_debug: Callable[..., None] = lambda *args: None
        self.__started = False
        self.__state = "new"
        self.__transport = transport
        self._limits = limits
        self._uses_backpressure = limits is not None or getattr(
            transport.transport, "_has_write_limits", False
        )
        self._stopping = False
        self._stop_task: Optional[asyncio.Task[None]] = None
        self._failure: Optional[ConnectionError] = None
        self._service_tasks: dict[str, asyncio.Task[None]] = {}
        self._flush_lock = asyncio.Lock()
        self._sender_lock = asyncio.Lock()
        self._send_bytes = 0
        self._send_chunks = 0
        self._send_messages = 0
        self._send_credits: set[_SendCredit] = set()
        self._send_reservations: set[SctpSendReservation] = set()
        self._send_waiters: Deque[tuple[asyncio.Future[None], SctpSendReservation]] = (
            deque()
        )

        self._loop = asyncio.get_event_loop()
        self._hmac_key = os.urandom(16)

        self._local_partial_reliability = True
        self._local_port = port
        self._local_verification_tag = random32()

        self._remote_extensions: list[int] = []
        self._remote_initial_tsn: Optional[int] = None
        self._remote_max_message_size = REMOTE_DEFAULT_MAX_MESSAGE_SIZE
        self._remote_partial_reliability = False
        self._remote_port: Optional[int] = None
        self._remote_verification_tag = 0

        # inbound
        self._advertised_rwnd = 1024 * 1024
        self._inbound_streams: dict[int, InboundStream] = {}
        self._inbound_streams_count = 0
        self._inbound_streams_max = MAX_STREAMS
        self._last_received_tsn: Optional[int] = None
        self._sack_duplicates: list[int] = []
        self._sack_misordered: set[int] = set()
        self._sack_needed = False
        self._inbound_bytes = 0
        self._inbound_chunks = 0
        self._active_inbound_streams: set[int] = set()

        # outbound
        self._cwnd = 3 * USERDATA_MAX_LENGTH
        self._fast_recovery_exit = None
        self._fast_recovery_transmit = False
        self._forward_tsn_chunk: Optional[ForwardTsnChunk] = None
        self._flight_size = 0
        self._local_tsn = random32()
        self._last_sacked_tsn = tsn_minus_one(self._local_tsn)
        self._advanced_peer_ack_tsn = tsn_minus_one(self._local_tsn)
        self._outbound_queue: Deque[DataChunk] = deque()
        self._outbound_stream_seq: dict[int, int] = {}
        self._outbound_streams_count = MAX_STREAMS
        self._partial_bytes_acked = 0
        self._sent_queue: Deque[DataChunk] = deque()

        # reconfiguration
        self._reconfig_queue: list[int] = []
        self._reconfig_request: Optional[StreamResetOutgoingParam] = None
        self._reconfig_request_seq = self._local_tsn
        self._reconfig_response_seq = 0

        # rtt calculation
        self._srtt: Optional[float] = None
        self._rttvar: Optional[float] = None

        # timers
        self._rto = SCTP_RTO_INITIAL
        self._t1_chunk: Optional[Chunk] = None
        self._t1_failures = 0
        self._t1_handle: Optional[asyncio.TimerHandle] = None
        self._t2_chunk: Optional[Chunk] = None
        self._t2_failures = 0
        self._t2_handle: Optional[asyncio.TimerHandle] = None
        self._t3_handle: Optional[asyncio.TimerHandle] = None
        self._t3_pending: Optional[asyncio.TimerHandle] = None

        # data channels
        self._data_channel_id: Optional[int] = None
        self._data_channel_queue: DataChannelQueue = deque()
        self._data_channels: dict[int, RTCDataChannel] = {}

        # FIXME: this is only used by RTCPeerConnection
        self._bundled = False
        self.mid: Optional[str] = None

    @property
    def is_server(self) -> bool:
        # RFC 8832 ties SCTP behaviour to the DTLS role, not the ICE role.
        return self.transport._role == "server"

    @property
    def maxChannels(self) -> Optional[int]:
        """
        The maximum number of :class:`RTCDataChannel` that can be used simultaneously.
        """
        if self._inbound_streams_count:
            return min(self._inbound_streams_count, self._outbound_streams_count)
        return None

    @property
    def port(self) -> int:
        """
        The local SCTP port number used for data channels.
        """
        return self._local_port

    @property
    def state(self) -> str:
        """
        The current state of the SCTP transport.
        """
        return self.__state

    @property
    def transport(self) -> RTCDtlsTransport:
        """
        The :class:`RTCDtlsTransport` over which SCTP data is transmitted.
        """
        return self.__transport

    @classmethod
    def getCapabilities(cls) -> RTCSctpCapabilities:
        """
        Retrieve the capabilities of the transport.

        :rtype: RTCSctpCapabilities
        """
        return RTCSctpCapabilities(maxMessageSize=LOCAL_MAX_MESSAGE_SIZE)

    def setTransport(self, transport: RTCDtlsTransport) -> None:
        self.__transport = transport

    async def start(
        self, remoteCaps: Optional[RTCSctpCapabilities], remotePort: int
    ) -> None:
        """
        Start the transport.
        """
        if not self.__started:
            self.__started = True
            self.__state = "connecting"
            self._remote_port = remotePort
            if remoteCaps is not None:
                self._remote_max_message_size = remoteCaps.maxMessageSize

            # configure logging
            if logger.isEnabledFor(logging.DEBUG):
                prefix = "RTCSctpTransport(%s) " % (
                    self.is_server and "server" or "client"
                )
                self.__log_debug = lambda msg, *args: logger.debug(prefix + msg, *args)

            # initialise local channel ID counter
            # RFC 8832: the DTLS client uses even IDs, the DTLS server odd IDs
            if self.is_server:
                self._data_channel_id = 1
            else:
                self._data_channel_id = 0

            # both endpoints initiate the association, see RFC 8841 section 9.3
            self.__transport._register_data_receiver(self)
            await self._init()

    async def stop(self) -> None:
        """
        Stop the transport.
        """
        if self._stop_task is None:
            self._stopping = True
            self._stop_task = asyncio.create_task(self._stop())
        await asyncio.shield(self._stop_task)

    async def _stop(self) -> None:
        tasks = list(self._service_tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        try:
            if self._association_state != self.State.CLOSED:
                await self._abort()
        finally:
            self.__transport._unregister_data_receiver(self)
            self._set_state(self.State.CLOSED)

    def _schedule(
        self, name: str, operation: Callable[[], Coroutine[None, None, None]]
    ) -> None:
        if self._stopping or self.__state == "closed":
            return
        task = self._service_tasks.get(name)
        if task is None or task.done():
            task = asyncio.create_task(operation())
            self._service_tasks[name] = task
            task.add_done_callback(lambda done: self._service_done(name, done))

    def _service_done(self, name: str, task: asyncio.Task[None]) -> None:
        if self._service_tasks.get(name) is task:
            self._service_tasks.pop(name, None)
        if not task.cancelled():
            error = task.exception()
            if error is not None:
                self._fail(ConnectionError(f"SCTP send failed: {error}"))

    def _fail(self, error: ConnectionError) -> None:
        if self._failure is None:
            self._failure = error
        self._set_state(self.State.CLOSED)

    def _check_send_channel(self, channel: RTCDataChannel) -> None:
        if self._failure is not None:
            raise self._failure
        if self._stopping or self.__state == "closed":
            raise ConnectionError("SCTP transport is closed")
        if channel.transport is not self or channel.readyState != "open":
            raise InvalidStateError("Data channel is not open on this association")

    def _has_capacity(self, size: int, chunks: int, messages: int) -> bool:
        return self._limits is None or (
            self._send_bytes + size <= self._limits.send_bytes
            and self._send_chunks + chunks <= self._limits.send_chunks
            and self._send_messages + messages <= self._limits.send_messages
        )

    async def reserve_data_channel(
        self, channel: RTCDataChannel, message_sizes: Sequence[int]
    ) -> SctpSendReservation:
        """Reserve the full encoded-byte bounds before producing any messages."""
        reservation = self._new_reservation(channel, message_sizes)
        if not self._send_waiters and self._has_capacity(
            reservation._bytes, reservation._chunks, len(reservation._sizes)
        ):
            self._grant_reservation(reservation)
            return reservation
        if (
            self._limits is not None
            and len(self._send_waiters) >= self._limits.send_waiters
        ):
            raise BufferError("SCTP send waiter limit exceeded")
        future: asyncio.Future[None] = self._loop.create_future()
        entry = (future, reservation)
        self._send_waiters.append(entry)
        try:
            await future
            return reservation
        except BaseException:
            if entry in self._send_waiters:
                self._send_waiters.remove(entry)
            reservation.release()
            self._wake_senders()
            raise

    def reserve_data_channel_nowait(
        self, channel: RTCDataChannel, message_sizes: Sequence[int]
    ) -> SctpSendReservation:
        """Reserve a whole message sequence or reject without retaining its payload."""
        reservation = self._new_reservation(channel, message_sizes)
        if self._send_waiters or not self._has_capacity(
            reservation._bytes, reservation._chunks, len(reservation._sizes)
        ):
            raise BufferError("SCTP send storage is unavailable")
        self._grant_reservation(reservation)
        return reservation

    def _new_reservation(
        self, channel: RTCDataChannel, message_sizes: Sequence[int]
    ) -> SctpSendReservation:
        self._check_send_channel(channel)
        if not message_sizes or (
            self._limits is not None and len(message_sizes) > self._limits.send_messages
        ):
            raise ValueError("Invalid send reservation message count")
        sizes = tuple(message_sizes)
        for size in sizes:
            if (
                type(size) is not int
                or size < 0
                or (self._limits is not None and size > self._limits.max_message_size)
            ):
                raise ValueError("Invalid send reservation message size")
            self._check_remote_message_size(size)
        reservation = SctpSendReservation(self, channel, sizes)
        if self._limits is not None and (
            reservation._bytes > self._limits.send_bytes
            or reservation._chunks > self._limits.send_chunks
        ):
            raise ValueError("Send reservation exceeds association capacity")
        return reservation

    def _grant_reservation(self, reservation: SctpSendReservation) -> None:
        reservation._active = True
        self._send_reservations.add(reservation)
        self._send_bytes += reservation._bytes
        self._send_chunks += reservation._chunks
        self._send_messages += len(reservation._sizes)

    def _wake_senders(self) -> None:
        while self._send_waiters:
            future, reservation = self._send_waiters[0]
            if future.done():
                self._send_waiters.popleft()
                continue
            try:
                self._check_send_channel(reservation._channel)
            except (ConnectionError, InvalidStateError) as error:
                self._send_waiters.popleft()
                future.set_exception(error)
                continue
            if not self._has_capacity(
                reservation._bytes, reservation._chunks, len(reservation._sizes)
            ):
                return
            self._send_waiters.popleft()
            self._grant_reservation(reservation)
            future.set_result(None)

    def _commit_reservation(
        self, reservation: SctpSendReservation, prepared: list[tuple[int, bytes]]
    ) -> None:
        credits = [
            _SendCredit(len(data), math.ceil(len(data) / USERDATA_MAX_LENGTH))
            for _, data in prepared
        ]
        entries = [
            (reservation._channel, protocol, data, credit)
            for (protocol, data), credit in zip(prepared, credits)
        ]
        try:
            reservation._active = False
            self._send_reservations.remove(reservation)
            self._send_bytes -= reservation._bytes - sum(c.size for c in credits)
            self._send_chunks -= reservation._chunks - sum(c.chunks for c in credits)
            self._send_messages -= len(reservation._sizes) - len(credits)
            self._send_credits.update(credits)
            self._data_channel_queue.extend(entries)
            for _, data in prepared:
                reservation._channel._addBufferedAmount(len(data))
            self._schedule("flush", self._data_channel_flush)
        except BaseException:
            self._fail(ConnectionError("SCTP message commit failed"))
            raise
        self._wake_senders()

    def _queue_data(self, channel: RTCDataChannel, protocol: int, data: bytes) -> None:
        credit = self._allocate_send_credit(data)
        self._data_channel_queue.append((channel, protocol, data, credit))

    def _allocate_send_credit(self, data: bytes) -> Optional[_SendCredit]:
        if self._limits is None:
            return None
        size = len(data)
        chunks = math.ceil(size / USERDATA_MAX_LENGTH)
        if size > self._limits.max_message_size:
            raise ValueError("SCTP message size limit exceeded")
        if not self._has_capacity(size, chunks, 1):
            raise BufferError("SCTP send storage limit exceeded")
        credit = _SendCredit(size, chunks)
        self._send_credits.add(credit)
        self._send_bytes += size
        self._send_chunks += chunks
        self._send_messages += 1
        return credit

    def _release_credit(self, credit: Optional[_SendCredit]) -> None:
        if credit is not None and credit.active:
            credit.active = False
            self._send_credits.discard(credit)
            self._send_bytes -= credit.size
            self._send_chunks -= credit.chunks
            self._send_messages -= 1
            self._wake_senders()

    def _release_chunk(self, chunk: DataChunk) -> None:
        credit = getattr(chunk, "_credit", None)
        if credit is not None and credit.active:
            chunk.user_data = b""
            chunk._credit = None
            credit.chunks -= 1
            self._send_chunks -= 1
            if credit.chunks == 0:
                self._release_credit(credit)
            else:
                self._wake_senders()

    async def _abort(self) -> None:
        """
        Abort the association.
        """
        chunk = AbortChunk()
        try:
            if self._uses_backpressure:
                async with asyncio.timeout(0):
                    await self._send_chunk(chunk)
            else:
                await self._send_chunk(chunk)
        except (ConnectionError, TimeoutError):
            pass

    async def _init(self) -> None:
        """
        Initialize the association.
        """
        chunk = InitChunk()
        chunk.initiate_tag = self._local_verification_tag
        chunk.advertised_rwnd = self._advertised_rwnd
        chunk.outbound_streams = self._outbound_streams_count
        chunk.inbound_streams = self._inbound_streams_max
        chunk.initial_tsn = self._local_tsn
        self._set_extensions(chunk.params)
        await self._send_chunk(chunk)
        if (
            self._stopping
            or self.__state == "closed"
            or self._association_state != self.State.CLOSED
        ):
            return

        # start T1 timer and enter COOKIE-WAIT state
        self._t1_start(chunk)
        self._set_state(self.State.COOKIE_WAIT)

    def _flight_size_decrease(self, chunk: DataChunk) -> None:
        self._flight_size = max(0, self._flight_size - chunk._book_size)

    def _flight_size_increase(self, chunk: DataChunk) -> None:
        self._flight_size += chunk._book_size

    def _get_extensions(self, params: list[tuple[int, bytes]]) -> None:
        """
        Gets what extensions are supported by the remote party.
        """
        for k, v in params:
            if k == SCTP_PRSCTP_SUPPORTED:
                self._remote_partial_reliability = True
            elif k == SCTP_SUPPORTED_CHUNK_EXT:
                self._remote_extensions = list(v)

    def _set_extensions(self, params: list[tuple[int, bytes]]) -> None:
        """
        Sets what extensions are supported by the local party.
        """
        extensions = []
        if self._local_partial_reliability:
            params.append((SCTP_PRSCTP_SUPPORTED, b""))
            extensions.append(ForwardTsnChunk.type)

        extensions.append(ReconfigChunk.type)
        params.append((SCTP_SUPPORTED_CHUNK_EXT, bytes(extensions)))

    def _get_inbound_stream(self, stream_id: int) -> InboundStream:
        """
        Get or create the inbound stream with the specified ID.
        """
        if stream_id not in self._inbound_streams:
            self._inbound_streams[stream_id] = InboundStream(
                max_message_size=(
                    self._limits.max_message_size if self._limits is not None else None
                ),
                on_remove=self._release_inbound if self._limits is not None else None,
            )
        return self._inbound_streams[stream_id]

    def _release_inbound(self, chunk: DataChunk) -> None:
        self._inbound_bytes -= len(chunk.user_data)
        self._inbound_chunks -= 1
        chunk.user_data = b""
        stream = self._inbound_streams.get(chunk.stream_id)
        if stream is None or not stream.reassembly:
            self._active_inbound_streams.discard(chunk.stream_id)

    def _admit_inbound(self, chunk: DataChunk) -> bool:
        duplicate = (
            uint32_gte(self._last_received_tsn, chunk.tsn)
            or chunk.tsn in self._sack_misordered
        )
        if self._limits is not None:
            retained = (
                self._inbound_chunks
                + len(self._sack_duplicates)
                + len(self._sack_misordered)
            )
            entries = 1 if duplicate else 2
            if retained + entries > self._limits.receive_entries:
                raise ConnectionError("SCTP receive entry limit exceeded")
            if not duplicate:
                if (
                    self._inbound_bytes + len(chunk.user_data)
                    > self._limits.receive_bytes
                ):
                    raise ConnectionError("SCTP receive byte limit exceeded")
                if (
                    chunk.stream_id not in self._active_inbound_streams
                    and len(self._active_inbound_streams) >= self._limits.active_streams
                ):
                    raise ConnectionError(
                        "SCTP active reassembly stream limit exceeded"
                    )
        return duplicate

    def _get_timestamp(self) -> int:
        return int(time.time())

    async def _handle_data(self, data: bytes) -> None:
        """
        Handle data received from the network.
        """
        if self._stopping or self.__state == "closed":
            return
        try:
            _, _, verification_tag, chunks = parse_packet(data)
        except ValueError:
            return

        # is this an init?
        init_chunk = len([x for x in chunks if isinstance(x, InitChunk)])
        if init_chunk:
            assert len(chunks) == 1
            expected_tag = 0
        else:
            expected_tag = self._local_verification_tag

        # verify tag
        if verification_tag != expected_tag:
            self.__log_debug(
                "Bad verification tag %d vs %d", verification_tag, expected_tag
            )
            return

        # handle chunks
        for chunk in chunks:
            try:
                await self._receive_chunk(chunk)
            except (ConnectionError, BufferError, ValueError) as error:
                if self._limits is None:
                    raise
                self._fail(ConnectionError(f"SCTP receive failed: {error}"))
                return
            if self._stopping or self.__state == "closed":
                return

        # send SACK if needed
        if self._sack_needed:
            await self._send_sack()

    def _maybe_abandon(self, chunk: DataChunk) -> bool:
        """
        Determine if a chunk needs to be marked as abandoned.

        If it does, it marks the chunk and any other chunk belong to the same
        message as abandoned.
        """
        if chunk._abandoned:
            return True

        abandon = (
            chunk._max_retransmits is not None
            and chunk._sent_count > chunk._max_retransmits
        ) or (chunk._expiry is not None and chunk._expiry < time.time())
        if not abandon:
            return False

        chunk_pos = self._sent_queue.index(chunk)
        for pos in range(chunk_pos, -1, -1):
            ochunk = self._sent_queue[pos]
            ochunk._abandoned = True
            ochunk._retransmit = False
            if ochunk.flags & SCTP_DATA_FIRST_FRAG:
                break
        for pos in range(chunk_pos, len(self._sent_queue)):
            ochunk = self._sent_queue[pos]
            ochunk._abandoned = True
            ochunk._retransmit = False
            if ochunk.flags & SCTP_DATA_LAST_FRAG:
                break

        return True

    def _mark_received(self, tsn: int) -> bool:
        """
        Mark an incoming data TSN as received.
        """
        # it's a duplicate
        if uint32_gte(self._last_received_tsn, tsn) or tsn in self._sack_misordered:
            self._sack_duplicates.append(tsn)
            return True

        # consolidate misordered entries
        self._sack_misordered.add(tsn)
        for tsn in sorted(self._sack_misordered):
            if tsn == tsn_plus_one(self._last_received_tsn):
                self._last_received_tsn = tsn
            else:
                break

        # filter out obsolete entries
        def is_obsolete(x: int) -> bool:
            return uint32_gt(x, self._last_received_tsn)

        self._sack_duplicates = list(filter(is_obsolete, self._sack_duplicates))
        self._sack_misordered = set(filter(is_obsolete, self._sack_misordered))
        return False

    async def _receive(self, stream_id: int, pp_id: int, data: bytes) -> None:
        """
        Receive data stream -> ULP.
        """
        await self._data_channel_receive(stream_id, pp_id, data)
        if self._limits is not None:
            await asyncio.sleep(0)

    async def _receive_chunk(self, chunk: Chunk) -> None:
        """
        Handle an incoming chunk.
        """
        self.__log_debug("< %s", chunk)

        # common
        if isinstance(chunk, DataChunk):
            await self._receive_data_chunk(chunk)
        elif isinstance(chunk, SackChunk):
            await self._receive_sack_chunk(chunk)
        elif isinstance(chunk, ForwardTsnChunk):
            await self._receive_forward_tsn_chunk(chunk)
        elif isinstance(chunk, HeartbeatChunk):
            heartbeat_ack = HeartbeatAckChunk()
            heartbeat_ack.params = chunk.params
            await self._send_chunk(heartbeat_ack)
        elif isinstance(chunk, AbortChunk):
            self.__log_debug("x Association was aborted by remote party")
            self._set_state(self.State.CLOSED)
        elif isinstance(chunk, ShutdownChunk):
            self._t2_cancel()
            self._set_state(self.State.SHUTDOWN_RECEIVED)
            shutdown_ack = ShutdownAckChunk()
            await self._send_chunk(shutdown_ack)
            if self._stopping or self.__state == "closed":
                return
            self._t2_start(shutdown_ack)
            self._set_state(self.State.SHUTDOWN_ACK_SENT)
        elif (
            isinstance(chunk, ShutdownCompleteChunk)
            and self._association_state == self.State.SHUTDOWN_ACK_SENT
        ):
            self._t2_cancel()
            self._set_state(self.State.CLOSED)
        elif (
            isinstance(chunk, ReconfigChunk)
            and self._association_state == self.State.ESTABLISHED
        ):
            for param in chunk.params:
                cls = RECONFIG_PARAM_TYPES.get(param[0])
                if cls is not None:
                    await self._receive_reconfig_param(cls.parse(param[1]))
                    if self._stopping or self.__state == "closed":
                        return

        # an INIT may collide with our own, see RFC 9260 section 5.2.1
        elif isinstance(chunk, InitChunk):
            if not (
                self._association_state == self.State.ESTABLISHED
                and chunk.initiate_tag == self._remote_verification_tag
                and chunk.initial_tsn == self._remote_initial_tsn
            ):
                self._remote_initial_tsn = chunk.initial_tsn
                self._last_received_tsn = tsn_minus_one(chunk.initial_tsn)
                self._reconfig_response_seq = tsn_minus_one(chunk.initial_tsn)
                self._remote_verification_tag = chunk.initiate_tag
                self._ssthresh = chunk.advertised_rwnd
                self._get_extensions(chunk.params)

                self.__log_debug(
                    "- Peer supports %d outbound streams, %d max inbound streams",
                    chunk.outbound_streams,
                    chunk.inbound_streams,
                )
                self._inbound_streams_count = min(
                    chunk.outbound_streams, self._inbound_streams_max
                )
                self._outbound_streams_count = min(
                    self._outbound_streams_count, chunk.inbound_streams
                )

            init_ack = InitAckChunk()
            init_ack.initiate_tag = self._local_verification_tag
            init_ack.advertised_rwnd = self._advertised_rwnd
            init_ack.outbound_streams = self._outbound_streams_count
            init_ack.inbound_streams = self._inbound_streams_max
            init_ack.initial_tsn = self._local_tsn
            self._set_extensions(init_ack.params)

            # generate state cookie
            cookie = pack("!L", self._get_timestamp())
            cookie += hmac.new(self._hmac_key, cookie, "sha1").digest()
            init_ack.params.append((SCTP_STATE_COOKIE, cookie))
            await self._send_chunk(init_ack)
        elif isinstance(chunk, CookieEchoChunk):
            # check state cookie MAC
            cookie = chunk.body
            if (
                len(cookie) != COOKIE_LENGTH
                or hmac.new(self._hmac_key, cookie[0:4], "sha1").digest() != cookie[4:]
            ):
                self.__log_debug("x State cookie is invalid")
                return

            # check state cookie lifetime
            now = self._get_timestamp()
            stamp = unpack_from("!L", cookie)[0]
            if stamp < now - COOKIE_LIFETIME or stamp > now:
                self.__log_debug("x State cookie has expired")
                error = ErrorChunk()
                error.params.append((SCTP_CAUSE_STALE_COOKIE, b"\x00" * 8))
                await self._send_chunk(error)
                return

            self._t1_cancel()
            cookie_ack = CookieAckChunk()
            await self._send_chunk(cookie_ack)
            if self._stopping or self.__state == "closed":
                return
            self._set_state(self.State.ESTABLISHED)

        elif (
            isinstance(chunk, InitAckChunk)
            and self._association_state == self.State.COOKIE_WAIT
        ):
            # cancel T1 timer and process chunk
            self._t1_cancel()
            self._remote_initial_tsn = chunk.initial_tsn
            self._last_received_tsn = tsn_minus_one(chunk.initial_tsn)
            self._reconfig_response_seq = tsn_minus_one(chunk.initial_tsn)
            self._remote_verification_tag = chunk.initiate_tag
            self._ssthresh = chunk.advertised_rwnd
            self._get_extensions(chunk.params)

            self.__log_debug(
                "- Peer supports %d outbound streams, %d max inbound streams",
                chunk.outbound_streams,
                chunk.inbound_streams,
            )
            self._inbound_streams_count = min(
                chunk.outbound_streams, self._inbound_streams_max
            )
            self._outbound_streams_count = min(
                self._outbound_streams_count, chunk.inbound_streams
            )

            echo = CookieEchoChunk()
            for k, v in chunk.params:
                if k == SCTP_STATE_COOKIE:
                    echo.body = v
                    break
            await self._send_chunk(echo)
            if self._stopping or self.__state == "closed":
                return

            # start T1 timer and enter COOKIE-ECHOED state
            self._t1_start(echo)
            self._set_state(self.State.COOKIE_ECHOED)
        elif (
            isinstance(chunk, CookieAckChunk)
            and self._association_state == self.State.COOKIE_ECHOED
        ):
            # cancel T1 timer and enter ESTABLISHED state
            self._t1_cancel()
            self._set_state(self.State.ESTABLISHED)
        elif isinstance(chunk, ErrorChunk) and self._association_state in [
            self.State.COOKIE_WAIT,
            self.State.COOKIE_ECHOED,
        ]:
            self._t1_cancel()
            self._set_state(self.State.CLOSED)
            self.__log_debug("x Could not establish association")
            return

    async def _receive_data_chunk(self, chunk: DataChunk) -> None:
        """
        Handle a DATA chunk.
        """
        try:
            self._admit_inbound(chunk)
            self._sack_needed = True

            # mark as received
            if self._mark_received(chunk.tsn):
                return

            # find stream
            inbound_stream = self._get_inbound_stream(chunk.stream_id)
            if self._limits is not None:
                self._inbound_bytes += len(chunk.user_data)
                self._inbound_chunks += 1
                self._active_inbound_streams.add(chunk.stream_id)

            # defragment data
            inbound_stream.add_chunk(chunk)
            self._advertised_rwnd -= len(chunk.user_data)
            for message in inbound_stream.pop_messages():
                self._advertised_rwnd += len(message[2])
                await self._receive(*message)
                if self._stopping or self.__state == "closed":
                    return
        except ConnectionError as error:
            if self._limits is not None:
                self._fail(error)
            raise

    async def _receive_forward_tsn_chunk(self, chunk: ForwardTsnChunk) -> None:
        """
        Handle a FORWARD TSN chunk.
        """
        self._sack_needed = True

        # it's a duplicate
        if uint32_gte(self._last_received_tsn, chunk.cumulative_tsn):
            return

        def is_obsolete(x: int) -> bool:
            return uint32_gt(x, self._last_received_tsn)

        # advance cumulative TSN
        self._last_received_tsn = chunk.cumulative_tsn
        self._sack_misordered = set(filter(is_obsolete, self._sack_misordered))
        for tsn in sorted(self._sack_misordered):
            if tsn == tsn_plus_one(self._last_received_tsn):
                self._last_received_tsn = tsn
            else:
                break

        # filter out obsolete entries
        self._sack_duplicates = list(filter(is_obsolete, self._sack_duplicates))
        self._sack_misordered = set(filter(is_obsolete, self._sack_misordered))

        # update reassembly
        for stream_id, stream_seq in chunk.streams:
            inbound_stream = self._get_inbound_stream(stream_id)

            # advance sequence number and perform delivery
            inbound_stream.sequence_number = uint16_add(stream_seq, 1)
            for message in inbound_stream.pop_messages():
                self._advertised_rwnd += len(message[2])
                await self._receive(*message)
                if self._stopping or self.__state == "closed":
                    return

        # prune obsolete chunks
        for stream_id, inbound_stream in self._inbound_streams.items():
            self._advertised_rwnd += inbound_stream.prune_chunks(
                self._last_received_tsn
            )

    async def _receive_sack_chunk(self, chunk: SackChunk) -> None:
        """
        Handle a SACK chunk.
        """
        async with self._sender_lock:
            if self._stopping or self.__state == "closed":
                return
            if not self._update_sack(chunk):
                return
        await self._data_channel_flush()
        await self._transmit()

    def _update_sack(self, chunk: SackChunk) -> bool:
        if uint32_gt(self._last_sacked_tsn, chunk.cumulative_tsn):
            return False

        received_time = time.time()
        self._last_sacked_tsn = chunk.cumulative_tsn
        cwnd_fully_utilized = self._flight_size >= self._cwnd
        done = 0
        done_bytes = 0

        # handle acknowledged data
        while self._sent_queue and uint32_gte(
            self._last_sacked_tsn, self._sent_queue[0].tsn
        ):
            schunk = self._sent_queue.popleft()
            done += 1
            if not schunk._acked:
                done_bytes += schunk._book_size
                self._flight_size_decrease(schunk)

            # update RTO estimate
            if done == 1 and schunk._sent_count == 1:
                self._update_rto(received_time - schunk._sent_time)
            self._release_chunk(schunk)

        # handle gap blocks
        loss = False
        if chunk.gaps:
            seen = set()
            for gap in chunk.gaps:
                for pos in range(gap[0], gap[1] + 1):
                    highest_seen_tsn = (chunk.cumulative_tsn + pos) % SCTP_TSN_MODULO
                    seen.add(highest_seen_tsn)

            # determined Highest TSN Newly Acked (HTNA)
            highest_newly_acked = chunk.cumulative_tsn
            for schunk in self._sent_queue:
                if uint32_gt(schunk.tsn, highest_seen_tsn):
                    break
                if schunk.tsn in seen and not schunk._acked:
                    done_bytes += schunk._book_size
                    schunk._acked = True
                    self._flight_size_decrease(schunk)
                    highest_newly_acked = schunk.tsn

            # strike missing chunks prior to HTNA
            for schunk in self._sent_queue:
                if uint32_gt(schunk.tsn, highest_newly_acked):
                    break
                if schunk.tsn not in seen and not schunk._fast_retransmitted:
                    schunk._misses += 1
                    if schunk._misses == 3:
                        schunk._misses = 0
                        schunk._fast_retransmitted = True
                        if not self._maybe_abandon(schunk):
                            schunk._retransmit = True

                        schunk._acked = False
                        self._flight_size_decrease(schunk)

                        loss = True

        # adjust congestion window
        if self._fast_recovery_exit is None:
            if done and cwnd_fully_utilized:
                if self._cwnd <= self._ssthresh:
                    # slow start
                    self._cwnd += min(done_bytes, USERDATA_MAX_LENGTH)
                else:
                    # congestion avoidance
                    self._partial_bytes_acked += done_bytes
                    if self._partial_bytes_acked >= self._cwnd:
                        self._partial_bytes_acked -= self._cwnd
                        self._cwnd += USERDATA_MAX_LENGTH
            if loss:
                self._ssthresh = max(self._cwnd // 2, 4 * USERDATA_MAX_LENGTH)
                self._cwnd = self._ssthresh
                self._partial_bytes_acked = 0
                self._fast_recovery_exit = self._sent_queue[-1].tsn
                self._fast_recovery_transmit = True
        elif uint32_gte(chunk.cumulative_tsn, self._fast_recovery_exit):
            self._fast_recovery_exit = None

        if not self._sent_queue:
            # there is no outstanding data, stop T3
            self._t3_cancel()
        elif done:
            # the earliest outstanding chunk was acknowledged, restart T3
            self._t3_restart()

        self._update_advanced_peer_ack_point()
        return True

    async def _receive_reconfig_param(
        self,
        param: Union[
            StreamAddOutgoingParam, StreamResetOutgoingParam, StreamResetResponseParam
        ],
    ) -> None:
        """
        Handle a RE-CONFIG parameter.
        """
        self.__log_debug("<< %s", param)

        if isinstance(param, StreamResetOutgoingParam):
            # mark closed inbound streams
            for stream_id in param.streams:
                stream = self._inbound_streams.pop(stream_id, None)
                if self._limits is not None and stream is not None:
                    for chunk in stream.reassembly:
                        self._advertised_rwnd += len(chunk.user_data)
                        self._release_inbound(chunk)

                # close data channel
                channel = self._data_channels.get(stream_id)
                if channel:
                    self._data_channel_close(channel)

            # send response
            response_param = StreamResetResponseParam(
                response_sequence=param.request_sequence, result=1
            )
            self._reconfig_response_seq = param.request_sequence

            await self._send_reconfig_param(response_param)
        elif isinstance(param, StreamAddOutgoingParam):
            # increase inbound streams
            self._inbound_streams_count += param.new_streams

            # send response
            response_param = StreamResetResponseParam(
                response_sequence=param.request_sequence, result=1
            )
            self._reconfig_response_seq = param.request_sequence

            await self._send_reconfig_param(response_param)
        elif isinstance(param, StreamResetResponseParam):
            if (
                self._reconfig_request
                and param.response_sequence == self._reconfig_request.request_sequence
            ):
                # mark closed streams
                for stream_id in self._reconfig_request.streams:
                    self._outbound_stream_seq.pop(stream_id, None)
                    self._data_channel_closed(stream_id)

                self._reconfig_request = None
                await self._transmit_reconfig()

    async def _send(
        self,
        stream_id: int,
        pp_id: int,
        user_data: bytes,
        expiry: Optional[float] = None,
        max_retransmits: Optional[int] = None,
        ordered: bool = True,
    ) -> None:
        """
        Send data ULP -> stream.
        """
        self._enqueue_sctp(
            stream_id, pp_id, user_data, expiry, max_retransmits, ordered
        )
        del user_data
        await self._transmit()

    def _enqueue_sctp(
        self,
        stream_id: int,
        pp_id: int,
        user_data: bytes,
        expiry: Optional[float] = None,
        max_retransmits: Optional[int] = None,
        ordered: bool = True,
        credit: Optional[_SendCredit] = None,
    ) -> None:
        if self._stopping or self.__state == "closed":
            raise ConnectionError("SCTP transport is closed")
        if self._limits is not None and credit is None:
            if not user_data:
                raise ValueError("SCTP message size limit exceeded")
            credit = self._allocate_send_credit(user_data)
        if ordered:
            stream_seq = self._outbound_stream_seq.get(stream_id, 0)
        else:
            stream_seq = 0

        fragments = math.ceil(len(user_data) / USERDATA_MAX_LENGTH)
        payload = memoryview(user_data) if credit is not None else user_data
        pos = 0
        for fragment in range(0, fragments):
            chunk = DataChunk()
            chunk.flags = 0
            if not ordered:
                chunk.flags = SCTP_DATA_UNORDERED
            if fragment == 0:
                chunk.flags |= SCTP_DATA_FIRST_FRAG
            if fragment == fragments - 1:
                chunk.flags |= SCTP_DATA_LAST_FRAG
            chunk.tsn = self._local_tsn
            chunk.stream_id = stream_id
            chunk.stream_seq = stream_seq
            chunk.protocol = pp_id
            chunk.user_data = payload[pos : pos + USERDATA_MAX_LENGTH]
            chunk._credit = credit

            # FIXME: dynamically added attributes, mypy can't handle them
            # initialize counters
            chunk._abandoned = False
            chunk._acked = False
            chunk._book_size = len(chunk.user_data)
            chunk._expiry = expiry
            chunk._fast_retransmitted = False
            chunk._max_retransmits = max_retransmits
            chunk._misses = 0
            chunk._retransmit = False
            chunk._sent_count = 0
            chunk._sent_time = None

            pos += USERDATA_MAX_LENGTH
            self._local_tsn = tsn_plus_one(self._local_tsn)
            self._outbound_queue.append(chunk)

        if ordered:
            self._outbound_stream_seq[stream_id] = uint16_add(stream_seq, 1)

    async def _send_chunk(self, chunk: Chunk) -> None:
        """
        Transmit a chunk (no bundling for now).
        """
        self.__log_debug("> %s", chunk)
        await self.__transport._send_data(
            serialize_packet(
                self._local_port,
                self._remote_port,
                self._remote_verification_tag,
                chunk,
            )
        )

    async def _send_reconfig_param(
        self,
        param: Union[
            StreamAddOutgoingParam, StreamResetOutgoingParam, StreamResetResponseParam
        ],
    ) -> None:
        chunk = ReconfigChunk()
        for k, cls in RECONFIG_PARAM_TYPES.items():
            if isinstance(param, cls):
                param_type = k
                break
        chunk.params.append((param_type, bytes(param)))

        self.__log_debug(">> %s", param)
        await self._send_chunk(chunk)

    async def _send_sack(self) -> None:
        """
        Build and send a selective acknowledgement (SACK) chunk.
        """
        gaps: list[list[int]] = []
        gap_next = None
        for tsn in sorted(self._sack_misordered):
            pos = (tsn - self._last_received_tsn) % SCTP_TSN_MODULO
            if tsn == gap_next:
                gaps[-1][1] = pos
            else:
                gaps.append([pos, pos])
            gap_next = tsn_plus_one(tsn)

        sack = SackChunk()
        sack.cumulative_tsn = self._last_received_tsn
        sack.advertised_rwnd = max(0, self._advertised_rwnd)
        sack.duplicates = self._sack_duplicates[:]
        sack.gaps = [tuple(x) for x in gaps]

        await self._send_chunk(sack)

        self._sack_duplicates.clear()
        self._sack_needed = False

    def _set_state(self, state: "RTCSctpTransport.State") -> None:
        """
        Transition the SCTP association to a new state.
        """
        if state != self._association_state:
            self.__log_debug("- %s -> %s", self._association_state, state)
            self._association_state = state

        if state == self.State.ESTABLISHED:
            self.__state = "connected"
            for channel in list(self._data_channels.values()):
                if channel.negotiated and channel.readyState != "open":
                    channel._setReadyState("open")
            self._schedule("flush", self._data_channel_flush)
        elif state == self.State.CLOSED:
            self._t1_cancel()
            self._t2_cancel()
            self._t3_cancel()
            self.__state = "closed"
            for task in self._service_tasks.values():
                if task is not asyncio.current_task():
                    task.cancel()
            self._data_channel_queue.clear()
            self._outbound_queue.clear()
            self._sent_queue.clear()
            self._inbound_streams.clear()
            self._sack_misordered.clear()
            self._sack_duplicates.clear()
            self._active_inbound_streams.clear()
            self._inbound_bytes = self._inbound_chunks = 0
            for reservation in self._send_reservations:
                reservation._active = False
            self._send_reservations.clear()
            for credit in self._send_credits:
                credit.active = False
            self._send_credits.clear()
            self._send_bytes = self._send_chunks = self._send_messages = 0
            self._wake_senders()

            # close data channels
            for stream_id in list(self._data_channels.keys()):
                self._data_channel_closed(stream_id)

            # no more events will be emitted, so remove all event listeners
            # to facilitate garbage collection.
            self.remove_all_listeners()

    # timers

    def _t1_cancel(self) -> None:
        if self._t1_handle is not None:
            self.__log_debug("- T1(%s) cancel", chunk_type(self._t1_chunk))
            self._t1_handle.cancel()
            self._t1_handle = None
            self._t1_chunk = None

    def _t1_expired(self) -> None:
        if self._stopping or self.__state == "closed":
            return
        self._t1_failures += 1
        self._t1_handle = None
        self.__log_debug(
            "x T1(%s) expired %d", chunk_type(self._t1_chunk), self._t1_failures
        )
        if self._t1_failures > SCTP_MAX_INIT_RETRANS:
            self._set_state(self.State.CLOSED)
        else:
            chunk = self._t1_chunk
            self._schedule("timer1", lambda: self._send_chunk(chunk))
            self._t1_handle = self._loop.call_later(self._rto, self._t1_expired)

    def _t1_start(self, chunk: Chunk) -> None:
        assert self._t1_handle is None
        self._t1_chunk = chunk
        self._t1_failures = 0
        self.__log_debug("- T1(%s) start", chunk_type(self._t1_chunk))
        self._t1_handle = self._loop.call_later(self._rto, self._t1_expired)

    def _t2_cancel(self) -> None:
        if self._t2_handle is not None:
            self.__log_debug("- T2(%s) cancel", chunk_type(self._t2_chunk))
            self._t2_handle.cancel()
            self._t2_handle = None
            self._t2_chunk = None

    def _t2_expired(self) -> None:
        if self._stopping or self.__state == "closed":
            return
        self._t2_failures += 1
        self._t2_handle = None
        self.__log_debug(
            "x T2(%s) expired %d", chunk_type(self._t2_chunk), self._t2_failures
        )
        if self._t2_failures > SCTP_MAX_ASSOCIATION_RETRANS:
            self._set_state(self.State.CLOSED)
        else:
            chunk = self._t2_chunk
            self._schedule("timer2", lambda: self._send_chunk(chunk))
            self._t2_handle = self._loop.call_later(self._rto, self._t2_expired)

    def _t2_start(self, chunk: ShutdownAckChunk) -> None:
        assert self._t2_handle is None
        self._t2_chunk = chunk
        self._t2_failures = 0
        self.__log_debug("- T2(%s) start", chunk_type(self._t2_chunk))
        self._t2_handle = self._loop.call_later(self._rto, self._t2_expired)

    def _t3_expired(self) -> None:
        if self._stopping or self.__state == "closed":
            return
        if not self._uses_backpressure:
            self._t3_handle = None
            self._update_t3()
            self._schedule("transmit", self._transmit)
        elif self._t3_handle is not None:
            self._t3_pending = self._t3_handle
            self._schedule("timer3", self._run_t3)

    async def _run_t3(self) -> None:
        while self._t3_pending is not None:
            expired = self._t3_pending
            self._t3_pending = None
            async with self._sender_lock:
                if self._stopping or self.__state == "closed":
                    return
                if self._t3_handle is not expired:
                    continue
                self._t3_handle = None
                self._update_t3()
                await self._transmit_locked()

    def _update_t3(self) -> None:
        self.__log_debug("x T3 expired")

        # mark retransmit or abandoned chunks
        for chunk in self._sent_queue:
            if not self._maybe_abandon(chunk):
                chunk._retransmit = True
        self._update_advanced_peer_ack_point()

        # adjust congestion window
        self._fast_recovery_exit = None
        self._flight_size = 0
        self._partial_bytes_acked = 0

        self._ssthresh = max(self._cwnd // 2, 4 * USERDATA_MAX_LENGTH)
        self._cwnd = USERDATA_MAX_LENGTH

    def _t3_restart(self) -> None:
        self.__log_debug("- T3 restart")
        if self._t3_handle is not None:
            self._t3_handle.cancel()
            self._t3_handle = None
        self._t3_pending = None
        self._t3_handle = self._loop.call_later(self._rto, self._t3_expired)

    def _t3_start(self) -> None:
        assert self._t3_handle is None
        self.__log_debug("- T3 start")
        self._t3_handle = self._loop.call_later(self._rto, self._t3_expired)

    def _t3_cancel(self) -> None:
        self._t3_pending = None
        if self._t3_handle is not None:
            self.__log_debug("- T3 cancel")
            self._t3_handle.cancel()
            self._t3_handle = None

    async def _transmit(self) -> None:
        """
        Transmit outbound data.
        """
        async with self._sender_lock:
            await self._transmit_locked()

    async def _transmit_locked(self) -> None:
        if self._stopping or self.__state == "closed":
            return
        # send FORWARD TSN
        if self._forward_tsn_chunk is not None:
            await self._send_chunk(self._forward_tsn_chunk)
            if self._stopping or self.__state == "closed":
                return
            self._forward_tsn_chunk = None

            # ensure T3 is running
            if not self._t3_handle:
                self._t3_start()

        # limit burst size
        if self._fast_recovery_exit is not None:
            burst_size = 2 * USERDATA_MAX_LENGTH
        else:
            burst_size = 4 * USERDATA_MAX_LENGTH
        cwnd = min(self._flight_size + burst_size, self._cwnd)

        # retransmit
        retransmit_earliest = True
        for chunk in self._sent_queue:
            if chunk._retransmit:
                if self._fast_recovery_transmit:
                    self._fast_recovery_transmit = False
                elif self._flight_size >= cwnd:
                    return
                self._flight_size_increase(chunk)

                chunk._misses = 0
                chunk._retransmit = False
                chunk._sent_count += 1
                await self._send_chunk(chunk)
                if self._stopping or self.__state == "closed":
                    return
                if retransmit_earliest:
                    # restart the T3 timer as the earliest outstanding TSN
                    # is being retransmitted
                    self._t3_restart()
            retransmit_earliest = False

        while self._outbound_queue and self._flight_size < cwnd:
            chunk = self._outbound_queue.popleft()
            self._sent_queue.append(chunk)
            self._flight_size_increase(chunk)

            # update counters
            chunk._sent_count += 1
            chunk._sent_time = time.time()

            await self._send_chunk(chunk)
            if self._stopping or self.__state == "closed":
                return
            if not self._t3_handle:
                self._t3_start()

    async def _transmit_reconfig(self) -> None:
        if (
            self._association_state == self.State.ESTABLISHED
            and self._reconfig_queue
            and not self._reconfig_request
        ):
            streams = self._reconfig_queue[0:RECONFIG_MAX_STREAMS]
            self._reconfig_queue = self._reconfig_queue[RECONFIG_MAX_STREAMS:]
            param = StreamResetOutgoingParam(
                request_sequence=self._reconfig_request_seq,
                response_sequence=self._reconfig_response_seq,
                last_tsn=tsn_minus_one(self._local_tsn),
                streams=streams,
            )
            self._reconfig_request = param
            self._reconfig_request_seq = tsn_plus_one(self._reconfig_request_seq)

            await self._send_reconfig_param(param)

    def _update_advanced_peer_ack_point(self) -> None:
        """
        Try to advance "Advanced.Peer.Ack.Point" according to RFC 3758.
        """
        if uint32_gt(self._last_sacked_tsn, self._advanced_peer_ack_tsn):
            self._advanced_peer_ack_tsn = self._last_sacked_tsn

        done = 0
        streams = {}
        while self._sent_queue and self._sent_queue[0]._abandoned:
            chunk = self._sent_queue.popleft()
            self._advanced_peer_ack_tsn = chunk.tsn
            done += 1
            if not (chunk.flags & SCTP_DATA_UNORDERED):
                streams[chunk.stream_id] = chunk.stream_seq
            self._release_chunk(chunk)

        if done:
            # build FORWARD TSN
            self._forward_tsn_chunk = ForwardTsnChunk()
            self._forward_tsn_chunk.cumulative_tsn = self._advanced_peer_ack_tsn
            self._forward_tsn_chunk.streams = list(streams.items())

    def _update_rto(self, R: float) -> None:
        """
        Update RTO given a new roundtrip measurement R.
        """
        if self._srtt is None:
            self._rttvar = R / 2
            self._srtt = R
        else:
            self._rttvar = (1 - SCTP_RTO_BETA) * self._rttvar + SCTP_RTO_BETA * abs(
                self._srtt - R
            )
            self._srtt = (1 - SCTP_RTO_ALPHA) * self._srtt + SCTP_RTO_ALPHA * R
        self._rto = max(SCTP_RTO_MIN, min(self._srtt + 4 * self._rttvar, SCTP_RTO_MAX))

    def _data_channel_close(self, channel: RTCDataChannel) -> None:
        """
        Request closing the datachannel by sending an Outgoing Stream Reset Request.
        """
        if channel.readyState not in ["closing", "closed"]:
            channel._setReadyState("closing")

            if self._association_state == self.State.ESTABLISHED:
                # queue a stream reset
                self._reconfig_queue.append(channel.id)
                if len(self._reconfig_queue) == 1:
                    self._schedule("reconfig", self._transmit_reconfig)
            else:
                # remove any queued messages for the datachannel
                new_queue: DataChannelQueue = deque()
                for queue_item in self._data_channel_queue:
                    if queue_item[0] != channel:
                        new_queue.append(queue_item)
                    else:
                        self._release_credit(queue_item[3])
                self._data_channel_queue = new_queue

                # mark the datachannel as closed
                if channel.id is not None:
                    self._data_channels.pop(channel.id)
                channel._setReadyState("closed")
            self._wake_senders()

    def _data_channel_closed(self, stream_id: int) -> None:
        channel = self._data_channels.pop(stream_id)
        channel._setReadyState("closed")
        self._wake_senders()

    async def _data_channel_flush(self) -> None:
        async with self._flush_lock:
            await self._data_channel_flush_locked()

    async def _data_channel_flush_locked(self) -> None:
        """
        Try to flush buffered data to the SCTP layer.

        We wait until the association is established, as we need to know
        whether we are a client or a server to correctly assign an odd/even ID
        to the data channels.
        """
        if self._association_state != self.State.ESTABLISHED or self._stopping:
            return

        while self._data_channel_queue and not self._outbound_queue:
            channel, protocol, user_data, credit = self._data_channel_queue.popleft()

            # register channel if necessary
            stream_id = channel.id
            if stream_id is None:
                stream_id = self._data_channel_id
                while stream_id in self._data_channels:
                    stream_id += 2
                self._data_channels[stream_id] = channel
                channel._setId(stream_id)

            # send data
            size = len(user_data)
            if protocol == WEBRTC_DCEP:
                self._enqueue_sctp(stream_id, protocol, user_data, credit=credit)
            else:
                if channel.maxPacketLifeTime:
                    expiry = time.time() + (channel.maxPacketLifeTime / 1000)
                else:
                    expiry = None
                self._enqueue_sctp(
                    stream_id,
                    protocol,
                    user_data,
                    expiry=expiry,
                    max_retransmits=channel.maxRetransmits,
                    ordered=channel.ordered,
                    credit=credit,
                )
            del user_data
            await self._transmit()
            if self._stopping or self.__state == "closed":
                return
            if protocol != WEBRTC_DCEP:
                channel._addBufferedAmount(-size)

    def _data_channel_add_negotiated(self, channel: RTCDataChannel) -> None:
        if channel.id in self._data_channels:
            raise ValueError(f"Data channel with ID {channel.id} already registered")

        self._data_channels[channel.id] = channel

        if self._association_state == self.State.ESTABLISHED:
            channel._setReadyState("open")

    def _data_channel_open(self, channel: RTCDataChannel) -> None:
        if channel.id is not None:
            if channel.id in self._data_channels:
                raise ValueError(
                    f"Data channel with ID {channel.id} already registered"
                )
            else:
                self._data_channels[channel.id] = channel

        channel_type = DATA_CHANNEL_RELIABLE
        priority = 0
        reliability = 0

        if not channel.ordered:
            channel_type |= 0x80
        if channel.maxRetransmits is not None:
            channel_type |= 1
            reliability = channel.maxRetransmits
        elif channel.maxPacketLifeTime is not None:
            channel_type |= 2
            reliability = channel.maxPacketLifeTime

        data = pack(
            "!BBHLHH",
            DATA_CHANNEL_OPEN,
            channel_type,
            priority,
            reliability,
            len(channel.label),
            len(channel.protocol),
        )
        data += channel.label.encode("utf8")
        data += channel.protocol.encode("utf8")
        self._queue_data(channel, WEBRTC_DCEP, data)
        self._schedule("flush", self._data_channel_flush)

    async def _data_channel_receive(
        self, stream_id: int, pp_id: int, data: bytes
    ) -> None:
        if pp_id == WEBRTC_DCEP and len(data):
            msg_type = data[0]
            if msg_type == DATA_CHANNEL_OPEN and len(data) >= 12:
                # we should not receive an open for an existing channel
                assert stream_id not in self._data_channels

                (
                    msg_type,
                    channel_type,
                    priority,
                    reliability,
                    label_length,
                    protocol_length,
                ) = unpack_from("!BBHLHH", data)
                pos = 12
                label = data[pos : pos + label_length].decode("utf8")
                pos += label_length
                protocol = data[pos : pos + protocol_length].decode("utf8")

                # check channel type
                maxPacketLifeTime = None
                maxRetransmits = None
                if (channel_type & 0x03) == 1:
                    maxRetransmits = reliability
                elif (channel_type & 0x03) == 2:
                    maxPacketLifeTime = reliability

                # register channel
                parameters = RTCDataChannelParameters(
                    label=label,
                    ordered=(channel_type & 0x80) == 0,
                    maxPacketLifeTime=maxPacketLifeTime,
                    maxRetransmits=maxRetransmits,
                    protocol=protocol,
                    id=stream_id,
                )
                channel = RTCDataChannel(self, parameters, False)
                channel._setReadyState("open")
                self._data_channels[stream_id] = channel

                # send ack
                self._queue_data(channel, WEBRTC_DCEP, pack("!B", DATA_CHANNEL_ACK))
                await self._data_channel_flush()
                if self._stopping or self.__state == "closed":
                    return

                # emit channel
                self.emit("datachannel", channel)
            elif msg_type == DATA_CHANNEL_ACK:
                assert stream_id in self._data_channels
                channel = self._data_channels[stream_id]
                channel._setReadyState("open")
        elif pp_id == WEBRTC_STRING and stream_id in self._data_channels:
            # emit message
            self._data_channels[stream_id].emit("message", data.decode("utf8"))
        elif pp_id == WEBRTC_STRING_EMPTY and stream_id in self._data_channels:
            # emit message
            self._data_channels[stream_id].emit("message", "")
        elif pp_id == WEBRTC_BINARY and stream_id in self._data_channels:
            # emit message
            self._data_channels[stream_id].emit("message", data)
        elif pp_id == WEBRTC_BINARY_EMPTY and stream_id in self._data_channels:
            # emit message
            self._data_channels[stream_id].emit("message", b"")

    def _data_channel_send(
        self, channel: RTCDataChannel, data: Union[bytes, str]
    ) -> None:
        self._check_send_channel(channel)
        pp_id, user_data = self._data_channel_encode(data)
        self._queue_data(channel, pp_id, user_data)
        channel._addBufferedAmount(len(user_data))
        self._schedule("flush", self._data_channel_flush)

    def _check_remote_message_size(self, size: int) -> None:
        if self._remote_max_message_size and size > self._remote_max_message_size:
            raise ValueError(
                f"Cannot send message of {size} bytes, the remote party "
                f"only supports messages up to {self._remote_max_message_size} bytes"
            )

    def _data_channel_encode(self, data: Union[bytes, str]) -> tuple[int, bytes]:
        if not isinstance(data, (str, bytes)):
            raise ValueError(f"Cannot send unsupported data type: {type(data)}")
        if data == "":
            pp_id, user_data = WEBRTC_STRING_EMPTY, b"\x00"
        elif isinstance(data, str):
            pp_id, user_data = WEBRTC_STRING, data.encode("utf8")
        elif data == b"":
            pp_id, user_data = WEBRTC_BINARY_EMPTY, b"\x00"
        else:
            pp_id, user_data = WEBRTC_BINARY, data

        self._check_remote_message_size(len(user_data))
        return pp_id, user_data

    class State(enum.Enum):
        CLOSED = 1
        COOKIE_WAIT = 2
        COOKIE_ECHOED = 3
        ESTABLISHED = 4
        SHUTDOWN_PENDING = 5
        SHUTDOWN_SENT = 6
        SHUTDOWN_RECEIVED = 7
        SHUTDOWN_ACK_SENT = 8
