import enum
from dataclasses import dataclass
from typing import Optional, Union

from aioice import IceLimits


@dataclass(frozen=True)
class SctpLimits:
    """Optional per-association retained-storage limits."""

    send_bytes: int = 64 * 1024 * 1024 + 4096
    send_chunks: int = 65536
    send_messages: int = 512
    send_waiters: int = 64
    receive_bytes: int = 4 * 1024 * 1024
    receive_entries: int = 8192
    active_streams: int = 16
    max_message_size: int = 262144

    def __post_init__(self) -> None:
        for value in vars(self).values():
            if type(value) is not int or value <= 0:
                raise ValueError("SCTP limits must be positive integers")


@dataclass
class RTCIceServer:
    """
    The :class:`RTCIceServer` dictionary defines how to connect to a single
    STUN or TURN server. It includes both the URL and the necessary credentials,
    if any, to connect to the server.
    """

    urls: Union[str, list[str]]
    """
    This required property is either a single string or a list of strings,
    each specifying a URL which can be used to connect to the server.
    """
    username: Optional[str] = None
    "The username to use during authentication (for TURN only)."
    credential: Optional[str] = None
    "The credential to use during authentication (for TURN only)."
    credentialType: str = "password"


class RTCBundlePolicy(enum.Enum):
    """
    The :class:`RTCBundlePolicy` affects which media tracks are negotiated if
    the remote endpoint is not bundle-aware, and what ICE candidates are
    gathered.

    See https://w3c.github.io/webrtc-pc/#rtcbundlepolicy-enum
    """

    BALANCED = "balanced"
    """
    Gather ICE candidates for each media type in use (audio, video, and data).
    If the remote endpoint is not bundle-aware, negotiate only one audio and
    video track on separate transports.
    """

    MAX_COMPAT = "max-compat"
    """
    Gather ICE candidates for each track. If the remote endpoint is not
    bundle-aware, negotiate all media tracks on separate transports.
    """

    MAX_BUNDLE = "max-bundle"
    """
    Gather ICE candidates for only one track. If the remote endpoint is not
    bundle-aware, negotiate only one media track.
    """


@dataclass
class RTCConfiguration:
    """
    The :class:`RTCConfiguration` dictionary is used to provide configuration
    options for an :class:`RTCPeerConnection`.
    """

    iceServers: Optional[list[RTCIceServer]] = None
    "A list of :class:`RTCIceServer` objects to configure STUN / TURN servers."

    bundlePolicy: RTCBundlePolicy = RTCBundlePolicy.BALANCED
    "The media-bundling policy to use when gathering ICE candidates."

    alwaysNegotiateDataChannels: bool = False
    "Whether to always negotiate data channels in the SDP."

    sctpLimits: Optional[SctpLimits] = None
    "Optional SCTP retained-storage limits."

    iceLimits: Optional[IceLimits] = None
    "Optional direct ICE retained-storage limits."
