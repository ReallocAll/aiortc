import asyncio
from unittest import IsolatedAsyncioTestCase

from aiortc.rtcconfiguration import SctpLimits
from aiortc.rtcdatachannel import RTCDataChannel, RTCDataChannelParameters
from aiortc.rtcsctptransport import (
    SCTP_DATA_FIRST_FRAG,
    SCTP_DATA_LAST_FRAG,
    SCTP_PRSCTP_SUPPORTED,
    SCTP_STR_RESET_ADD_OUT_STREAMS,
    SCTP_SUPPORTED_CHUNK_EXT,
    USERDATA_MAX_LENGTH,
    DataChunk,
    InitAckChunk,
    InitChunk,
    ReconfigChunk,
    RTCSctpTransport,
    SackChunk,
    ShutdownAckChunk,
    StreamAddOutgoingParam,
    parse_packet,
    serialize_packet,
)

from .test_sctp_bounds import DatagramSink
from .utils import dummy_dtls_transport_pair


class SenderBackpressureTest(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.sctp = RTCSctpTransport(DatagramSink(), limits=SctpLimits())
        self.sctp._remote_port = 5000
        self.sctp._ssthresh = 100000
        self.sctp._rto = 3600
        self.sctp._set_state(RTCSctpTransport.State.ESTABLISHED)
        self.channel = RTCDataChannel(
            self.sctp, RTCDataChannelParameters(negotiated=True, id=42)
        )

    async def asyncTearDown(self):
        await self.sctp.stop()

    async def seed(self, messages):
        permit = await self.sctp.reserve_data_channel(
            self.channel, [len(m) for m in messages]
        )
        permit.send_nowait(messages)
        permit.release()
        await self.sctp._data_channel_flush()
        await asyncio.sleep(0)

    async def test_suspended_retransmit_sack_flush_and_stale_t3_are_serialized(self):
        await self.seed([b"x" * (2 * USERDATA_MAX_LENGTH)])
        last_tsn = self.sctp._sent_queue[-1].tsn
        for chunk in self.sctp._sent_queue:
            chunk._retransmit = True
        self.sctp._flight_size = 0
        entered, release = asyncio.Event(), asyncio.Event()
        active = 0
        maximum_active = 0
        calls = 0

        async def send(data):
            nonlocal active, maximum_active, calls
            active += 1
            maximum_active = max(maximum_active, active)
            calls += 1
            try:
                if calls == 1:
                    entered.set()
                    await release.wait()
            finally:
                active -= 1

        self.sctp.transport._send_data = send
        transmitting = asyncio.create_task(self.sctp._transmit())
        await entered.wait()
        expired = self.sctp._t3_handle
        sack = SackChunk()
        sack.cumulative_tsn = last_tsn
        acknowledging = asyncio.create_task(self.sctp._receive_sack_chunk(sack))
        await asyncio.sleep(0)
        self.channel.send(b"n")
        flushing = asyncio.create_task(self.sctp._data_channel_flush())
        expired.cancel()
        self.sctp._t3_expired()
        await asyncio.sleep(0)
        try:
            self.assertFalse(acknowledging.done())
            self.assertEqual(self.sctp._cwnd, 3 * USERDATA_MAX_LENGTH)
            release.set()
            await asyncio.wait_for(
                asyncio.gather(transmitting, acknowledging, flushing), 2
            )
            await asyncio.sleep(0)
            self.assertEqual(maximum_active, 1)
            self.assertEqual(self.sctp._cwnd, 3 * USERDATA_MAX_LENGTH)
            self.assertEqual(self.sctp._send_bytes, 1)
            self.assertEqual(len(self.sctp._sent_queue), 1)
            self.assertIsNot(self.sctp._t3_handle, expired)
        finally:
            release.set()
            await asyncio.gather(
                transmitting, acknowledging, flushing, return_exceptions=True
            )

    async def test_suspended_init_preserves_peer_establishment_or_close(self):
        for bounded in (True, False):
            for held_index in (0, 1):
                for close in (False, True):
                    with self.subTest(
                        bounded=bounded, held_index=held_index, close=close
                    ):
                        async with dummy_dtls_transport_pair() as dtls:
                            peers = [
                                RTCSctpTransport(
                                    t, limits=SctpLimits() if bounded else None
                                )
                                for t in dtls
                            ]
                            channels = [
                                RTCDataChannel(
                                    t, RTCDataChannelParameters(label="test")
                                )
                                for t in peers
                            ]
                            opened = [asyncio.Event(), asyncio.Event()]
                            for channel, event in zip(channels, opened):
                                channel.on("open", event.set)
                            held, other = peers[held_index], peers[1 - held_index]
                            entered, release = asyncio.Event(), asyncio.Event()
                            progress, late_processed = asyncio.Event(), asyncio.Event()
                            received = [[], []]
                            delivered = [asyncio.Event(), asyncio.Event()]

                            def observe(peer, index):
                                receive = peer._receive_chunk

                                async def receive_chunk(chunk):
                                    await receive(chunk)
                                    if peer is other and isinstance(chunk, InitChunk):
                                        late_processed.set()
                                    progress.set()

                                def datachannel(channel):
                                    def message(data):
                                        received[index].append(data)
                                        delivered[index].set()

                                    channel.on("message", message)

                                peer._receive_chunk = receive_chunk
                                peer.on("datachannel", datachannel)

                            async def drain():
                                while True:
                                    progress.clear()
                                    if all(
                                        not p._data_channel_queue
                                        and not p._outbound_queue
                                        and not p._sent_queue
                                        and p._flight_size == 0
                                        and p._send_bytes
                                        == p._send_chunks
                                        == p._send_messages
                                        == 0
                                        for p in peers
                                    ):
                                        return
                                    await progress.wait()

                            if not close:
                                for index, peer in enumerate(peers):
                                    observe(peer, index)
                            original = held.transport._send_data

                            async def send(data):
                                if not entered.is_set() and any(
                                    isinstance(c, InitChunk)
                                    for c in parse_packet(data)[3]
                                ):
                                    entered.set()
                                    await release.wait()
                                await original(data)

                            held.transport._send_data = send
                            starting = asyncio.create_task(
                                held.start(other.getCapabilities(), other.port)
                            )
                            try:
                                await asyncio.wait_for(entered.wait(), 2)
                                await other.start(held.getCapabilities(), held.port)
                                await asyncio.wait_for(
                                    asyncio.gather(*(e.wait() for e in opened)), 2
                                )
                                for peer, channel in zip(peers, channels):
                                    self.assertEqual(
                                        peer._association_state, peer.State.ESTABLISHED
                                    )
                                    self.assertEqual(
                                        channel.id % 2,
                                        int(peer.transport._role == "server"),
                                    )
                                self.assertIsNone(held._t1_handle)
                                if close:
                                    await held.stop()
                                else:
                                    await asyncio.wait_for(drain(), 2)
                                    for index, peer in enumerate(peers):
                                        self.assertEqual(
                                            peer._last_sacked_tsn,
                                            (peer._local_tsn - 1) % (2**32),
                                        )
                                        self.assertEqual(
                                            peer._last_received_tsn,
                                            (peers[1 - index]._local_tsn - 1) % (2**32),
                                        )
                                    self.assertFalse(late_processed.is_set())
                                release.set()
                                await asyncio.wait_for(starting, 2)
                                self.assertEqual(
                                    held._association_state,
                                    held.State.CLOSED
                                    if close
                                    else held.State.ESTABLISHED,
                                )
                                self.assertIsNone(held._t1_handle)
                                if not close:
                                    await asyncio.wait_for(late_processed.wait(), 2)
                                    for index, channel in enumerate(channels):
                                        channel.send(bytes([index]))
                                    await asyncio.wait_for(
                                        asyncio.gather(*(e.wait() for e in delivered)),
                                        2,
                                    )
                                    self.assertEqual(received, [[b"\x01"], [b"\x00"]])
                                    await asyncio.wait_for(drain(), 2)
                            finally:
                                release.set()
                                await asyncio.gather(starting, return_exceptions=True)
                                await asyncio.gather(*(peer.stop() for peer in peers))
                                self.assertTrue(
                                    all(p._stop_task.done() for p in peers)
                                )
                                self.assertTrue(all(p.state == "closed" for p in peers))

    async def test_init_identity_preserves_exact_duplicate_only(self):
        for bounded in (True, False):
            for change in ("none", "tag", "tsn", "state"):
                with self.subTest(bounded=bounded, change=change):
                    peer = RTCSctpTransport(
                        DatagramSink(), limits=SctpLimits() if bounded else None
                    )
                    peer._remote_port = 5000
                    emitted = []

                    async def send(data):
                        emitted.extend(parse_packet(data)[3])

                    async def receive(chunk):
                        tag = (
                            0
                            if isinstance(chunk, InitChunk)
                            else peer._local_verification_tag
                        )
                        await peer._handle_data(
                            serialize_packet(5000, 5000, tag, chunk)
                        )

                    def bookkeeping():
                        return (
                            peer._last_received_tsn,
                            peer._reconfig_response_seq,
                            peer._remote_verification_tag,
                            peer._remote_initial_tsn,
                            peer._ssthresh,
                            tuple(peer._remote_extensions),
                            peer._remote_partial_reliability,
                            peer._inbound_streams_count,
                            peer._outbound_streams_count,
                        )

                    peer.transport._send_data = send
                    try:
                        self.assertIsNone(peer._remote_initial_tsn)
                        initial = InitChunk()
                        initial.initiate_tag, initial.initial_tsn = 123, 100
                        initial.advertised_rwnd = 4096
                        initial.outbound_streams = initial.inbound_streams = 8
                        initial.params = [
                            (SCTP_SUPPORTED_CHUNK_EXT, b"\xc0"),
                            (SCTP_PRSCTP_SUPPORTED, b""),
                        ]
                        await receive(initial)
                        self.assertEqual(peer._remote_initial_tsn, 100)
                        peer._set_state(peer.State.ESTABLISHED)
                        data = DataChunk(
                            flags=SCTP_DATA_FIRST_FRAG | SCTP_DATA_LAST_FRAG
                        )
                        data.tsn, data.stream_id, data.stream_seq = 100, 42, 0
                        data.protocol, data.user_data = 53, b"x"
                        await receive(data)
                        reconfig = ReconfigChunk()
                        reconfig.params = [
                            (
                                SCTP_STR_RESET_ADD_OUT_STREAMS,
                                bytes(
                                    StreamAddOutgoingParam(
                                        request_sequence=101, new_streams=1
                                    )
                                ),
                            )
                        ]
                        await receive(reconfig)
                        if change == "state":
                            peer._set_state(peer.State.COOKIE_WAIT)
                        before = bookkeeping()
                        incoming = InitChunk()
                        incoming.initiate_tag = 124 if change == "tag" else 123
                        incoming.initial_tsn = 200 if change == "tsn" else 100
                        incoming.advertised_rwnd = 8192
                        incoming.outbound_streams, incoming.inbound_streams = 4, 3
                        incoming.params = [(SCTP_SUPPORTED_CHUNK_EXT, b"\x82")]
                        emitted.clear()
                        await receive(incoming)
                        self.assertEqual(len(emitted), 1)
                        self.assertIsInstance(emitted[0], InitAckChunk)
                        self.assertIsNone(peer._t1_handle)
                        if change == "none":
                            self.assertEqual(bookkeeping(), before)
                            self.assertEqual(emitted[0].outbound_streams, before[-1])
                        else:
                            self.assertEqual(
                                bookkeeping(),
                                (
                                    incoming.initial_tsn - 1,
                                    incoming.initial_tsn - 1,
                                    incoming.initiate_tag,
                                    incoming.initial_tsn,
                                    8192,
                                    (0x82,),
                                    True,
                                    4,
                                    3,
                                ),
                            )
                            self.assertEqual(emitted[0].outbound_streams, 3)
                    finally:
                        await peer.stop()

    async def test_new_t3_expiry_is_not_lost_while_expiry_worker_is_sending(self):
        await self.seed([b"a" * 100, b"b" * 100])
        entered, release = asyncio.Event(), asyncio.Event()
        calls = 0

        async def send(data):
            nonlocal calls
            calls += 1
            if calls == 2:
                entered.set()
                await release.wait()

        self.sctp.transport._send_data = send
        self.sctp._t3_handle.cancel()
        self.sctp._t3_expired()
        try:
            await asyncio.wait_for(entered.wait(), 1)
            self.sctp._t3_handle.cancel()
            self.sctp._t3_expired()
            release.set()
            for _ in range(20):
                if calls >= 4:
                    break
                await asyncio.sleep(0)
            self.assertEqual(
                [chunk._sent_count for chunk in self.sctp._sent_queue], [3, 3]
            )
        finally:
            release.set()

    async def test_close_while_paused_joins_without_resume_and_prevents_late_work(self):
        entered, release = asyncio.Event(), asyncio.Event()
        writes = []

        async def send(data):
            writes.append(len(data))
            entered.set()
            await release.wait()

        self.sctp.transport._send_data = send
        self.channel.send(b"queued")
        await entered.wait()
        stopping = asyncio.create_task(self.sctp.stop())
        try:
            await asyncio.wait_for(asyncio.shield(stopping), 0.2)
            self.assertEqual(self.sctp.state, "closed")
            self.assertEqual(self.sctp._send_bytes, 0)
            count = len(writes)
            release.set()
            await asyncio.sleep(0)
            self.assertEqual(len(writes), count)
            self.assertFalse(self.sctp._service_tasks)
        finally:
            release.set()
            await stopping

    async def test_t1_and_t2_work_capture_chunks_before_timer_fields_are_cleared(self):
        seen = []

        async def send(chunk):
            seen.append(chunk)

        self.sctp._send_chunk = send
        for number, chunk in ((1, InitChunk()), (2, ShutdownAckChunk())):
            getattr(self.sctp, f"_t{number}_start")(chunk)
            getattr(self.sctp, f"_t{number}_expired")()
            getattr(self.sctp, f"_t{number}_cancel")()
            await asyncio.sleep(0)
            self.assertIs(seen[-1], chunk)
