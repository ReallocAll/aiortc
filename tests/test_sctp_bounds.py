import asyncio
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase

from aiortc import rtcconfiguration as config
from aiortc.rtcdatachannel import RTCDataChannel, RTCDataChannelParameters
from aiortc.rtcpeerconnection import RTCPeerConnection
from aiortc.rtcsctptransport import (
    SCTP_DATA_FIRST_FRAG,
    SCTP_DATA_LAST_FRAG,
    USERDATA_MAX_LENGTH,
    DataChunk,
    ForwardTsnChunk,
    RTCSctpTransport,
    SackChunk,
    parse_packet,
)
from aiortc.sdp import SessionDescription


class DatagramSink:
    state = "connected"
    _role = "client"
    transport = SimpleNamespace(role="controlling")

    async def _send_data(self, data):
        pass

    def _unregister_data_receiver(self, receiver):
        pass


class SctpBoundsTest(IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        for transport in getattr(self, "transports", []):
            await transport.stop()

    def transport(self, *, bounded=True, **limits):
        transport = RTCSctpTransport(
            DatagramSink(), limits=config.SctpLimits(**limits) if bounded else None
        )
        transport._remote_port = 5000
        transport._ssthresh = 100000
        transport._last_received_tsn = 0
        transport._set_state(RTCSctpTransport.State.ESTABLISHED)
        if not hasattr(self, "transports"):
            self.transports = []
        self.transports.append(transport)
        return transport

    def channel(self, transport):
        return RTCDataChannel(
            transport, RTCDataChannelParameters(negotiated=True, id=42)
        )

    @staticmethod
    def chunk(tsn, stream=42, data=b"x", flags=SCTP_DATA_FIRST_FRAG, seq=0):
        chunk = DataChunk(flags=flags)
        chunk.tsn = tsn
        chunk.stream_id = stream
        chunk.stream_seq = seq
        chunk.protocol = 53
        chunk.user_data = data
        return chunk

    async def retransmit_fixture(self, *, bounded=True, first=1, max_retransmits=None):
        transport = self.transport(
            bounded=bounded,
            send_bytes=13 * USERDATA_MAX_LENGTH,
            send_chunks=13,
            send_messages=1,
        )
        transport._local_tsn = first
        transport._last_sacked_tsn = (first - 1) % (2**32)
        transport._cwnd = 13 * USERDATA_MAX_LENGTH
        transport._rto = 3600
        emitted = []

        async def send(data):
            emitted.extend(parse_packet(data)[3])

        transport.transport._send_data = send
        await transport._send(
            42,
            53,
            b"x" * (13 * USERDATA_MAX_LENGTH),
            max_retransmits=max_retransmits,
        )
        while transport._outbound_queue:
            await transport._transmit()
        return transport, emitted

    async def gap_report(self, transport, first, start, end):
        sack = SackChunk()
        sack.cumulative_tsn = (first - 1) % (2**32)
        sack.gaps = [(start, end)]
        await transport._receive_chunk(sack)

    @staticmethod
    def data_tsns(emitted):
        return [chunk.tsn for chunk in emitted if isinstance(chunk, DataChunk)]

    async def expire_t3(self, transport):
        transport._t3_handle.cancel()
        transport._t3_expired()
        name = "timer3" if transport._uses_backpressure else "transmit"
        await asyncio.wait_for(transport._service_tasks[name], 1)

    async def test_remote_size_checks_encoded_data_and_default(self):
        for bounded in (True, False):
            with self.subTest(bounded=bounded):
                transport = self.transport(bounded=bounded)
                channel = self.channel(transport)
                self.assertEqual(transport._remote_max_message_size, 65536)
                with self.assertRaises(ValueError):
                    transport._data_channel_encode(b"x" * 65537)
                with self.assertRaises(ValueError):
                    transport.reserve_data_channel_nowait(channel, [65537])
                transport._remote_max_message_size = 2
                self.assertEqual(transport._data_channel_encode("é"), (51, b"\xc3\xa9"))
                self.assertEqual(transport._data_channel_encode(b"ab"), (53, b"ab"))
                with self.assertRaises(ValueError):
                    channel.send("€")
                self.assertEqual(channel.bufferedAmount, 0)
                self.assertFalse(transport._data_channel_queue)
                self.assertFalse(transport._send_credits)
                transport._remote_max_message_size = 1
                self.assertEqual(transport._data_channel_encode(""), (56, b"\x00"))
                self.assertEqual(transport._data_channel_encode(b""), (57, b"\x00"))
                transport._remote_max_message_size = 0
                self.assertEqual(
                    len(transport._data_channel_encode(b"x" * 65537)[1]), 65537
                )
                transport.reserve_data_channel_nowait(channel, [65537]).release()
                if bounded:
                    local = self.transport(max_message_size=2)
                    local._remote_max_message_size = 0
                    with self.assertRaises(ValueError):
                        self.channel(local).send(b"abc")
                    self.assertFalse(local._send_credits)

    async def test_remote_size_rejects_reservations_before_admission(self):
        for bounded in (True, False):
            with self.subTest(bounded=bounded):
                transport = self.transport(bounded=bounded, send_bytes=8)
                channel = self.channel(transport)
                transport._remote_max_message_size = 2
                with self.assertRaises(ValueError):
                    await transport.reserve_data_channel(channel, [1, 3])
                with self.assertRaises(ValueError):
                    transport.reserve_data_channel_nowait(channel, [1, 3])
                self.assertEqual(
                    (
                        transport._send_bytes,
                        transport._send_chunks,
                        transport._send_messages,
                    ),
                    (0, 0, 0),
                )
                self.assertFalse(transport._send_waiters)
                self.assertFalse(transport._send_reservations)
                self.assertFalse(transport._send_credits)
                self.assertFalse(transport._data_channel_queue)
                self.assertEqual(channel.bufferedAmount, 0)

    async def test_remote_size_commit_failure_keeps_permit_releasable(self):
        for bounded in (True, False):
            with self.subTest(bounded=bounded):
                transport = self.transport(bounded=bounded)
                channel = self.channel(transport)
                transport._remote_max_message_size = 3
                permit = await transport.reserve_data_channel(channel, [3, 3])
                transport._remote_max_message_size = 2
                with self.assertRaises(ValueError):
                    permit.send_nowait([b"a", "€"])
                self.assertTrue(permit._active)
                self.assertIn(permit, transport._send_reservations)
                self.assertEqual(
                    (
                        transport._send_bytes,
                        transport._send_chunks,
                        transport._send_messages,
                    ),
                    (6, 2, 2),
                )
                self.assertFalse(transport._data_channel_queue)
                self.assertFalse(transport._outbound_queue)
                self.assertFalse(transport._sent_queue)
                self.assertFalse(transport._send_credits)
                self.assertEqual(channel.bufferedAmount, 0)
                permit.release()
                self.assertEqual(transport._send_bytes, 0)
                self.assertFalse(transport._send_reservations)

    async def test_sdp_advertises_instance_receive_limit(self):
        for limits in (
            None,
            config.SctpLimits(),
            config.SctpLimits(max_message_size=33555456),
        ):
            with self.subTest(limits=limits):
                peer = RTCPeerConnection(
                    config.RTCConfiguration(iceServers=[], sctpLimits=limits)
                )
                try:
                    peer.createDataChannel("test")
                    offer = await peer.createOffer()
                    capability = (
                        SessionDescription.parse(offer.sdp).media[0].sctpCapabilities
                    )
                    self.assertEqual(
                        capability.maxMessageSize,
                        limits.max_message_size if limits else 262144,
                    )
                    self.assertEqual(
                        RTCSctpTransport.getCapabilities().maxMessageSize, 262144
                    )
                finally:
                    await peer.close()

    async def test_fast_retransmit_once_emits_data_and_preserves_t3_and_credit(self):
        for bounded in (True, False):
            for first in (1, 0xFFFFFFFC):
                with self.subTest(bounded=bounded, first=first):
                    transport, emitted = await self.retransmit_fixture(
                        bounded=bounded, first=first
                    )
                    initial = [(first + index) % (2**32) for index in range(13)]
                    retained = list(transport._sent_queue)
                    for end in range(2, 11):
                        await self.gap_report(transport, first, 2, end)
                    actual = self.data_tsns(emitted)
                    self.assertEqual(actual, initial + [first])
                    self.assertEqual(transport._flight_size, 4 * USERDATA_MAX_LENGTH)
                    if bounded:
                        self.assertEqual(
                            (
                                transport._send_bytes,
                                transport._send_chunks,
                                transport._send_messages,
                            ),
                            (13 * USERDATA_MAX_LENGTH, 13, 1),
                        )
                        channel = self.channel(transport)
                        with self.assertRaises(BufferError):
                            transport.reserve_data_channel_nowait(channel, [1])
                    await self.expire_t3(transport)
                    actual = self.data_tsns(emitted)
                    self.assertEqual(actual, initial + [first, first])
                    self.assertTrue(retained[0]._fast_retransmitted)
                    sack = SackChunk()
                    sack.cumulative_tsn = initial[-1]
                    await transport._receive_chunk(sack)
                    self.assertEqual(transport._flight_size, 0)
                    self.assertEqual(list(transport._sent_queue), [])
                    self.assertIsNone(transport._t3_handle)
                    self.assertIsNone(transport._fast_recovery_exit)
                    if bounded:
                        self.assertEqual(
                            (
                                transport._send_bytes,
                                transport._send_chunks,
                                transport._send_messages,
                            ),
                            (0, 0, 0),
                        )
                        self.assertTrue(
                            all(chunk.user_data == b"" for chunk in retained)
                        )
                        transport.reserve_data_channel_nowait(
                            channel, [13 * USERDATA_MAX_LENGTH]
                        ).release()

    async def test_fast_retransmit_once_preserves_deferred_hole_flight_accounting(self):
        for bounded in (True, False):
            with self.subTest(bounded=bounded):
                transport, emitted = await self.retransmit_fixture(bounded=bounded)
                for end in range(3, 6):
                    await self.gap_report(transport, 1, 3, end)
                self.assertEqual(self.data_tsns(emitted), list(range(1, 14)) + [1])
                self.assertTrue(transport._sent_queue[1]._retransmit)
                self.assertEqual(transport._sent_queue[1]._sent_count, 1)
                for end in range(6, 9):
                    await self.gap_report(transport, 1, 3, end)
                actual = self.data_tsns(emitted)
                self.assertEqual(actual, list(range(1, 14)) + [1, 2])
                self.assertEqual(transport._flight_size, 7 * USERDATA_MAX_LENGTH)

    async def test_fast_retransmit_once_is_consumed_before_block_close_or_cancel(self):
        for action in ("resume", "close", "cancel"):
            with self.subTest(action=action):
                transport, emitted = await self.retransmit_fixture()
                retained = list(transport._sent_queue)
                for end in (3, 4):
                    await self.gap_report(transport, 1, 3, end)
                entered, release = asyncio.Event(), asyncio.Event()
                original = transport.transport._send_data

                async def send(data):
                    await original(data)
                    if any(
                        isinstance(chunk, DataChunk) for chunk in parse_packet(data)[3]
                    ):
                        entered.set()
                        await release.wait()

                transport.transport._send_data = send
                receiving = asyncio.create_task(self.gap_report(transport, 1, 3, 5))
                try:
                    await asyncio.wait_for(entered.wait(), 1)
                    self.assertTrue(
                        all(chunk._fast_retransmitted for chunk in retained[:2])
                    )
                    self.assertTrue(retained[1]._retransmit)
                    self.assertEqual(retained[1]._sent_count, 1)
                    if action == "close":
                        await asyncio.wait_for(transport.stop(), 1)
                    elif action == "cancel":
                        receiving.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await receiving
                    release.set()
                    if action != "cancel":
                        await asyncio.wait_for(receiving, 1)
                    if action == "resume":
                        for end in range(6, 9):
                            await self.gap_report(transport, 1, 3, end)
                        self.assertEqual(
                            self.data_tsns(emitted), list(range(1, 14)) + [1, 2]
                        )
                    else:
                        await transport.stop()
                        await transport._transmit()
                        transport._t3_expired()
                        self.assertEqual(
                            self.data_tsns(emitted), list(range(1, 14)) + [1]
                        )
                        self.assertEqual(
                            (
                                transport._send_bytes,
                                transport._send_chunks,
                                transport._send_messages,
                            ),
                            (0, 0, 0),
                        )
                        self.assertFalse(transport._send_credits)
                finally:
                    release.set()
                    receiving.cancel()
                    await asyncio.gather(receiving, return_exceptions=True)

    async def test_fast_retransmit_once_defers_partial_reliability_abandonment_to_t3(
        self,
    ):
        for bounded in (True, False):
            with self.subTest(bounded=bounded):
                transport, emitted = await self.retransmit_fixture(
                    bounded=bounded, max_retransmits=1
                )
                for end in range(2, 11):
                    await self.gap_report(transport, 1, 2, end)
                self.assertEqual(self.data_tsns(emitted), list(range(1, 14)) + [1])
                self.assertFalse(
                    any(isinstance(chunk, ForwardTsnChunk) for chunk in emitted)
                )
                self.assertEqual(len(transport._sent_queue), 13)
                await self.expire_t3(transport)
                self.assertEqual(self.data_tsns(emitted), list(range(1, 14)) + [1])
                self.assertEqual(
                    [
                        chunk.cumulative_tsn
                        for chunk in emitted
                        if isinstance(chunk, ForwardTsnChunk)
                    ],
                    [13],
                )
                self.assertFalse(transport._sent_queue)
                self.assertFalse(transport._send_credits)

    def receive_queue(self, transport, maxsize=256):
        queue = asyncio.Queue(maxsize=maxsize)
        sizes = []
        channel = self.channel(transport)

        @channel.on("message")
        def receive(data):
            try:
                queue.put_nowait(data)
                sizes.append(queue.qsize())
            except asyncio.QueueFull:
                transport._fail(ConnectionError("Application receive queue full"))

        return queue, sizes

    async def prepare_delivery_burst(self, transport, mode, count=258):
        first_seq = 1 if mode == "forward" else 0
        chunks = [
            self.chunk(
                index + first_seq + 1,
                data=index.to_bytes(2, "big"),
                flags=SCTP_DATA_FIRST_FRAG | SCTP_DATA_LAST_FRAG,
                seq=index + first_seq,
            )
            for index in range(count)
        ]
        if mode != "in_order":
            for chunk in chunks[1:] if mode == "gap" else chunks:
                await transport._receive_data_chunk(chunk)

        async def release():
            if mode == "forward":
                forward = ForwardTsnChunk()
                forward.cumulative_tsn = 1
                forward.streams = [(42, 0)]
                await transport._receive_forward_tsn_chunk(forward)
            else:
                for chunk in chunks if mode == "in_order" else chunks[:1]:
                    await transport._receive_data_chunk(chunk)

        return chunks, release

    async def test_delivery_bursts_yield_to_waiting_consumer(self):
        for mode in ("gap", "in_order", "forward"):
            with self.subTest(mode=mode):
                transport = self.transport()
                queue, sizes = self.receive_queue(transport)
                window = transport._advertised_rwnd
                chunks, release = await self.prepare_delivery_burst(transport, mode)
                stream = transport._get_inbound_stream(42)
                self.assertTrue(queue.empty())
                received = []

                async def consume():
                    for _ in range(258):
                        received.append(await queue.get())

                consumer = asyncio.create_task(consume())
                await asyncio.sleep(0)
                try:
                    self.assertFalse(consumer.done())
                    await release()
                    self.assertIsNone(transport._failure)
                    await asyncio.wait_for(consumer, 1)
                    self.assertEqual(
                        received, [index.to_bytes(2, "big") for index in range(258)]
                    )
                    self.assertTrue(queue.empty())
                    self.assertLessEqual(max(sizes), 256)
                    self.assertEqual(transport.state, "connected")
                    self.assertEqual(transport._last_received_tsn, chunks[-1].tsn)
                    self.assertEqual(transport._sack_misordered, set())
                    self.assertEqual(transport._sack_duplicates, [])
                    self.assertEqual(transport._advertised_rwnd, window)
                    self.assertEqual(
                        stream.sequence_number, 259 if mode == "forward" else 258
                    )
                    self.assertEqual(stream.reassembly, [])
                    self.assertEqual(
                        (transport._inbound_bytes, transport._inbound_chunks), (0, 0)
                    )
                    self.assertEqual(transport._active_inbound_streams, set())
                    self.assertTrue(all(chunk.user_data == b"" for chunk in chunks))
                finally:
                    consumer.cancel()
                    await asyncio.gather(consumer, return_exceptions=True)

    async def test_stalled_consumer_still_closes_at_queue_capacity(self):
        transport = self.transport()
        queue, sizes = self.receive_queue(transport)
        _, release = await self.prepare_delivery_burst(transport, "gap")
        await release()
        self.assertEqual(transport.state, "closed")
        self.assertIsInstance(transport._failure, ConnectionError)
        self.assertEqual(max(sizes), 256)
        self.assertEqual(
            [queue.get_nowait() for _ in range(256)],
            [index.to_bytes(2, "big") for index in range(256)],
        )
        self.assertTrue(queue.empty())
        self.assertEqual((transport._inbound_bytes, transport._inbound_chunks), (0, 0))
        self.assertEqual(transport._active_inbound_streams, set())
        self.assertEqual(transport._inbound_streams, {})

    async def test_close_and_cancel_at_delivery_yield_stop_the_burst(self):
        for mode in ("gap", "forward"):
            for action in ("close", "cancel"):
                with self.subTest(mode=mode, action=action):
                    transport = self.transport()
                    channel = self.channel(transport)
                    received = []
                    first = asyncio.Event()

                    @channel.on("message")
                    def receive(data):
                        received.append(data)
                        first.set()

                    _, release = await self.prepare_delivery_burst(
                        transport, mode, count=3
                    )

                    async def interrupt():
                        await first.wait()
                        if action == "cancel":
                            receiving.cancel()
                        else:
                            await transport.stop()

                    interruption = asyncio.create_task(interrupt())
                    await asyncio.sleep(0)
                    receiving = asyncio.create_task(release())
                    try:
                        if action == "cancel":
                            with self.assertRaises(asyncio.CancelledError):
                                await receiving
                            self.assertEqual(
                                (transport._inbound_bytes, transport._inbound_chunks),
                                (4, 2),
                            )
                            self.assertEqual(transport._active_inbound_streams, {42})
                        else:
                            await receiving
                        await asyncio.wait_for(interruption, 1)
                        self.assertEqual(received, [b"\x00\x00"])
                    finally:
                        receiving.cancel()
                        interruption.cancel()
                        await asyncio.gather(
                            receiving, interruption, return_exceptions=True
                        )
                        await transport.stop()
                    self.assertEqual(channel.readyState, "closed")
                    self.assertEqual(transport.state, "closed")
                    self.assertIsNone(transport._failure)
                    self.assertEqual(
                        (transport._inbound_bytes, transport._inbound_chunks), (0, 0)
                    )
                    self.assertEqual(transport._active_inbound_streams, set())
                    self.assertEqual(transport._inbound_streams, {})
                    self.assertEqual(transport._service_tasks, {})

    async def test_unbounded_delivery_keeps_immediate_upstream_scheduling(self):
        transport = self.transport(bounded=False)
        queue, sizes = self.receive_queue(transport, maxsize=0)
        window = transport._advertised_rwnd
        _, release = await self.prepare_delivery_burst(transport, "gap")
        received = []

        async def consume():
            for _ in range(258):
                received.append(await queue.get())

        consumer = asyncio.create_task(consume())
        await asyncio.sleep(0)
        try:
            await release()
            self.assertEqual(received, [])
            self.assertEqual(queue.qsize(), 258)
            self.assertEqual(max(sizes), 258)
            self.assertEqual(transport._advertised_rwnd, window)
            await asyncio.wait_for(consumer, 1)
            self.assertEqual(
                received, [index.to_bytes(2, "big") for index in range(258)]
            )
            self.assertTrue(queue.empty())
        finally:
            consumer.cancel()
            await asyncio.gather(consumer, return_exceptions=True)

    async def test_gap_ack_retains_payload_until_cumulative_removal(self):
        size = 2 * USERDATA_MAX_LENGTH
        transport = self.transport(send_bytes=size, send_chunks=2, send_messages=1)
        channel = self.channel(transport)
        permit = await transport.reserve_data_channel(channel, [size])
        permit.send_nowait([b"x" * size])
        permit.release()
        await transport._data_channel_flush()
        self.assertEqual(channel.bufferedAmount, 0)
        first, last = [chunk.tsn for chunk in transport._sent_queue]
        gap = SackChunk()
        gap.cumulative_tsn = (first - 1) % (2**32)
        gap.gaps = [(1, 2)]
        await transport._receive_sack_chunk(gap)
        self.assertEqual(transport._flight_size, 0)
        waiting = asyncio.create_task(transport.reserve_data_channel(channel, [1]))
        await asyncio.sleep(0)
        self.assertFalse(waiting.done())
        cumulative = SackChunk()
        cumulative.cumulative_tsn = last
        await transport._receive_sack_chunk(cumulative)
        (await asyncio.wait_for(waiting, 1)).release()

    async def test_cancel_before_and_after_capacity_grant_refunds_once(self):
        transport = self.transport(send_bytes=4, send_chunks=1, send_messages=1)
        channel = self.channel(transport)
        for after_grant in (False, True):
            held = await transport.reserve_data_channel(channel, [4])
            waiting = asyncio.create_task(transport.reserve_data_channel(channel, [4]))
            await asyncio.sleep(0)
            if after_grant:
                held.release()
            waiting.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiting
            held.release()
            held.release()
            (
                await asyncio.wait_for(transport.reserve_data_channel(channel, [4]), 1)
            ).release()

    async def test_impossible_and_excess_waiters_reject_without_waiting(self):
        transport = self.transport(
            send_bytes=4, send_chunks=1, send_messages=1, send_waiters=1
        )
        channel = self.channel(transport)
        with self.assertRaises(ValueError):
            await transport.reserve_data_channel(channel, [5])
        held = await transport.reserve_data_channel(channel, [4])
        waiting = asyncio.create_task(transport.reserve_data_channel(channel, [4]))
        await asyncio.sleep(0)
        with self.assertRaises(BufferError):
            await transport.reserve_data_channel(channel, [1])
        waiting.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiting
        held.release()

    async def test_whole_commit_validation_precedes_any_enqueue(self):
        transport = self.transport()
        channel = self.channel(transport)
        held = await transport.reserve_data_channel(channel, [2, 2])
        with self.assertRaises(ValueError):
            held.send_nowait([b"ok", b"oversize"])
        self.assertEqual(channel.bufferedAmount, 0)
        self.assertEqual(len(transport._data_channel_queue), 0)
        held.release()

    async def test_nowait_admission_rejection_does_not_mutate_credit_or_waiters(self):
        transport = self.transport(send_bytes=4, send_chunks=1, send_messages=1)
        channel = self.channel(transport)
        held = await transport.reserve_data_channel(channel, [4])
        with self.assertRaises(BufferError):
            transport.reserve_data_channel_nowait(channel, [1])
        self.assertEqual(
            (transport._send_bytes, transport._send_chunks, transport._send_messages),
            (4, 1, 1),
        )
        self.assertEqual(len(transport._send_waiters), 0)
        self.assertEqual(channel.bufferedAmount, 0)
        held.release()
        transport.reserve_data_channel_nowait(channel, [4]).release()

    async def test_zero_byte_reservation_only_accepts_empty_application_data(self):
        transport = self.transport()
        channel = self.channel(transport)
        held = await transport.reserve_data_channel(channel, [0])
        with self.assertRaises(ValueError):
            held.send_nowait([b"x"])
        self.assertEqual(channel.bufferedAmount, 0)
        held.send_nowait([b""])
        held.release()

    async def test_ordinary_empty_messages_use_entry_and_payload_credit(self):
        transport = self.transport(send_bytes=10, send_chunks=10, send_messages=1)
        channel = self.channel(transport)
        channel.send(b"")
        with self.assertRaises(BufferError):
            channel.send(b"")
        self.assertEqual(channel.bufferedAmount, 1)

    async def test_close_invalidates_unused_permits_and_wakes_waiters(self):
        transport = self.transport(send_bytes=4, send_chunks=1, send_messages=1)
        channel = self.channel(transport)
        held = await transport.reserve_data_channel(channel, [4])
        waiting = asyncio.create_task(transport.reserve_data_channel(channel, [1]))
        await asyncio.sleep(0)
        await transport.stop()
        with self.assertRaises(ConnectionError):
            await asyncio.wait_for(waiting, 1)
        with self.assertRaises(ConnectionError):
            held.send_nowait([b"x"])
        held.release()

    async def test_inbound_bytes_reject_before_acknowledging_overflow(self):
        transport = self.transport(receive_bytes=4)
        await transport._receive_data_chunk(self.chunk(1, data=b"1234"))
        with self.assertRaises(ConnectionError):
            await transport._receive_data_chunk(self.chunk(2, data=b"5"))
        self.assertEqual(transport._last_received_tsn, 1)
        self.assertEqual(transport.state, "closed")

    async def test_missing_fragments_and_zero_payloads_obey_entry_cap(self):
        transport = self.transport(receive_entries=2)
        await transport._receive_data_chunk(self.chunk(2, data=b""))
        with self.assertRaises(ConnectionError):
            await transport._receive_data_chunk(self.chunk(4, data=b""))
        self.assertEqual(transport.state, "closed")

    async def test_duplicate_tsn_bookkeeping_obeys_entry_cap(self):
        transport = self.transport(receive_entries=2)
        await transport._receive_data_chunk(self.chunk(0, data=b""))
        await transport._receive_data_chunk(self.chunk(0, data=b""))
        with self.assertRaises(ConnectionError):
            await transport._receive_data_chunk(self.chunk(0, data=b""))

    async def test_active_stream_cap_preserves_high_stream_ids(self):
        transport = self.transport(active_streams=2)
        await transport._receive_data_chunk(self.chunk(1, stream=42))
        await transport._receive_data_chunk(self.chunk(2, stream=4242))
        with self.assertRaises(ConnectionError):
            await transport._receive_data_chunk(self.chunk(3, stream=60000))

    async def test_assembled_message_limit_applies_before_delivery(self):
        transport = self.transport(max_message_size=4)
        delivered = []

        async def receive(*message):
            delivered.append(message)

        transport._receive = receive
        await transport._receive_data_chunk(self.chunk(1, data=b"123"))
        with self.assertRaises(ConnectionError):
            await transport._receive_data_chunk(
                self.chunk(2, data=b"45", flags=SCTP_DATA_LAST_FRAG)
            )
        self.assertEqual(delivered, [])

    async def test_completed_stream_releases_active_and_payload_capacity(self):
        transport = self.transport(active_streams=1, receive_bytes=4, receive_entries=4)
        delivered = []

        async def receive(*message):
            delivered.append(message)

        transport._receive = receive
        for tsn, stream in ((1, 42), (2, 4242)):
            await transport._receive_data_chunk(
                self.chunk(tsn, stream, b"1234", flags=3)
            )
        self.assertEqual(delivered, [(42, 53, b"1234"), (4242, 53, b"1234")])

    async def test_gap_fill_delivers_two_messages_with_independent_size_limits(self):
        transport = self.transport(
            max_message_size=4, receive_bytes=9, receive_entries=8
        )
        delivered = []

        async def receive(*message):
            delivered.append(message)

        transport._receive = receive
        chunks = [
            self.chunk(1, data=b"ab", seq=0),
            self.chunk(2, data=b"cd", flags=SCTP_DATA_LAST_FRAG, seq=0),
            self.chunk(3, data=b"ef", seq=1),
            self.chunk(4, data=b"gh", flags=SCTP_DATA_LAST_FRAG, seq=1),
        ]
        stream = transport._get_inbound_stream(42)
        for index in (0, 2, 3):
            await transport._receive_data_chunk(chunks[index])
            self.assertEqual(delivered, [])
        await transport._receive_data_chunk(chunks[1])
        self.assertEqual(delivered, [(42, 53, b"abcd"), (42, 53, b"efgh")])
        self.assertEqual(transport.state, "connected")
        self.assertIsNone(transport._failure)
        self.assertEqual(stream.sequence_number, 2)
        self.assertEqual(stream.reassembly, [])
        self.assertEqual((transport._inbound_bytes, transport._inbound_chunks), (0, 0))
        self.assertEqual(transport._active_inbound_streams, set())
        self.assertEqual([chunk.user_data for chunk in chunks], [b""] * 4)

    async def test_gap_fill_retains_only_the_incomplete_successor_charge(self):
        transport = self.transport(
            max_message_size=4, receive_bytes=9, receive_entries=8
        )
        delivered = []

        async def receive(*message):
            delivered.append(message)

        transport._receive = receive
        first = self.chunk(1, data=b"ab", seq=0)
        last = self.chunk(2, data=b"cd", flags=SCTP_DATA_LAST_FRAG, seq=0)
        successor = self.chunk(3, data=b"ef", seq=1)
        stream = transport._get_inbound_stream(42)
        for chunk in (first, successor):
            await transport._receive_data_chunk(chunk)
            self.assertEqual(delivered, [])
        await transport._receive_data_chunk(last)
        self.assertEqual(delivered, [(42, 53, b"abcd")])
        self.assertEqual(transport.state, "connected")
        self.assertIsNone(transport._failure)
        self.assertEqual(stream.sequence_number, 1)
        self.assertEqual(stream.reassembly, [successor])
        self.assertEqual(successor.user_data, b"ef")
        self.assertEqual((transport._inbound_bytes, transport._inbound_chunks), (2, 1))
        self.assertEqual(transport._active_inbound_streams, {42})
        self.assertEqual((first.user_data, last.user_data), (b"", b""))
        await transport._receive_data_chunk(
            self.chunk(4, data=b"gh", flags=SCTP_DATA_LAST_FRAG, seq=1)
        )
        self.assertEqual(delivered, [(42, 53, b"abcd"), (42, 53, b"efgh")])
        self.assertEqual(stream.sequence_number, 2)
        self.assertEqual(stream.reassembly, [])
        self.assertEqual((transport._inbound_bytes, transport._inbound_chunks), (0, 0))
        self.assertEqual(transport._active_inbound_streams, set())

    async def test_gap_fill_still_rejects_a_truly_oversized_successor(self):
        transport = self.transport(
            max_message_size=4, receive_bytes=9, receive_entries=8
        )
        delivered = []

        async def receive(*message):
            delivered.append(message)

        transport._receive = receive
        for chunk in (
            self.chunk(1, data=b"ab", seq=0),
            self.chunk(3, data=b"ef", seq=1),
            self.chunk(4, data=b"ghi", flags=SCTP_DATA_LAST_FRAG, seq=1),
        ):
            await transport._receive_data_chunk(chunk)
            self.assertEqual(delivered, [])
        with self.assertRaisesRegex(
            ConnectionError, "SCTP assembled message limit exceeded"
        ) as caught:
            await transport._receive_data_chunk(
                self.chunk(2, data=b"cd", flags=SCTP_DATA_LAST_FRAG, seq=0)
            )
        self.assertEqual(delivered, [(42, 53, b"abcd")])
        self.assertIs(transport._failure, caught.exception)
        self.assertEqual(transport.state, "closed")
        self.assertEqual((transport._inbound_bytes, transport._inbound_chunks), (0, 0))
        self.assertEqual(transport._active_inbound_streams, set())
        self.assertEqual(transport._inbound_streams, {})

    async def test_conservative_reservation_refunds_unused_shape_at_commit(self):
        transport = self.transport(send_bytes=8, send_chunks=3, send_messages=3)
        channel = self.channel(transport)
        held = await transport.reserve_data_channel(channel, [4, 4])
        held.send_nowait([b"x"])
        held.release()
        self.assertEqual(
            (transport._send_bytes, transport._send_chunks, transport._send_messages),
            (1, 1, 1),
        )
        transport.reserve_data_channel_nowait(channel, [7]).release()

    async def test_abandoned_chunks_release_only_when_removed(self):
        size = 2 * USERDATA_MAX_LENGTH
        transport = self.transport(send_bytes=size, send_chunks=2, send_messages=1)
        channel = RTCDataChannel(
            transport,
            RTCDataChannelParameters(negotiated=True, id=42, maxRetransmits=0),
        )
        held = await transport.reserve_data_channel(channel, [size])
        held.send_nowait([b"x" * size])
        await transport._data_channel_flush()
        self.assertTrue(transport._maybe_abandon(transport._sent_queue[0]))
        with self.assertRaises(BufferError):
            transport.reserve_data_channel_nowait(channel, [1])
        transport._update_advanced_peer_ack_point()
        transport.reserve_data_channel_nowait(channel, [size]).release()

    async def test_send_worker_failure_closes_association_and_wakes_capacity(self):
        transport = self.transport(send_bytes=4, send_chunks=1, send_messages=1)
        channel = self.channel(transport)

        async def fail(data):
            raise OSError("datagram write failed")

        transport.transport._send_data = fail
        held = await transport.reserve_data_channel(channel, [4])
        held.send_nowait([b"1234"])
        with self.assertRaises(ConnectionError):
            await asyncio.wait_for(transport.reserve_data_channel(channel, [1]), 1)
        self.assertEqual(transport.state, "closed")
        self.assertEqual(transport._send_bytes, 0)

    async def test_predicted_chunk_budget_rejects_impossible_reservation(self):
        transport = self.transport(send_bytes=10000, send_chunks=2)
        with self.assertRaises(ValueError):
            await transport.reserve_data_channel(self.channel(transport), [2401])
