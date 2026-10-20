import asyncio
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from aiortc import RTCConfiguration, RTCPeerConnection
from aiortc.rtcdtlstransport import RTCCertificate, RTCDtlsTransport, State

from .utils import dummy_ice_transport_pair


class JoinedLifetimeTest(IsolatedAsyncioTestCase):
    async def test_bounded_dtls_stop_attempts_notify_without_waiting_for_udp_resume(
        self,
    ):
        ice, _ = dummy_ice_transport_pair()
        ice._has_write_limits = True
        dtls = RTCDtlsTransport(ice, [RTCCertificate.generateCertificate()])
        release = asyncio.Event()
        joined = asyncio.Event()
        attempted = []

        class SSL:
            def shutdown(self):
                attempted.append("shutdown")

        async def write():
            attempted.append("write")
            await release.wait()

        async def reader():
            try:
                await asyncio.Event().wait()
            finally:
                joined.set()

        dtls._ssl = SSL()
        dtls._state = State.CONNECTED
        dtls._write_ssl = write
        dtls._task = asyncio.create_task(reader())
        await asyncio.sleep(0)
        stopping = asyncio.create_task(dtls.stop())
        try:
            await asyncio.wait_for(asyncio.shield(stopping), 0.2)
            self.assertEqual(attempted, ["shutdown", "write"])
            self.assertTrue(joined.is_set())
        finally:
            release.set()
            await stopping

    async def test_dtls_stop_joins_reader_cancellation(self):
        ice, _ = dummy_ice_transport_pair()
        dtls = RTCDtlsTransport(ice, [RTCCertificate.generateCertificate()])
        cancelling = asyncio.Event()
        release = asyncio.Event()

        async def reader():
            try:
                await asyncio.Event().wait()
            finally:
                cancelling.set()
                await release.wait()

        task = asyncio.create_task(reader())
        dtls._task = task
        await asyncio.sleep(0)
        stopping = asyncio.create_task(dtls.stop())
        try:
            await asyncio.wait_for(cancelling.wait(), 1)
            self.assertFalse(stopping.done())
        finally:
            release.set()
            await stopping
            await asyncio.gather(task, return_exceptions=True)
        self.assertTrue(task.done())

    async def test_peer_close_cancels_and_joins_scheduled_connect(self):
        pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
        pc.createDataChannel("test")
        entered = asyncio.Event()
        cancelling = asyncio.Event()
        release = asyncio.Event()
        tasks = []

        async def connect():
            tasks.append(asyncio.current_task())
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelling.set()
                await release.wait()

        closing = None
        try:
            with patch.object(pc, "_RTCPeerConnection__connect", side_effect=connect):
                await pc.setLocalDescription(await pc.createOffer())
                await asyncio.wait_for(entered.wait(), 1)
                closing = asyncio.create_task(pc.close())
                await asyncio.wait_for(cancelling.wait(), 1)
                self.assertFalse(closing.done())
        finally:
            release.set()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if closing is not None:
                await closing
            await pc.close()
