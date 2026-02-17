import time
import struct
from concurrent.futures import ThreadPoolExecutor
from threading import Lock, Condition
import hashlib

# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY

TYPE_DATA = 0
TYPE_ACK = 1
TYPE_FIN = 2

ACK_TIMEOUT = 0.25
GRACE_PERIOD = 2.0
DELAYED_ACK = 0.05

# Header: type(1), seq(4), ack(4), md5(16)
HEADER_FMT = "!BII16s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

MAX_UDP = 1472
MAX_PAYLOAD = MAX_UDP - HEADER_SIZE

NO_ACK = 0xFFFFFFFF 


class Streamer:
    def __init__(self, dst_ip, dst_port, src_ip=INADDR_ANY, src_port=0):
        """Reliable streaming protocol over LossyUDP."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        # Synchronization
        self.lock = Lock()
        self.data_ready = Condition(self.lock)
        self.send_cv = Condition(self.lock)

        # Send Side
        self.send_seq = 0                      # sequence space for DATA + FIN we originate
        self.unacked = {}                      # seq -> [pkt_bytes, last_send_ts]
        self.send_buf = bytearray()            # Nagle buffer for app sends

        # Recieve Side
        self.recv_buffer = {}                  # seq -> payload (out-of-order buffer)
        self.deliver_next = 0                  # next seq to deliver to application
        self.ack_next = 0                      # next missing in-order seq (for cumulative ACK)

        # Connection State
        self.got_fin = False
        self.closed = False

        # Piggyback State
        self.pending_ack = False
        self.last_ack_sent = NO_ACK
        self.rx_since_last_ack = 0
        self.ack_deadline = 0.0

        # Threads
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.executor.submit(self.listener)
        self.executor.submit(self.retransmit_loop)
        self.executor.submit(self.sender_loop)

    # Helpers

    def _mk_pkt(self, ptype: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        header_wo_hash = struct.pack("!BII", ptype, seq, ack)
        digest = hashlib.md5(header_wo_hash + payload).digest()
        return struct.pack(HEADER_FMT, ptype, seq, ack, digest) + payload

    def _parse_pkt(self, packet: bytes):
        if not packet or len(packet) < HEADER_SIZE:
            return None
        ptype, seq, ack, recv_digest = struct.unpack(HEADER_FMT, packet[:HEADER_SIZE])
        payload = packet[HEADER_SIZE:]
        header_wo_hash = struct.pack("!BII", ptype, seq, ack)
        if hashlib.md5(header_wo_hash + payload).digest() != recv_digest:
            return None
        return ptype, seq, ack, payload

    def _cur_ack_locked(self) -> int:
        if self.ack_next == 0:
            return NO_ACK
        return self.ack_next - 1

    def _send_pure_ack_locked(self, ack_seq: int = 0) -> None:
        ackno = self._cur_ack_locked()
        # If nothing new to ack and not forced, skip
        if ackno == self.last_ack_sent and not self.pending_ack and ack_seq == 0:
            return

        pkt = self._mk_pkt(TYPE_ACK, ack_seq, ackno, b"")
        self.last_ack_sent = ackno
        self.pending_ack = False
        self.rx_since_last_ack = 0

        self.socket.sendto(pkt, (self.dst_ip, self.dst_port))

    # Threads
    def listener(self):
        while not self.closed:
            try:
                packet, _addr = self.socket.recvfrom()
                parsed = self._parse_pkt(packet)
                if parsed is None:
                    continue

                ptype, seq, ack, payload = parsed

                with self.lock:
                    if ptype == TYPE_ACK:
                        if seq in self.unacked:
                            del self.unacked[seq]
                            self.send_cv.notify_all()

                    if ack != NO_ACK:
                        to_del = [s for s in self.unacked.keys() if s != seq and s <= ack]
                        for s in to_del:
                            del self.unacked[s]
                        self.send_cv.notify_all()

                if ptype == TYPE_DATA:
                    with self.lock:
                        if seq >= self.deliver_next and seq not in self.recv_buffer:
                            self.recv_buffer[seq] = payload

                        while self.ack_next in self.recv_buffer:
                            self.ack_next += 1

                        self.pending_ack = True
                        self.rx_since_last_ack += 1
                        self.ack_deadline = time.time() + DELAYED_ACK

                        self.data_ready.notify_all()

                        if self.rx_since_last_ack >= 2:
                            self._send_pure_ack_locked()

                elif ptype == TYPE_FIN:
                    with self.lock:
                        self.got_fin = True
                        self.pending_ack = True
                        self.ack_deadline = time.time()
                        self._send_pure_ack_locked(ack_seq=seq)
                        self.data_ready.notify_all()

            except Exception:
                if not self.closed:
                    break

    def sender_loop(self):
        while not self.closed:
            with self.lock:
                while not self.send_buf and not self.closed:
                    self.send_cv.wait(timeout=0.1)

                if self.closed:
                    return

                # Nagle: if there is in-flight data, wait until either:
                # - buffer has a full segment, OR
                # - in-flight clears (ACK arrives), OR
                # - closing
                while (len(self.unacked) > 0 and len(self.send_buf) < MAX_PAYLOAD and not self.closed):
                    self.send_cv.wait(timeout=0.05)

                if self.closed:
                    return

                payload = bytes(self.send_buf[:MAX_PAYLOAD])
                del self.send_buf[:len(payload)]

                seq = self.send_seq
                self.send_seq += 1

                ackno = self._cur_ack_locked()
                pkt = self._mk_pkt(TYPE_DATA, seq, ackno, payload)

                self.unacked[seq] = [pkt, time.time()]

                # If we piggybacked an ACK, clear pending state
                if self.pending_ack and ackno != self.last_ack_sent:
                    self.last_ack_sent = ackno
                    self.pending_ack = False
                    self.rx_since_last_ack = 0

            self.socket.sendto(pkt, (self.dst_ip, self.dst_port))

    def retransmit_loop(self):
        while not self.closed:
            time.sleep(0.02)
            now = time.time()
            to_resend = []

            with self.lock:
                # Delayed ACK timer expiration
                if self.pending_ack and now >= self.ack_deadline:
                    self._send_pure_ack_locked()

                # Retransmit timed-out packets
                for seq, info in list(self.unacked.items()):
                    if now - info[1] > ACK_TIMEOUT:
                        to_resend.append(info[0])
                        info[1] = now

            for pkt in to_resend:
                self.socket.sendto(pkt, (self.dst_ip, self.dst_port))

    def send(self, data_bytes: bytes) -> None:
        with self.lock:
            self.send_buf += data_bytes
            self.send_cv.notify_all()

    def recv(self) -> bytes:
        with self.lock:
            while True:
                if self.deliver_next in self.recv_buffer:
                    res = self.recv_buffer.pop(self.deliver_next)
                    self.deliver_next += 1
                    return res

                if self.got_fin:
                    return b""

                self.data_ready.wait(timeout=0.5)

    def close(self) -> None:
        while True:
            with self.lock:
                empty = (len(self.send_buf) == 0 and len(self.unacked) == 0)
                if empty:
                    break
                self.send_cv.notify_all()
            time.sleep(0.05)

        with self.lock:
            fin_seq = self.send_seq
            self.send_seq += 1

            ackno = self._cur_ack_locked()
            fin_pkt = self._mk_pkt(TYPE_FIN, fin_seq, ackno, b"")
            self.unacked[fin_seq] = [fin_pkt, time.time()]

            # piggybacked ACK clears pending
            if self.pending_ack and ackno != self.last_ack_sent:
                self.last_ack_sent = ackno
                self.pending_ack = False
                self.rx_since_last_ack = 0

        self.socket.sendto(fin_pkt, (self.dst_ip, self.dst_port))

        while True:
            with self.lock:
                if fin_seq not in self.unacked and self.got_fin:
                    break
            time.sleep(0.05)

        time.sleep(GRACE_PERIOD)

        self.closed = True
        self.socket.stoprecv()
        self.executor.shutdown(wait=False)
