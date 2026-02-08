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

HEADER_FMT = '!BI16s'  # 1 byte type, 4 bytes seq number, 16 bytes hash of payload
HEADER_SIZE = struct.calcsize(HEADER_FMT)
MAX_UDP = 1472  # maximum UDP payload size for LossyUDP
MAX_PAYLOAD = MAX_UDP - HEADER_SIZE


class Streamer:
    def __init__(self, dst_ip, dst_port,
                 src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        self.send_seq = 0
        self.expected_seq = 0
        self.recv_buffer = {}

        self.closed = False
        self.lock = Lock()
        self.data_ready = Condition(self.lock)
        
        self.last_acked = -1
        self.ack_ready = Condition(self.lock)
        self.got_fin = False
        # background listener
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.executor.submit(self.listener)

        

    def listener(self):
        while not self.closed:
            try:
                packet, addr = self.socket.recvfrom()

                if self.closed or packet == b'':
                    break

                if len(packet) < HEADER_SIZE:
                    continue # ignore malformed packet

                ptype, seq, recv_digest = struct.unpack(HEADER_FMT, packet[:HEADER_SIZE])
                payload = packet[HEADER_SIZE:]

                header_wo_hash = struct.pack('!BI', ptype, seq)
                calc_digest = hashlib.md5(header_wo_hash + payload).digest()

                if calc_digest != recv_digest:
                    continue

                if ptype == TYPE_DATA:
                    # buffer payload
                    with self.data_ready:
                        if seq >= self.expected_seq and seq not in self.recv_buffer:
                            self.recv_buffer[seq] = payload
                            self.data_ready.notify_all()

                    # send ACK
                    header_wo_hash = struct.pack('!BI', TYPE_ACK, seq)
                    digest = hashlib.md5(header_wo_hash).digest()    
                    ack_pkt = struct.pack(HEADER_FMT, TYPE_ACK, seq, digest)
                    self.socket.sendto(ack_pkt, (self.dst_ip, self.dst_port))
                
                elif ptype == TYPE_ACK:
                    # record ack so send() can finish
                    with self.ack_ready:
                        if seq > self.last_acked:
                            self.last_acked = seq
                        self.ack_ready.notify_all()
                
                elif ptype == TYPE_FIN:
                    with self.lock:
                        self.got_fin = True

                    header_wo_hash = struct.pack('!BI', TYPE_ACK, seq)
                    digest = hashlib.md5(header_wo_hash).digest()
                    fin_ack = struct.pack(HEADER_FMT, TYPE_ACK, seq, digest)
                    self.socket.sendto(fin_ack, (self.dst_ip, self.dst_port))

            except Exception as e:
                if not self.closed:
                    print("Listener died!")
                    print(e)
                    

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        # Your code goes here!  The code below should be changed!

        # for now I'm just sending the raw application-level data in one UDP payload

        # send data in chunks of MAX_PAYLOAD bytes
        for i in range(0, len(data_bytes), MAX_PAYLOAD):
            chunk = data_bytes[i:i+MAX_PAYLOAD]
            seq = self.send_seq

            header_wo_hash = struct.pack('!BI', TYPE_DATA, seq)
            digest = hashlib.md5(header_wo_hash + chunk).digest()
            pkt = struct.pack(HEADER_FMT, TYPE_DATA, seq, digest) + chunk
            self.socket.sendto(pkt, (self.dst_ip, self.dst_port))
            # wait for ACK
            t0 = time.time()
            while not self.closed:
                with self.ack_ready:
                    if self.last_acked >= seq:
                        break
                    self.ack_ready.wait(timeout=0.05)
                # timeout => resend
                if time.time() - t0 >= ACK_TIMEOUT:
                    self.socket.sendto(pkt, (self.dst_ip, self.dst_port))
                    t0 = time.time()
            self.send_seq += 1

        # self.socket.sendto(data_bytes, (self.dst_ip, self.dst_port))

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""
        # your code goes here!  The code below should be changed!
        with self.data_ready: # acquires lock
            while self.expected_seq not in self.recv_buffer:
                self.data_ready.wait(timeout=0.1)
                if self.closed:
                    return b'' # return empty bytes if closed while waiting
            
            data = self.recv_buffer.pop(self.expected_seq)
            self.expected_seq += 1
            return data
            

        # this sample code just calls the recvfrom method on the LossySocket
        # data, addr = self.socket.recvfrom()
        # For now, I'll just pass the full UDP payload to the app
        # return data

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # your code goes here, especially after you add ACKs and retransmissions.
        fin_seq = self.send_seq
        self.send_seq += 1
        header_wo_hash = struct.pack('!BI', TYPE_FIN, fin_seq)
        digest = hashlib.md5(header_wo_hash).digest()    
        fin_pkt = struct.pack(HEADER_FMT, TYPE_FIN, fin_seq, digest)

        self.socket.sendto(fin_pkt, (self.dst_ip, self.dst_port))

        t0 = time.time()
        while True:
            with self.ack_ready:
                if self.last_acked >= fin_seq:
                    break
                self.ack_ready.wait(timeout=0.05)
            if time.time() - t0 >= ACK_TIMEOUT:
                self.socket.sendto(fin_pkt, (self.dst_ip, self.dst_port))
                t0 = time.time()
        
        while True:
            with self.lock:
                if self.got_fin:
                    break
            time.sleep(0.05)
        
        time.sleep(GRACE_PERIOD)

        self.closed = True
        self.socket.stoprecv()
        try:
            self.executor.shutdown(wait=False)
        except Exception:
            pass
    
