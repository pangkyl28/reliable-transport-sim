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

HEADER_FMT = '!BI16s' 
HEADER_SIZE = struct.calcsize(HEADER_FMT)
MAX_UDP = 1472 
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

        # State variables
        self.send_seq = 0       
        self.recv_next = 0      
        self.recv_buffer = {}   
        
        self.unacked = {}       
        self.got_fin = False
        self.closed = False
        
        # Synchronization
        self.lock = Lock()
        self.data_ready = Condition(self.lock)
        
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.executor.submit(self.listener)
        self.executor.submit(self.retransmit_loop)
    
    def listener(self):
        while not self.closed:
            try:
                packet, addr = self.socket.recvfrom()
                if not packet or len(packet) < HEADER_SIZE:
                    continue

                ptype, seq, recv_digest = struct.unpack(HEADER_FMT, packet[:HEADER_SIZE])
                payload = packet[HEADER_SIZE:]

                # Integrity Check
                header_wo_hash = struct.pack('!BI', ptype, seq)
                if hashlib.md5(header_wo_hash + payload).digest() != recv_digest:
                    continue

                if ptype == TYPE_DATA:
                    with self.lock:
                        if seq >= self.recv_next and seq not in self.recv_buffer:
                            self.recv_buffer[seq] = payload
                            self.data_ready.notify_all()
                    
                    # Send ACK for the specific packet received (Selective Repeat style)
                    self.send_ack(seq)

                elif ptype == TYPE_ACK:
                    with self.lock:
                        if seq in self.unacked:
                            del self.unacked[seq]

                elif ptype == TYPE_FIN:
                    with self.lock:
                        self.got_fin = True
                    self.send_ack(seq) # ACK the FIN

            except Exception:
                if not self.closed: 
                    break
                    
    def send_ack(self, seq):
        header = struct.pack('!BI', TYPE_ACK, seq)
        digest = hashlib.md5(header).digest()
        pkt = struct.pack(HEADER_FMT, TYPE_ACK, seq, digest)
        self.socket.sendto(pkt, (self.dst_ip, self.dst_port))

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        # Your code goes here!  The code below should be changed!

        # for now I'm just sending the raw application-level data in one UDP payload

        # send data in chunks of MAX_PAYLOAD bytes
        for i in range(0, len(data_bytes), MAX_PAYLOAD):
            chunk = data_bytes[i:i+MAX_PAYLOAD]
            with self.lock:
                seq = self.send_seq
                self.send_seq += 1
                
                header_wo_hash = struct.pack('!BI', TYPE_DATA, seq)
                digest = hashlib.md5(header_wo_hash + chunk).digest()
                pkt = struct.pack(HEADER_FMT, TYPE_DATA, seq, digest) + chunk
                
                self.unacked[seq] = [pkt, time.time()]
            
            self.socket.sendto(pkt, (self.dst_ip, self.dst_port))
    
    def retransmit_loop(self):
        while not self.closed:
            time.sleep(0.1)
            now = time.time()
            to_resend = []
            
            with self.lock:
                for seq, info in self.unacked.items():
                    if now - info[1] > ACK_TIMEOUT:
                        to_resend.append(info[0])
                        info[1] = now # Reset timer
            
            for pkt in to_resend:
                self.socket.sendto(pkt, (self.dst_ip, self.dst_port))

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""
        # your code goes here!  The code below should be changed!
        with self.lock:
            while self.recv_next not in self.recv_buffer:
                if not self.data_ready.wait(timeout=1.0) and self.closed:
                    return b''
            res = self.recv_buffer.pop(self.recv_next)
            self.recv_next += 1
            return res    

        # this sample code just calls the recvfrom method on the LossySocket
        # data, addr = self.socket.recvfrom()
        # For now, I'll just pass the full UDP payload to the app
        # return data

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # your code goes here, especially after you add ACKs and retransmissions.
        while True:
            with self.lock:
                if not self.unacked: break
            time.sleep(0.1)

        fin_seq = self.send_seq
        self.send_seq += 1
        header = struct.pack('!BI', TYPE_FIN, fin_seq)
        digest = hashlib.md5(header).digest()
        fin_pkt = struct.pack(HEADER_FMT, TYPE_FIN, fin_seq, digest)

        with self.lock:
            self.unacked[fin_seq] = [fin_pkt, time.time()]
        self.socket.sendto(fin_pkt, (self.dst_ip, self.dst_port))

        while True:
            with self.lock:
                if fin_seq not in self.unacked and self.got_fin:
                    break
            time.sleep(0.1)

        time.sleep(GRACE_PERIOD)
        self.closed = True
        self.socket.stoprecv()
        self.executor.shutdown(wait=False)
    
