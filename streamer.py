import time
import struct
from concurrent.futures import ThreadPoolExecutor
from threading import Lock, Condition

# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY


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
        # background listener
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.executor.submit(self.listener)

    def listener(self):
        HEADER_SIZE = 4
        while not self.closed:
            try:
                packet, addr = self.socket.recvfrom()

                if self.closed or packet == b'':
                    break

                if len(packet) < HEADER_SIZE:
                    continue # ignore malformed packet

                seq = struct.unpack('!I', packet[:HEADER_SIZE])[0]
                payload = packet[HEADER_SIZE:]

                with self.data_ready: # acquires lock
                    if seq >= self.expected_seq and seq not in self.recv_buffer:
                        self.recv_buffer[seq] = payload
                        self.data_ready.notify_all() # wake up recv() if it's waiting for this seq
            
            except Exception as e:
                if not self.closed:
                    print("Listener died!")
                    print(e)
                    

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        # Your code goes here!  The code below should be changed!

        # for now I'm just sending the raw application-level data in one UDP payload
        HEADER_SIZE = 4 # 4 bytes for seq
        MAX_UDP = 1472

        MAX_PAYLOAD = MAX_UDP - HEADER_SIZE # must be <= 1472 for LossyUDP

        # send data in chunks of MAX_PAYLOAD bytes
        for i in range(0, len(data_bytes), MAX_PAYLOAD):
            chunk = data_bytes[i:i+MAX_PAYLOAD]
            header = struct.pack('!I', self.send_seq)
            self.socket.sendto(header + chunk, (self.dst_ip, self.dst_port))
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
        self.closed = True
        self.socket.stoprecv() # unblock listener if it's waiting

        try:
            self.executor.shutdown(wait=False)
        except Exception:
            pass
    
