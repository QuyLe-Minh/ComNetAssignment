from utilities import *
import threading
import struct

lock = threading.Lock()
    

class Seeder:
    def __init__(self, port):
        my_ip = get_local_ip()
        self.main_seeder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.main_seeder.bind((my_ip, port)) 
        
        lock.acquire()
        print(f"Seeder IP: {my_ip}")
        print(f"Server is listening on port {port}...")
        lock.release()
        self.main_seeder.settimeout(1)
        self.main_seeder.listen()
        self.MY_PEER_ID = b'-RN0.0.0-Z\xf5\xc2\xcfH\x88\x15\xc4\xa2\xfa\x7f'
        
        self.pieces = {"cs229-linalg.pdf": [0],
                       "emnlp2014-depparser.pdf": [0,1],
                       "test.txt": [0],
                       "swe.pdf": [i for i in range(21)]
                       }

        self.key = None
    
    def parse_request(self, request):
        protocol_len, = struct.unpack("B", request[:1])
        protocol = request[1:1+protocol_len].decode()
        reserved = request[1+protocol_len:9+protocol_len]
        infohash = request[9+protocol_len:29+protocol_len]
        peerid = request[29+protocol_len:]
        
        print(peerid)
        
        return (protocol_len, protocol, reserved, infohash, peerid)
    
    def handle_handshake(self, conn):
        request = conn.recv(68)
        conn.sendall(request)
        key = conn.recv(30)
        self.key = key.decode()
    
    def bitfield_send(self, conn):
        pieces = self.pieces[self.key]
        
        bitfield = bytearray(10)    #80 pieces
        for i in pieces:
            byte_index = i // 8
            bit_index = i % 8
            bitfield[byte_index] |= 1 << (7-bit_index)
            
        peer_mess = PeerMessage(BITFIELD_ID.to_bytes(1, byteorder="big"), bitfield)    
        
        conn.send(peer_mess.get_encoded())

    def seeding(self, conn, piece_id, offset, block_length):
        # print("Sending...")
        message_id = PIECE_ID.to_bytes(1, byteorder="big")
        with open(os.path.join("data", self.key), "rb") as f:
            f.seek(piece_id * PIECE_LENGTH + offset)
            piece = f.read(block_length)
            payload = piece_id.to_bytes(4, byteorder="big")
            payload += offset.to_bytes(4, byteorder="big")
            payload += piece
            
            peer_message = PeerMessage(message_id, payload)
            conn.sendall(peer_message.get_encoded())

        
    def parse_request_send(self, request):
        message_length_prefix = request[:4]
        message_id = request[4]
        payload = request[5:]
        
        return (message_id, payload)
        
        
    def handle_client(self, conn):
        self.handle_handshake(conn)
        self.bitfield_send(conn)
        while True:
            request = conn.recv(47) # 4 bytes for length prefix, 1 byte for message id, 42 bytes for payload (last 30 bytes for file)
            if request == b"":
                print("Connection closed")
                conn.close()
                break            
            message_id, payload = self.parse_request_send(request)
            
            if message_id == REQUEST_ID:
                piece_id = int.from_bytes(payload[:4], byteorder='big')
                offset = int.from_bytes(payload[4:8], byteorder='big')
                block_length = int.from_bytes(payload[8:12], byteorder='big')
                self.key = payload[12:].decode()
            
                self.seeding(conn, piece_id, offset, block_length)

        
    def listening(self):
        while True:
            try:
                conn, _ = self.main_seeder.accept()
                thread = threading.Thread(target=self.handle_client, args=(conn,))
                thread.start()
            except:
                pass
    
def start_seeder(port):
    seeder = Seeder(port)
    seeder.listening()

if __name__ == "__main__":
    for port in LOCAL_PORT:
        thread = threading.Thread(target=start_seeder, args=(port,))
        thread.start()
 
                     