from utilities import *
import threading
import struct
    

class Seeder:
    def __init__(self):
        self.server_host = get_local_ip()
        self.server_port = SERVER_PORT
        self.main_seeder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.main_seeder.bind((self.server_host, LOCAL_PORT))     #static one, may change later
        
        print(f"Seeder IP: {self.server_host}")
        print(f"Server is listening on port {LOCAL_PORT}...")
        self.main_seeder.settimeout(1)
        self.main_seeder.listen()
        self.MY_PEER_ID = b'-RN0.0.0-Z\xf5\xc2\xcfH\x88\x15\xc4\xa2\xfa\x7f'

        self.file_path = FILE_PATH

        self.pieces = [0, 1, 3, 6, 7]
    
    def parse_request(self, request):
        protocol_len, = struct.unpack("B", request[:1])
        protocol = request[1:1+protocol_len].decode()
        reserved = request[1+protocol_len:9+protocol_len]
        infohash = request[9+protocol_len:29+protocol_len]
        peerid = request[29+protocol_len:]
        
        print(peerid)
        
        return (protocol_len, protocol, reserved, infohash, peerid)
    
    def handle_handshake(self, conn, addr):
        request = conn.recv(68)
        # protocol_len, protocol, reserved, infohash, peerid = self.parse_request(request)
        # message = (protocol_len + protocol + reserved + infohash + peerid)
        conn.sendall(request)
        
        bitfield_send = (len(self.pieces).to_bytes(4, byteorder="big") + b"\x05")
        conn.sendall(bitfield_send)
        
        bitfield = 0
        for i in self.pieces:
            bitfield |= 1 << (7-i)
            
        conn.send(bitfield.to_bytes(1, byteorder="big"))

    def unchoke_send(self, conn, addr):
        pass

    def get_message(self, conn, addr):
        piece = None
        if piece in self.pieces:
            self.unchoke_send(conn, addr)
            
        conn.close()

    def seeding(self, conn, addr, piece_id, offset, block_length):
        print("Seeding...")
        with open(self.file_path, "rb") as f:
            f.seek(offset)
            piece = f.read(block_length)
            conn.sendall(piece)
        conn.close()
        
    def parse_request_send(self, request):
        message_length_prefix = request[:4]
        message_id = request[4]
        payload = request[5:]
        
        # piece_id = payload[:4]
        # offset = payload[4:8]
        # block_length = payload[8:]
        
        piece_id = int.from_bytes(payload[:4], byteorder='big')
        offset = int.from_bytes(payload[4:8], byteorder='big')
        block_length = int.from_bytes(payload[8:], byteorder='big')
        
        return (piece_id, offset, block_length)
        
        
    def handle_client(self, conn, addr):
        self.handle_handshake(conn, addr)
        request = conn.recv(17)
        piece_id, offset, block_length = self.parse_request_send(request)
        conn.sendall(request[:13])
        self.seeding(conn, addr, piece_id, offset, block_length)
        
    def listening(self):
        while True:
            try:
                conn, addr = self.main_seeder.accept()
                print("HI PEER")
                thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                thread.start()

                # thread2 = threading.Thread(target=self.seeding, args=(conn, addr))
                # thread2.start()
            except:
                pass
    
if __name__ == "__main__":
    seeder = Seeder()
    seeder.listening()
    # handle_download_piece("", "swe.torrent", 0)
    # client = Client()
    # client.connect_to_server()
 
                     