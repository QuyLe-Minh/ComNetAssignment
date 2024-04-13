import socket
import re

SERVER_PORT = 55555
LOCAL_PORT = 20386

CHOKE_ID = 0
UNCHOKE_ID = 1
INTERESTED_ID = 2
NOT_INTERESTED_ID = 3
HAVE_ID = 4
BITFIELD_ID = 5
REQUEST_ID = 6
PIECE_ID = 7
CANCEL_ID = 8
MY_PEER_ID = b"00112233445566778899"    #string of length 20, identifier for client

class PeerMessage:
    def __init__(self, message_id: bytes, payload: bytes):
        self.message_id = message_id
        self.payload = payload
        self.message_length_prefix = (len(message_id + payload)).to_bytes(
            4, byteorder="big"
        )
    def get_decoded(self):
        return {
            "message_length_prefix": self.message_length_prefix.hex(),
            "message_id": self.message_id.hex(),
            "payload": self.payload.hex(),
        }
    def get_encoded(self):
        return self.message_length_prefix + self.message_id + self.payload
    
class PEER:
    BLOCK_SIZE = 2**14  # 16KB
    
    def __init__(self):
        self.protocol = b"BitTorrent protocol"  # 19 bytes
        self.reserved = b"\x00" * 8 
        self.protocol_length = len(self.protocol).to_bytes(1, byteorder="big") 
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    @staticmethod
    def validate_ip(ip):
        # Regular expression to validate an IP address
        ip_pattern = re.compile("^(\d{1,3}\.){3}\d{1,3}$")
        if ip_pattern.match(ip):
            parts = ip.split(".")
            return all(0 <= int(part) <= 255 for part in parts)
        return False           
        
    def connect(self, peer_ip, peer_port) ->socket.socket:
        self.socket.connect((peer_ip, peer_port))
        return self.socket
    
    def handshake(self, info_hash: bytes, peer_id: bytes) -> bytes:
        if len(info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes long")
        if len(peer_id) != 20:
            raise ValueError("peer_id must be 20 bytes long")
        handshake_msg = (
            self.protocol_length + self.protocol + self.reserved + info_hash + peer_id
        )
        self.socket.sendall(handshake_msg)  # send the handshake message
        response = self.socket.recv(68)  # receive the handshake response
        connected_peer_id = response[48:]
        return connected_peer_id    
    
    def choke(self):
        message_id = CHOKE_ID.to_bytes(1, byteorder="big")
        payload = b""
        peer_message = PeerMessage(message_id, payload)
        self.socket.sendall(peer_message.get_encoded())
        
    def unchoke_send(self):
        message_id = UNCHOKE_ID.to_bytes(1, byteorder="big")
        payload = b""
        peer_message = PeerMessage(message_id, payload)
        self.socket.sendall(peer_message.get_encoded())
        
    def unchock_listen(self):
        response = self.socket.recv(5)
        length = int.from_bytes(response[0:4], byteorder="big")
        message_id = response[4]
        if message_id != UNCHOKE_ID:
            raise ValueError(f"Invalid message id: {message_id} for unchoke message")
        
    def interested_send(self):
        message_id = INTERESTED_ID.to_bytes(1, byteorder="big")
        payload = b""
        peer_message = PeerMessage(message_id, payload)
        self.socket.sendall(peer_message.get_encoded())
      
    def not_interested(self):
        message_id = NOT_INTERESTED_ID.to_bytes(1, byteorder="big")
        payload = b""
        peer_message = PeerMessage(message_id, payload)
        self.socket.sendall(peer_message.get_encoded())  
        
    def have(self):
        message_id = HAVE_ID.to_bytes(1, byteorder="big")
        payload = b""
        peer_message = PeerMessage(message_id, payload)
        self.socket.sendall(peer_message.get_encoded())  

    def bitfield_listen(self) -> list[int]:
        response = self.socket.recv(5)
        length = int.from_bytes(response[0:4], byteorder="big")
        message_id = response[4]
        if message_id != BITFIELD_ID:
            raise ValueError(f"Invalid message id: {message_id} for bitfield message")
        payload = self.socket.recv(length - 1)
        payload_str = "".join(format(x, "08b") for x in payload)
        # print(payload_str)
        indexes_of_pieces = [i for i, bit in enumerate(payload_str) if bit == "1"]
        return indexes_of_pieces   
    
    def request_send(self, piece_index: int, piece_length: int) -> bytes:
        message_id = REQUEST_ID.to_bytes(1, byteorder="big")
        full_block = b""
        for offset in range(0, piece_length, self.BLOCK_SIZE):
            print("-----Requesting Block-----")
            print(f"Offset: {offset} - Length: {piece_length}")
            block_length = min(self.BLOCK_SIZE, piece_length - offset)
            payload = piece_index.to_bytes(4, byteorder="big")
            payload += offset.to_bytes(4, byteorder="big")
            payload += block_length.to_bytes(4, byteorder="big")
            peer_message = PeerMessage(message_id, payload)
            # send the request message
            self.socket.sendall(peer_message.get_encoded())
            _, begin, block = self.piece_listen()  # listen for the piece message
            full_block += block
            print(f"Recieved {len(full_block)} bytes")
        return full_block  
    
    def piece_listen(self) -> tuple[int, int, bytes]:
        print("-----Listening for Piece-----")
        length = int.from_bytes(self.socket.recv(4), byteorder="big")
        message_id = int.from_bytes(self.socket.recv(1), byteorder="big")
        if message_id != self.PIECE_ID:
            raise ValueError(f"Invalid message id: {message_id} for piece message")
        piece_index = int.from_bytes(self.socket.recv(4), byteorder="big")
        begin = int.from_bytes(self.socket.recv(4), byteorder="big")
        recieved = 0
        size_of_block = length - 9
        full_block = b""
        while recieved < size_of_block:
            print(f"Recieved: {recieved} - Size: {size_of_block}")
            block = self.socket.recv(size_of_block - recieved)
            full_block += block
            recieved += len(block)
        print(f"Recieved: {recieved} - Size: {size_of_block}")
        return piece_index, begin, full_block  
    
    def cancel(self):
        pass 
    