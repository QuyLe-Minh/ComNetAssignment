import socket    

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

def get_local_ip():
    try:
        # Create a socket object and connect to an external server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))  # Google's public DNS server and port 80
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error as e:
        return f"Unable to determine local IP: {str(e)}"            
    