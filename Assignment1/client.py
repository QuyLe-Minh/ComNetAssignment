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

    def seeding(self, conn, addr):
        print("Seeding...")
        with open(self.file_path, "rb") as f:
            while True:
                piece = f.read(262144)
                if not piece:
                    break
                conn.sendall(hashlib.sha1(piece).digest())
        conn.close()
        
    def listening(self):
        while True:
            try:
                conn, addr = self.main_seeder.accept()
                print("HI PEER")
                thread = threading.Thread(target=self.handle_handshake, args=(conn, addr))
                thread.start()

                # thread2 = threading.Thread(target=self.seeding, args=(conn, addr))
                # thread2.start()
            except:
                pass
    
def handle_download_piece(download_directory, torrent_file_name, piece):
    # extract the meta info from the torrent file
    file_data = read_file(torrent_file_name)
    decoded_data = Bencode.decode(file_data)
    meta_info = MetaInfo(decoded_data)
    # connect to the tracker and get the peers
    tracker = Tracker(meta_info.announce)
    response = tracker.get_peers(
        meta_info.info_hash, MY_PEER_ID.decode(), 55555, 0, 0, meta_info.length, 1
    )
    if response.status_code != 200:
        raise ConnectionError(
            f"Failed to get peers! Status Code: {response.status_code}, Reason: {response.reason}"
        )
    # get the peers from the response
    response_data = response.content
    decoded_response = Bencode.decode(response_data)
    peers = decoded_response["peers"]
    # connect to the first peer and send the handshake message
    peer = PEER()
    peer_ip_port = get_peer_ip(peers[0:6])
    peer_ip = peer_ip_port.split(":")[0]
    peer_port = int(peer_ip_port.split(":")[1])
    peer.connect(peer_ip, peer_port)
    peer.handshake(meta_info.info_hash, MY_PEER_ID)
    indexes_of_pieces = peer.bitfield_listen()
    if piece not in indexes_of_pieces:
        raise ValueError(f"Peer does not have piece {piece}")
    peer.interested_send()
    peer.unchock_listen()
    piece_length = meta_info.piece_length
    if piece == (len(meta_info.pieces) // 20) - 1:
        piece_length = meta_info.length % meta_info.piece_length
    block = peer.request_send(piece, piece_length)
    print(len(block))
    try:
        with open(f"{download_directory}", "wb") as f:
            f.write(block)
            print(f"Piece {piece} downloaded to {download_directory}")
    except Exception as e:
        print(e)
        
        
def download(output_dir, torrent_file_name):
    file_data = read_file(torrent_file_name)
    decoded_data = Bencode.decode(file_data)
    meta_info = MetaInfo(decoded_data)
    
    tracker = Tracker(meta_info.announce)
    response = tracker.get_peers(meta_info.info_hash_hex, MY_PEER_ID.decode(), SERVER_PORT, 0, 0, meta_info.length, 1) 
        
    if response.status_code != 200:
        raise ConnectionError(f"Failed to get peers!!! Status Code: {response.status_code}, Reason: {response.reason}") 
        
    response_data = response.content
    decoded_response = Bencode.decode(response_data)
    peers = decoded_response["peers"]
    peer = PEER()
    peer_ip_port = get_peer_ip(peers[0:6])
    peer_ip = peer_ip_port.split(":")[0]
    peer_port = int(peer_ip_port.split(":")[1])    
    peer.connect(peer_ip, peer_port)
    # peer.handshake(meta_info.info_hash, MY_PEER_ID)
    
    # indexes_of_pieces = peer.bitfield_listen()
    # peer.interested_send()
    # peer.unchock_listen()
    
    # for piece in indexes_of_pieces:
    #     handle_download_piece(output_dir, torrent_file_name, piece)
def handle_handshake(torrent_file_name, peer_ip_with_port):
    file_data = read_file(torrent_file_name)
    decoded_data = Bencode.decode(file_data)

    meta_info = MetaInfo(decoded_data)
    peer_ip, peer_port = peer_ip_with_port.split(":")
    peer_port = int(peer_port)
    
    peer = PEER()

    peer.connect(peer_ip, peer_port)
    connected_peer_id = peer.handshake(meta_info.info_hash, MY_PEER_ID)
    print(f"Peer ID: {connected_peer_id.hex()}")   
    
def handle_peers(torrent_file_name):
    file_data = read_file(torrent_file_name)
    decoded_data = Bencode.decode(file_data)
    meta_info = MetaInfo(decoded_data)
    tracker = Tracker(meta_info.announce)
    response = tracker.get_peers(
        meta_info.info_hash, MY_PEER_ID.decode(), 55555, 0, 0, meta_info.length, 1
    )
    if response.status_code != 200:
        raise ConnectionError(
            f"Failed to get peers! Status Code: {response.status_code}, Reason: {response.reason}"
        )
    response_data = response.content
    decoded_response = Bencode.decode(response_data)
    peers = decoded_response["peers"]
    peers_ip = []
    for i in range(0, len(peers), 6):
        peers_ip.append(get_peer_ip(peers[i : i + 6]))
    for peer in peers_ip:
        print(peer) 
    
if __name__ == "__main__":
    seeder = Seeder()
    seeder.listening()
    # handle_download_piece("", "swe.torrent", 0)
    # client = Client()
    # client.connect_to_server()
 
                     