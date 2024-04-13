from utilities import *
import threading
    

class Seeder:
    DEFAULT_SERVER_PORT = 55555
    
    def __init__(self):
        self.server_host = get_local_ip()
        self.server_port = self.DEFAULT_SERVER_PORT
        self.main_seeder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.main_seeder.bind((get_local_ip(), LOCAL_PORT))     #static one, may change later
        self.main_seeder.settimeout(1)
        self.main_seeder.listen()
    
    def handle_handshake(self, conn, addr):
        request = conn.recv(1024).decode()
        
        pass
        
    def connect_to_server(self):
        while True:
            try:
                conn, addr = self.main_seeder.accept()
                print("HI CLIENT")
                thread = threading.Thread(target=self.handle_handshake, args=(conn, addr))
                thread.start()
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
    
if __name__ == "__main__":
    handle_download_piece("", "swe.torrent", 0)
    # client = Client()
    # client.connect_to_server()
 
                     