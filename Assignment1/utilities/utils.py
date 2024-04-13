import hashlib
import json
import socket
import os
import time
from utilities import Bencode, MetaInfo

    
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
    

def read_file(file_name):
    with open(file_name, "rb") as f:
        return f.read()
    
def get_piece_hashes(pieces):
    return [pieces[i : i + 20].hex() for i in range(0, len(pieces), 20)]

def handle_decode(bencoded_value):
    def bytes_to_str(data):
        if isinstance(data, bytes):
            return data.decode()
        raise TypeError(f"Type not serializable: {type(data)}")
    decoded_value = Bencode.decode(bencoded_value)
    print(json.dumps(decoded_value, default=bytes_to_str))

def handle_info(torrent_file_name):
    file_data = read_file(torrent_file_name)    #read bytes
    decoded_data = Bencode.decode(file_data)
    meta_info = MetaInfo(decoded_data)
    print(f"Tracker URL: {meta_info.announce.decode()}")    #string built in function
    print(f"Length: {meta_info.length}")
    print(f"Info Hash: {meta_info.info_hash_hex}")
    print(f"Piece Length: {meta_info.piece_length}")
    print(f"Piece Hashes:")
    piece_hashes = meta_info.get_piece_hashes()
    for piece_hash in piece_hashes:
        print(piece_hash)
        

def create_torrent_file(file_path, tracker_url, piece_length=262144):  # Default piece length is 256KB
    # Get file info
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)

    # Read the file in pieces and calculate the hash for each piece
    pieces = b''
    with open(file_path, 'rb') as f:
        while True:
            piece = f.read(piece_length)
            if not piece:
                break
            pieces += hashlib.sha1(piece).digest()

    # Create the torrent file content
    torrent = {
        'announce': tracker_url,
        'creation date': int(time.time()),
        'info': {
            'name': file_name,
            'piece length': piece_length,
            'length': file_size,
            'pieces': pieces
        }
    }

    # Bencode the torrent file content
    torrent_bencoded = Bencode.encode(torrent)

    # Write the torrent file
    torrent_file_name = file_name.split('.')[0] + '.torrent'
    with open(torrent_file_name, 'wb') as f:
        f.write(torrent_bencoded)

    print(f'Torrent file created: {torrent_file_name}')
    
def get_peer_ip(peer):
    return f"{peer[0]}.{peer[1]}.{peer[2]}.{peer[3]}:{peer[4]*256 + peer[5]}"    


if __name__ == "__main__":
    # Usage
    create_torrent_file('swe.pdf', get_local_ip() + ":55555" + "/announce")