import json
import sys
import hashlib
import requests
import socket
import threading
from tqdm import tqdm

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
BLOCK_SIZE = 2**14  # 16KB
PIECE_LENGTH = 512 * 1024  # 512KB


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
    
class Tracker:
    def __init__(self, announce_url):
        self.announce_url = announce_url
    def get_peers(
        self,
        info_hash: bytes,
        peer_id: str,
        name: str, 
        port: int = 55555,
        uploaded: int = 0,
        downloaded: int = 0,
        left: int = 0,
        compact: int = 1,
    ) -> requests.Response:
        response = requests.get(
            self.announce_url,
            params={
                "info_hash": info_hash,
                "peer_id": peer_id,
                "port": port,
                "uploaded": uploaded,
                "downloaded": downloaded,
                "left": left,
                "compact": compact,
                "name": name
            },
        )
        return response #type->bytes
    
class Peer:
    def __init__(self):
        self.protocol = b"BitTorrent protocol"  # 19 bytes
        self.reserved = b"\x00" * 8  # 8 bytes reserved
        self.protocol_length = len(self.protocol).to_bytes(1, byteorder="big")  # 1 byte
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket

    def connect(self, peer_ip, peer_port) -> socket.socket:
        self.socket.connect((peer_ip, peer_port))
        return self.socket
    
    def disconnect(self):
        if self.socket:
            self.socket.close()
            self.socket = None
    """"
    The handshake message is the first message sent by the client to the server.
    It is used to establish a connection between the client and the server.
    The handshake message has the following format:
    <protocol_len><protocol><reserved><info_hash><peer_id><file_key>
    protocol_len: 1 byte for length of the protocol identifier
    protocol: 19 bytes of protocol identifier
    reserved: 8 bytes reserved for future use
    info_hash: 20 bytes hash of the info key in the torrent file
    peer_id: 20 bytes unique identifier of the client
    file_key: variable length key for the file requested
    """
    def handshake(self, file:str, info_hash: bytes, peer_id: bytes) -> bytes:
        if len(info_hash) != 20:
            raise ValueError("info_hash must be 20 bytes long")
        if len(peer_id) != 20:
            raise ValueError("peer_id must be 20 bytes long")
        handshake_msg = (
            self.protocol_length + self.protocol + self.reserved + info_hash + peer_id + file.encode()
        )
        self.socket.sendall(handshake_msg)  # send the handshake message
        response = self.socket.recv(68)  # receive the handshake response
        connected_peer_id = response[48:68]
        return connected_peer_id
    """
    The choke message is used to notify the peer that the client is not interested in downloading pieces from the peer.
    The choke message has the following format:
    <length><message_id>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    """
    def choke(self):
        message_id = CHOKE_ID.to_bytes(1, byteorder="big")
        payload = b""
        peer_message = PeerMessage(message_id, payload)
        self.socket.sendall(peer_message.get_encoded())
    """
    The unchoke message is used to notify the peer that the client is ready to download pieces from the peer.
    The unchoke message has the following format:
    <length><message_id>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    """
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
    """
    The interested message is used to notify the peer that the client is interested in downloading pieces from the peer.
    The interested message has the following format:
    <length><message_id>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    """
    def interested_send(self):
        message_id = INTERESTED_ID.to_bytes(1, byteorder="big")
        payload = b""
        peer_message = PeerMessage(message_id, payload)
        self.socket.sendall(peer_message.get_encoded())
    """
    The not interested message is used to notify the peer that the client is not interested in downloading pieces from the peer.
    The not interested message has the following format:
    <length><message_id>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    """
    def not_interested(self):
        message_id = NOT_INTERESTED_ID.to_bytes(1, byteorder="big")
        payload = b""
        peer_message = PeerMessage(message_id, payload)
        self.socket.sendall(peer_message.get_encoded())
    """
    The have message is used to notify the peer that the client has downloaded a piece.
    The have message has the following format:
    <length><message_id><payload>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    payload: 4 bytes for the zero-based piece index
    """
    def have(self):
        message_id = HAVE_ID.to_bytes(1, byteorder="big")
        payload = b""
        peer_message = PeerMessage(message_id, payload)
        self.socket.sendall(peer_message.get_encoded())
    """"
    The bitfield message is used to specify which pieces the peer has.
    The bitfield message has the following format:
    <length><message_id><payload>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    payload: variable length payload representing the pieces
    """
    def bitfield_listen(self) -> list[int]:
        response = self.socket.recv(5)
        length = int.from_bytes(response[0:4], byteorder="big")
        message_id = response[4]
        if message_id != BITFIELD_ID:
            raise ValueError(f"Invalid message id: {message_id} for bitfield message")
        payload = self.socket.recv(length - 1)
        payload_str = "".join(format(x, "08b") for x in payload)
        indexes_of_pieces = [i for i, bit in enumerate(payload_str) if bit == "1"]
        return indexes_of_pieces
    """
    The request message is used to request a piece from the peer.
    The request message has the following format:
    <length><message_id><payload>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    payload: 12 bytes payload representing the index, begin, and length
    payload: ~30 bytes more for the file requested?
    """
    def request_send(self, file: str, piece_index: int, piece_length: int) -> bytes:
        message_id = REQUEST_ID.to_bytes(1, byteorder="big")
        full_block = b""
        for offset in range(0, piece_length, BLOCK_SIZE):
            # print("-----Requesting Block-----")
            # print(f"Offset: {offset} - Length: {piece_length}")
            block_length = min(BLOCK_SIZE, piece_length - offset)
            payload = piece_index.to_bytes(4, byteorder="big")
            payload += offset.to_bytes(4, byteorder="big")
            payload += block_length.to_bytes(4, byteorder="big")
            payload += file.encode()
            peer_message = PeerMessage(message_id, payload)
            # send the request message
            self.socket.sendall(peer_message.get_encoded())
            _, begin, block = self.piece_listen()  # listen for the piece message
            full_block += block
            # print(f"Recieved {len(full_block)} bytes")
        return full_block
    """
    The piece message is used to send a piece to the peer.
    The piece message has the following format:
    <length><message_id><payload>
    length: 4 bytes for length of the message
    message_id: 1 byte for message identifier
    payload: variable length payload representing the piece 
        index: the zero-based piece index
        begin: the zero-based byte offset within the piece
        block: the data for the piece, usually 2^14 bytes long
    """
    def piece_listen(self) -> tuple[int, int, bytes]:
        # print("-----Listening for Piece-----")
        length = int.from_bytes(self.socket.recv(4), byteorder="big")
        message_id = int.from_bytes(self.socket.recv(1), byteorder="big")
        if message_id != PIECE_ID:
            raise ValueError(f"Invalid message id: {message_id} for piece message")
        piece_index = int.from_bytes(self.socket.recv(4), byteorder="big")
        begin = int.from_bytes(self.socket.recv(4), byteorder="big")
        recieved = 0
        size_of_block = length - 9
        full_block = b""
        while recieved < size_of_block:
            block = self.socket.recv(size_of_block - recieved)
            full_block += block
            recieved += len(block)
        # print(f"Recieved: {recieved} - Size: {size_of_block}")
        return piece_index, begin, full_block
    
    def cancel(self):
        pass
class MetaInfo:
    def __init__(self, data):
        self.announce = data["announce"]
        self.info = data["info"]
        self.name = self.info["name"]
        self.files_info = None
        self.length = None
        try:
            self.files_info = self.info["files"]    #length, path
        except:
            self.length = self.info["length"]
        self.piece_length = self.info["piece length"]
        self.pieces = self.info["pieces"]
        self.info_hash = hashlib.sha1(Bencode.encode(self.info)).digest()   #the actual hash value of the data and returns it as a bytes object.
        self.info_hash_hex = self.info_hash.hex()   #from bytes to hexadecimal
    def get_piece_hashes(self):
        return [self.pieces[i : i + 20].hex() for i in range(0, len(self.pieces), 20)]  #20 bytes/piece
class Bencode:
    def __init__(self):
        pass
    @staticmethod
    def decode_string(bencoded_value) -> tuple:
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        length = int(bencoded_value[:first_colon_index])
        start_index = first_colon_index + 1
        end_index = start_index + length
        if end_index > len(bencoded_value):
            raise ValueError("Invalid encoded value")
        value = bencoded_value[start_index:end_index]
        length = first_colon_index + length + 1
        return value, length
    @staticmethod
    def decode_integer(bencoded_value):
        end_index = bencoded_value.find(b"e")
        if end_index == -1:
            raise ValueError("Invalid encoded value")
        value = int(bencoded_value[1:end_index])
        length = end_index + 1
        return value, length
    @staticmethod
    def decode_list(bencoded_value):
        result = []
        i = 1
        while i < len(bencoded_value):
            if chr(bencoded_value[i]) == "e":
                break
            if chr(bencoded_value[i]).isdigit():
                value, length = Bencode.decode_string(bencoded_value[i:])
            elif chr(bencoded_value[i]) == "i":
                value, length = Bencode.decode_integer(bencoded_value[i:])
            elif chr(bencoded_value[i]) == "l":
                value, length = Bencode.decode_list(bencoded_value[i:])
            elif chr(bencoded_value[i]) == "d":
                value, length = Bencode.decode_dictionary(bencoded_value[i:])
            i += length
            result.append(value)
        return result, i + 1
    @staticmethod
    def decode_dictionary(bencoded_value):
        result = {}
        i = 1
        while i < len(bencoded_value):
            if chr(bencoded_value[i]) == "e":
                break
            key, key_length = Bencode.decode_string(bencoded_value[i:])
            i += key_length
            if chr(bencoded_value[i]).isdigit():
                value, length = Bencode.decode_string(bencoded_value[i:])
            elif chr(bencoded_value[i]) == "i":
                value, length = Bencode.decode_integer(bencoded_value[i:])
            elif chr(bencoded_value[i]) == "l":
                value, length = Bencode.decode_list(bencoded_value[i:])
            elif chr(bencoded_value[i]) == "d":
                value, length = Bencode.decode_dictionary(bencoded_value[i:])
            i += length
            result[key.decode()] = value
        result = dict(sorted(result.items()))
        return result, i + 1
    @staticmethod
    def decode(bencoded_value):
        if chr(bencoded_value[0]).isdigit():
            value, _ = Bencode.decode_string(bencoded_value)
            return value
        elif chr(bencoded_value[0]) == "i":
            value, _ = Bencode.decode_integer(bencoded_value)
            return value
        elif chr(bencoded_value[0]) == "l":
            value, _ = Bencode.decode_list(bencoded_value)
            return value
        elif chr(bencoded_value[0]) == "d":
            value, _ = Bencode.decode_dictionary(bencoded_value)
            return value
        else:
            raise NotImplementedError("Unknown bencode type")
    @staticmethod
    def encode(value):
        if isinstance(value, str):
            return f"{len(value)}:{value}".encode()
        elif isinstance(value, bytes):
            return f"{len(value)}:".encode() + value
        elif isinstance(value, int):
            return f"i{value}e".encode()
        elif isinstance(value, list):
            result = b"l"
            for item in value:
                result += Bencode.encode(item)
            result += b"e"
            return result
        elif isinstance(value, dict):
            result = b"d"
            for key, item in value.items():
                result += Bencode.encode(key)
                result += Bencode.encode(item)
            result += b"e"
            return result
        else:
            raise NotImplementedError(f"Unknown type {type(value)}")
        
def read_file(file_name):
    with open(file_name, "rb") as f:
        return f.read()

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
    
    tracker = Tracker(meta_info.announce)
    print(f"Tracker URL: {meta_info.announce.decode()}")    #string built in function
    
    file_to_space = {}
    if meta_info.files_info:
        for file in meta_info.files_info:
            print(f"File Name: {file['path'][0].decode()}")
            print(f"File Length: {file['length'] / (1024 ** 2)} MB")
            
            file_to_space[file['path'][0].decode()] = file['length']
    print(f"Info Hash: {meta_info.info_hash_hex}")
    print(f"File Name: {meta_info.name.decode()}")
    print(f"Piece Length: {meta_info.piece_length}")

    
    response = tracker.get_peers(
        meta_info.info_hash, MY_PEER_ID.decode(), meta_info.name, 55555, 0, 0, 10, 1
    )
    if response.status_code != 200:
                raise ConnectionError(
            f"Failed to get peers! Status Code: {response.status_code}, Reason: {response.reason}"
        )
    response_data = response.content
    decoded_response = Bencode.decode(response_data)
    peers = decoded_response["peers"]
    for file, peer_addr in peers.items():
        peers_ip = []
        for i in range(0, len(peer_addr), 6):
            peers_ip.append(get_peer_ip(peer_addr[i : i + 6]))  #4bytes ip + 2bytes port
        
        print(f"File {file}: {peers_ip}")
    
    return (peers, meta_info, file_to_space)

def get_peer_ip(peer):
    return f"{peer[0]}.{peer[1]}.{peer[2]}.{peer[3]}:{peer[4]*256 + peer[5]}"

def handle_download(output_directory, torrent_file_name):
    """Download file(s)

    Args:
        output_directory (str): folder to save the downloaded file(s)
        torrent_file_name
    """
    import time
    peers, meta_info, file_to_space = handle_info(torrent_file_name) 
    
    print("=====================================")
    
    total_start = time.time() 
    
    for file, peer_addr in peers.items():
        with open(f'{output_directory}/{file}', 'w') as f:
            pass
        
        total_size = file_to_space[file]
        
        start_time = time.time()
        with tqdm(total = total_size, unit='B', unit_scale=True, desc=file) as pbar:
            def callback():
                pbar.update(PIECE_LENGTH)

            download_file(file, peer_addr, meta_info, output_directory, callback)
        
        time_taken = time.time() - start_time
        print(f"Time taken to download {file}: {time_taken} seconds")
        
        print("=====================================")
    total_time_taken = time.time() - total_start
    print(f"Total time taken: {total_time_taken} seconds")
        
        
        
def download_file(file, peer_addr, meta_info, output_directory, callback):
    MAX_WORKERS = 5
    from concurrent.futures import ThreadPoolExecutor
    executors = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    
    peer = Peer()
    peer_ip_port = get_peer_ip(peer_addr[:6]).split(":")
    peer_ip = peer_ip_port[0]
    peer_port = int(peer_ip_port[1])
    peer.connect(peer_ip, peer_port)
    peer.handshake(file, meta_info.info_hash, MY_PEER_ID)
    indexes_of_pieces = peer.bitfield_listen()
    # print(f"FILE: {file} - PIECES: {indexes_of_pieces}")
    
    n = min(len(peer_addr) // 6, MAX_WORKERS)

    futures = [None] * n
    for piece in indexes_of_pieces: 
        idx = 0
        while True:
            if futures[idx] is None or futures[idx].done():
                futures[idx] = executors.submit(handle_download_piece, f"{output_directory}/{file}", meta_info, peer_addr, file, piece, idx)
                break
            idx = (idx + 1) % n
        callback()
        
    executors.shutdown(wait=True)
    
            
def handle_download_piece(download_directory, meta_info, peers, file, piece, idx = 0):
    # extract the meta info from the torrent file

    # connect to the first peer and send the handshake message
    peer = Peer()
    peer_ip_port = get_peer_ip(peers[idx * 6:(idx+1) * 6]).split(":")
    peer_ip = peer_ip_port[0]
    peer_port = int(peer_ip_port[1])
    peer.connect(peer_ip, peer_port)
    peer.handshake(file, meta_info.info_hash, MY_PEER_ID)
    indexes_of_pieces = peer.bitfield_listen()

    if piece not in indexes_of_pieces:
        raise ValueError(f"Peer does not have piece {piece}")

    piece_length = meta_info.piece_length

    if piece == (len(meta_info.pieces) // 20) - 1:
        piece_length = meta_info.length % meta_info.piece_length

    block = peer.request_send(file, piece, piece_length)
    try:
        #append
        with open(f"{download_directory}", "r+b") as f:
            f.seek(piece * PIECE_LENGTH)
            f.write(block)
    except Exception as e:
        print(e)         


def main():
    command = sys.argv[1]
    if command == "info":
        torrent_file_name = sys.argv[2]
        handle_info(torrent_file_name)
    elif command == "download":
        assert sys.argv[2] == "-o", "Expected -o as the second argument"
        output_directory = sys.argv[3]
        torrent_file_name = sys.argv[4]
        handle_download(output_directory, torrent_file_name)
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()
