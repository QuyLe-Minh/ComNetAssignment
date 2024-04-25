import hashlib
import time
import os

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
        
class MetaInfo:
    def __init__(self, data):
        self.announce = data["announce"]
        self.info = data["info"]
        self.length = self.info["length"]  # single file case
        self.files = None  # multi files case
        self.piece_length = self.info["piece length"]
        self.pieces = self.info["pieces"]
        self.info_hash = hashlib.sha1(Bencode.encode(self.info)).digest()   #the actual hash value of the data and returns it as a bytes object.
        self.info_hash_hex = self.info_hash.hex()   #from bytes to hexadecimal
        
    def get_piece_hashes(self):
        return [self.pieces[i : i + 20].hex() for i in range(0, len(self.pieces), 20)]  #20 bytes/piece
    
def create_torrent_file(directory, tracker):
    # Get all files in directory
    files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]

    # Create the file dictionary for each file
    file_dicts = []
    for file in files:
        print(file)
        file_size = os.path.getsize(os.path.join(directory, file))
        file_dicts.append({'length': file_size, 'path': [file]})

    # Create the info dictionary
    info = {
        'files': file_dicts,
        'name': directory,
        'piece length': 512 * 1024,  # 512KB
    }

    # Generate the pieces
    pieces = b''
    for file in files:
        with open(os.path.join(directory, file), 'rb') as f:
            while True:
                piece = f.read(512 * 1024)
                if not piece:
                    break
                pieces += hashlib.sha1(piece).digest()
    info['pieces'] = pieces

    # Create the torrent file content
    torrent = {
        'announce': tracker,
        'creation date': int(time.time()),
        'info': info
    }

    # Bencode the torrent file content
    torrent_bencoded = Bencode.encode(torrent)

    # Write the torrent file
    with open(directory + '.torrent', 'wb') as f:
        f.write(torrent_bencoded)
    