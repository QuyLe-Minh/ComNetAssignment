import socket    

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
        
    
def get_peer_ip(peer):
    return f"{peer[0]}.{peer[1]}.{peer[2]}.{peer[3]}:{peer[4]*256 + peer[5]}"    