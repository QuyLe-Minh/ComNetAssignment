from utilities import *
import threading
import urllib
import struct

class Server:
    def __init__(self):
        self.port = 55555
        self.host = get_local_ip()
        print(f"Server IP: {self.host}")
        print("Server is listening on port 55555...")
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the server to the host and port
        self.server.bind((self.host, self.port))
        self.server.settimeout(1)
        self.server.listen()
        
        self.complete = 1
        self.incomplete = 0
        self.interval = 60
        self.min_interval = 60
        self.peers = socket.inet_aton(get_local_ip())+ struct.pack('!H', LOCAL_PORT)
        
    def add_peer(self, addr):
        ip, port = addr
        peer = socket.inet_aton(ip) + struct.pack('!H', port)
        self.peers += peer
        
    def handle_client_request(self, conn, addr):
        self.add_peer(addr)
        request = conn.recv(1024).decode()
        parts = request.split(" ")
        _, url, _ = parts[0], parts[1], parts[2]
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)    # I dunno wtf is this
        
        param = {
            "complete": self.complete,
            "incomplete": self.incomplete,
            "interval": self.interval,
            "min_interval": self.min_interval,
            "peers": self.peers
        }
        param = Bencode.encode(param)   #encode to d type
        header = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n'
        response = header.encode("utf-8") + param
        conn.sendall(response)
        conn.close()
        
    def listening(self):
        while True:
            try:
                conn, addr = self.server.accept()
                print("HI CLIENT")
                thread = threading.Thread(target=self.handle_client_request, args=(conn, addr))
                thread.start()
            except:
                pass

if __name__=="__main__":  
    server = Server()
    server.listening()
                
    