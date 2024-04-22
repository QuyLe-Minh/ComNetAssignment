from utilities import *
import threading
import urllib
import struct

class Server:
    def __init__(self):
        self.port = SERVER_PORT
        self.host = get_local_ip()
        print(f"Server IP: {self.host}")
        print(f"Server is listening on port {self.port}...")
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
        
        self.file_hash = {"test.txt": self.peers,
                          "swe.pdf": self.peers}
        
    def add_peer(self, addr, file_name):
        ip, port = addr
        peer = socket.inet_aton(ip) + struct.pack('!H', port)
        self.file_hash[file_name] += peer
        
    def handle_get_request(self, conn, addr, request):
        GET_request = request.split(" ")[1]
        name = GET_request.split('&')[-1]
        file_name = name.split('=')[-1]
        files = ""
        
        peers = [self.file_hash[file] for file in files]
        param = {
            "complete": self.complete,
            "incomplete": self.incomplete,
            "interval": self.interval,
            "min_interval": self.min_interval,
            "peers": peers
        }        
        
        param = Bencode.encode(param)   #encode to d type
        header = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n'
        response = header.encode("utf-8") + param
        conn.sendall(response)
        
        self.add_peer(addr, file_name)
        
    def handle_client_request(self, conn, addr):
        request = conn.recv(1024).decode("utf-8")
        command = request.split(" ")[0]
        if command == "GET":
            self.handle_get_request(conn, addr, request)
    
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
                
    