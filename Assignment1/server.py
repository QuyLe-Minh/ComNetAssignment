from utilities import *
import threading
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
        self.peers = []

        for port in LOCAL_PORT:
            self.peers.append(socket.inet_aton(get_local_ip()) + struct.pack('!H', port))

        self.file_hash = {"test.txt": self.peers[0],
                          "swe.pdf": self.peers[1] + self.peers[4] + self.peers[2] + self.peers[3],
                          "cs229-linalg.pdf": self.peers[2] + self.peers[4],
                          "emnlp2014-depparser.pdf": self.peers[3] + self.peers[0],
                          "NLP.pdf": self.peers[0] + self.peers[1] + self.peers[3] + self.peers[4] + self.peers[2]
                          }
        
        self.multi_files_hash = {"data": [file for file in os.listdir("data")]}
        
    def add_peer(self, addr, file_name):
        ip, port = addr
        peer = socket.inet_aton(ip) + struct.pack('!H', port)
        self.file_hash[file_name] += peer
        
    def handle_get_request(self, conn, addr, request):
        GET_request = request.split(" ")[1]
        name = GET_request.split('&')[-1]
        file_name = name.split('=')[-1]
        peers = {}
        try:
            files = self.multi_files_hash[file_name]
            for file in files:
                peers[file] = self.file_hash[file]
                self.add_peer(addr, file)
        except:
            peers[file_name] = self.file_hash[file_name]
            self.add_peer(addr, file_name)


        param = {
            "complete": self.complete,
            "incomplete": self.incomplete,
            "interval": self.interval,
            "min_interval": self.min_interval,
            "address": socket.inet_aton(addr[0]) + struct.pack('!H', addr[1]),
            "peers": peers  # peers is dictionary no matter how many files
        }        
        
        param = Bencode.encode(param)   #encode to d type
        header = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n'
        response = header.encode("utf-8") + param
        conn.sendall(response)
        
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
            except KeyboardInterrupt:
                print("Server is shutting down...")
                conn.close()
                break
            except Exception:
                pass

if __name__=="__main__": 
    server = Server()
    server.listening()
                
    