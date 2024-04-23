from utilities import *
from collections import OrderedDict, defaultdict

if __name__ == "__main__":
    multi_files_hash = OrderedDict(defaultdict(list))
    multi_files_hash["data"] = [file for file in os.listdir("data")]
    print([file for file in os.listdir("data")])
    print(multi_files_hash["hello"])
    # ip = get_local_ip()
    # print(ip)
    # create_torrent_file("data", f"http://{ip}:{SERVER_PORT}/announce")

# peer = socket.inet_aton('192.168.1.1') + struct.pack('!H', 6881) + socket.inet_aton('192.168.1.3') + struct.pack('!H', 55555)
# print(get_peer_ip(peer[6:]))
# response = requests.get("http://192.168.2.87:55555", params={"port":5555, "name": "QUYLE"})

# param = {
#     "complete": 1,
#     "incomplete": 2,
#     "interval": 3,
#     "min_interval": 4,
#     "peers": 5
# }
# print(str(Bencode.encode(param)))
# s = Bencode.encode(param)
# s = str(s)
# print(type(s))
# s = "hello its me " + s
# print(Bencode.encode(s))

# print(response.reason)
# print(response.content.decode())

# import urllib.parse

# request_line = "GET /?port=5555&name=QUYLE HTTP/1.1"
# parts = request_line.split(" ")
# method = parts[0]
# url = parts[1]
# version = parts[2]

# parsed_url = urllib.parse.urlparse(url)
# params = urllib.parse.parse_qs(parsed_url.query)

# print("Method:", method)
# print("URL:", url)
# print("Version:", version)
# print("Parameters:", params)