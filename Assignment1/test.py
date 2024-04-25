from utilities import *
from collections import OrderedDict, defaultdict

if __name__ == "__main__":
    # with open("test.txt", "r+b") as f:
    #     f.seek(4)
    #     f.write(b"hello")
    ip = get_local_ip()
    print(ip)
    create_torrent_file("data", f"http://{ip}:{SERVER_PORT}/announce")
