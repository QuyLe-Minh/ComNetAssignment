# Local P2P bittorrent

A simple local P2P bittorrent with full operations from scratch, including create torrent files, seeding files and vice versa

# Workflow
![System Diagram](https://github.com/QuyLe-Minh/ComNetAssignment/assets/92782164/c5048101-5d25-47ff-ac41-61df7afa6246)

Server and Seeders will run all the time. They will receive message from Clients and handle it. Because of the complexity of the real-world Bittorrent, we will simplify our system a little bit and summarize it as follows:
- Server and Seeders start listening.
- Client make requests to Server to get list of active peers.
- For each file in list_of_files:
    + Make a handshake and get bitfield from list of peers.
    + Generate maximum MAX_WORKERS threads to download MAX_WORKERS pieces concurrently such that thread must connect to exclusive peer that is existed (one-to-one).

In our system, to simplify, we ignore some of protocols, such as choke message, unchoke message, have message, ... and modify **request-message prototype** to handle them properly. You should have a look at `main.py` to know details.

# Set up
## 1. Clone my repos and do some setup stuffs
- Make a cloned of my repository using the following command: 
```sh
git clone https://github.com/QuyLe-Minh/ComNetAssignment.git
cd ComNetAssignment/Assignment1
pip install -r requirements.txt
```

## 2. Configure parameters
All your parameters need tuning are in `utilities/__init__.py`. For some computers that can not host SERVER_PORT, simply change there and make some modifications in **tracker.get_peers** function in `main.py` or `download_using_strategy.py`.

## 3. Create a torrent file
- You must make your own torrent file including resources you want to share and send it to clients. In order to do it, you should migrate all your desired files into folder `data` and run:
```sh
python test.py
```

## 4. Simulate a bittorrent operations
- Just run the following code and follow the instructions:
```sh
chmod +x run.sh
./run.sh
```

- Or to experiment the behavior of the system with other computers in the network, you must have at least 2 roles/computers:
    + The first computer must run as a server (and seeders). You will need 2 terminals to run this:
    ```sh
    python server.py
    python client.py
    ```
    + The second computer acts as a client with only `main.py` or `download_using_strategy.py`. Then run as follows:
    ```sh
    python main.py download -o /path/to/your/destination /path/to/your/torrent
    ```
    or
    ```sh
    python download_using_trategy.py download -o /path/to/your/destination /path/to/your/torrent
    ```
## 5. Result
You are all done. Bittorrent and chill !!
