import requests

class Tracker:
    def __init__(self, announce_url):
        self.announce_url = announce_url
    def get_peers(
        self,
        info_hash: bytes,
        peer_id: str,
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
            },
        )
        return response #type->bytes