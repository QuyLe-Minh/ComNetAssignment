from bencode import Bencode
from metainfo import MetaInfo
from peer import PEER, PeerMessage
from utils import *
from tracker import Tracker

SERVER_PORT = 55555
LOCAL_PORT = 54321

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