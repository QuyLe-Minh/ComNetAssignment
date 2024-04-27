from .meta_info import *
from .utils import *

FILE_PATH = "test.txt"
SOURCE_PATH = "data"

CHOKE_ID = 0
UNCHOKE_ID = 1
INTERESTED_ID = 2
NOT_INTERESTED_ID = 3
HAVE_ID = 4
BITFIELD_ID = 5
REQUEST_ID = 6
PIECE_ID = 7
CANCEL_ID = 8

SERVER_PORT = 55555
LOCAL_PORT = [20386, 20387, 20388, 20389, 20390]
BLOCK_SIZE = 2**14 
PIECE_LENGTH = 512 * 1024