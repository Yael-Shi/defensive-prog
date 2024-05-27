from enum import Enum


PORT_FILE_NAME = "port.info"
DEFAULT_PORT_NUM = 1357
HOST = ''  # determined by the customer
FORMAT = '[%(levelname)s - %(asctime)s - %(filename)s:%(lineno)d:%(funcName)s]: %(msg)s' #for logging msgs

DB_NAME = "defensive.db"
FILES_RECEIVED_DIR = "files_recived"
SRV_VERSION = 3
MAX_NUM_QUEUED_CONN = 10 
CHUNK_SIZE_TO_READ = 4096

class Protocol_sizes(Enum):
    CRC_SIZE_IN_PROTOCAL = 4
    CONTENT_FILE_SIZE_IN_PROTOCAL = 4
    PAYLOAD_SIZE_IN_PROTOCAL = 4
    VERSION_SIZE_IN_PROTOCOL = 1


class Cl_locs_sizes(Enum):
    HEADER_SIZE = 23
    LOC_OF_CLIENT_ID = 0
    SIZE_OF_CLIENT_ID = 16
    LOC_OF_VERSION = 16
    LOC_OF_CODE = 17
    LOC_OF_PL_SIZE = -4  # location for the end of the msg haeder
    
    #locations of vars in the payload
    LOC_OF_PUBLICKEY = 255

class File_Handling_locs_sizes(Enum):
    FILE_NAME_SIZE = 255;
    CONTENT_FILE_SIZE = 4

class Incoming_req_code(Enum):
    REGISTRATION = 1025
    SEND_PUBLIC_KEY = 1026
    RE_CONNECT = 1027
    SEND_FILE = 1028
    VALID_CRC = 1029
    IVALID_CRC_SEND_AGAIN = 1030
    IVALID_CRC_QUIT = 1031


class Outgoing_res(Enum):
    REGIS_SUCC = 2100
    REGIS_FAIL = 2101
    RECEIVED_PUBLIC_KEY_SEND_AES = 2102
    RECEIVED_FILE_OK_CRC = 2103
    CONFIRM_RECEIPT_MSG = 2104
    CONFIRM_RECONNECT_SEND_AES = 2105
    RECONNECT_FAILED = 2106
    GENE_ERR = 2107
