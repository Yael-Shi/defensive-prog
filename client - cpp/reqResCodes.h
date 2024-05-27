#pragma once

/*list of codes for each requst from client to server*/
const int REGISTRATION = 1025;
const int SEND_PUBLIC_KEY = 1026;
const int RE_CONNECT = 1027;
const int SEND_FILE = 1028;
const int VALID_CRC = 1029;
const int IVALID_CRC_SEND_AGAIN = 1030;
const int IVALID_CRC_QUIT = 1031;

/*list of codes for each response from server to client*/
const int REGIS_SUCC = 2100;
const int REGIS_FAIL = 2101;
const int RECEIVED_PUBLIC_KEY_SEND_AES = 2102;
const int RECEIVED_FILE_OK_CRC = 2103;
const int CONFIRM_RECEIPT_MSG = 2104;
const int CONFIRM_RECONNECT_SEND_AES = 2105;
const int RECONNECT_FAILED = 2106;
const int GENE_ERR = 2107;