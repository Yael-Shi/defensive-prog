#include "ReqResDescriptions.h"


std::string ReqResDescriptions::getRequestDescription(int requestCode) {
    switch (requestCode) {
    case REGISTRATION:
        return REGISTRATION_REQUEST_DESC;
    case SEND_PUBLIC_KEY:
        return SEND_PUBLIC_KEY_REQUEST_DESC;
    case RE_CONNECT:
        return RE_CONNECT_REQUEST_DESC;
    case SEND_FILE:
        return SEND_FILE_REQUEST_DESC;
    case VALID_CRC:
        return VALID_CRC_REQUEST_DESC;
    case IVALID_CRC_SEND_AGAIN:
        return IVALID_CRC_SEND_AGAIN_REQUEST_DESC;
    case IVALID_CRC_QUIT:
        return IVALID_CRC_QUIT_REQUEST_DESC;
    default:
        return DEFAULT_REQUEST_DESC;
    }
}


std::string ReqResDescriptions::getResponseDescription(int responseCode) {
    switch (responseCode) {
    case REGIS_SUCC:
        return REGIS_SUCC_RESPONSE_DESC;
    case REGIS_FAIL:
        return REGIS_FAIL_RESPONSE_DESC;
    case RECEIVED_PUBLIC_KEY_SEND_AES:
        return RECEIVED_PUBLIC_KEY_RESPONSE_DESC;
    case RECEIVED_FILE_OK_CRC:
        return RECEIVED_FILE_OK_CRC_RESPONSE_DESC;
    case CONFIRM_RECEIPT_MSG:
        return CONFIRM_RECEIPT_MSG_RESPONSE_DESC;
    case CONFIRM_RECONNECT_SEND_AES:
        return CONFIRM_RECONNECT_SEND_AES_RESPONSE_DESC;
    case RECONNECT_FAILED:
        return RECONNECT_FAILED_RESPONSE_DESC;
    case GENE_ERR:
        return GENE_ERR_RESPONSE_DESC;
    default:
        return DEFAULT_RESPONSE_DESC;
    }
}
