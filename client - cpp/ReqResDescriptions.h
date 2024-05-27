#pragma once

#include <string>
#include "reqResCodes.h"

// Requests
const std::string REGISTRATION_REQUEST_DESC = "Attempting to register with the server...";
const std::string SEND_PUBLIC_KEY_REQUEST_DESC = "Attempting to send public key to the server...";
const std::string RE_CONNECT_REQUEST_DESC = "Attempting to re-connect to the server...";
const std::string SEND_FILE_REQUEST_DESC = "Attempting to send the file to the server...";
const std::string VALID_CRC_REQUEST_DESC = "Attempting to handle CRC from the server...";
const std::string IVALID_CRC_SEND_AGAIN_REQUEST_DESC = "Attempting to handle wrong CRC from the server...";
const std::string IVALID_CRC_QUIT_REQUEST_DESC = "Attempting to handle wrong CRC for fourth time from the server...";
const std::string DEFAULT_REQUEST_DESC = "Unknown request description";


// Responses
const std::string REGIS_SUCC_RESPONSE_DESC = "Registration done successfully!";
const std::string REGIS_FAIL_RESPONSE_DESC = "Error " + std::to_string(REGIS_FAIL) + ": Registration failed. Change your user-name and try again.";
const std::string RECEIVED_PUBLIC_KEY_RESPONSE_DESC = "Received public key from the server successfully!";
const std::string RECEIVED_FILE_OK_CRC_RESPONSE_DESC = "Received file information from the server successfully!";
const std::string CONFIRM_RECEIPT_MSG_RESPONSE_DESC = "The connection process with the server has ended. Disconnecting.";
const std::string CONFIRM_RECONNECT_SEND_AES_RESPONSE_DESC = "Re-connection done successfully!";
const std::string RECONNECT_FAILED_RESPONSE_DESC = "Error " + std::to_string(RECONNECT_FAILED) + ": Request to reconnect has been rejected (you are not registered or your public key is incorrect). \nPlease try to register again as a new user.";
const std::string GENE_ERR_RESPONSE_DESC = "Error " + std::to_string(GENE_ERR) + ": This is a general error. \nPlease contact support at finalproject@defensive.com";
const std::string DEFAULT_RESPONSE_DESC = "Unknown response description";


class ReqResDescriptions {
public:
	static std::string getRequestDescription(int);
	static std::string getResponseDescription(int);
};
