#pragma once

#include <array>
#include <boost/asio.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/algorithm/string/erase.hpp>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>
#include <utility>
#include "ReqResDescriptions.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "cksum_new.h"
#include "fatalErrorException.h"

using boost::asio::ip::tcp;
using ActionFunction = std::function<std::pair<bool, int>()>;


const std::string CLIENT_INSTRC_FILE = "transfer.info";
//ip and port in line 1
const int CLIENT_NAME_LINE_INSTRC_FILE = 2;
const int FILE_PATH_TO_SEND_LINE_INSTRC_FILE = 3;

const std::string CLIENT_INFO_FILE = "me.info";
const int CLIENT_NAME_LINE_INFO_FILE = 1;
const int CLIENT_ID_LINE_INFO_FILE = 2;
const int PRIVATE_KEY_LINE_INFO_FILE = 3;

const std::string PRIVATE_KEY_FILE_NAME = "priv.key";

const int CLIENT_VERSION = 3;
const int CLIENT_ID_SIZE = 16;
const size_t CLIENT_NAME_MAX_SIZE = 255;
const size_t FILE_NAME_MAX_SIZE = 255;
const std::size_t ENCRYPTED_CONTENT_FILE_SIZE = std::numeric_limits<std::uint32_t>::max(); //the range the contet size can be
const int ATTEMPTS_REACH_SRV = 4;
const int RETRY_SEND_CRC_WRONG = 3; //When crc from the server is diff from that of the client, try sending again up to 3 times
const int CHUNK_SIZE_TO_READ = 4096;

//sizes of values which sent to/from server
const int CONTENT_FILE_SIZE_IN_PROTOCAL = 4;
const int CRC_SIZE_IN_PROTOCAL = 4;

struct Request {
    std::vector<uint8_t> clientId;
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
    std::vector<char> payload;
};

struct Response {
    uint8_t srv_version;
    uint16_t srv_code;
    uint32_t srv_payloadSize;
    std::vector<char> srv_payload;
};

class Client {
public:
    RSAPrivateWrapper* privateKeyPtr;
    std::string publicKey;
    Client();  // Constructor
    void handleClient();

    /*setters and getters*/
    void setClientID(const char*);
    void setClientIDFromFile();
    void setCode(uint16_t);
    void setPayloadSize(uint32_t);
    void setPayload(const std::vector<char>&);
    void setPayloadString(const std::string&);
    void setClientName();
    std::string getClientName() const;
    void setAsymmetricalKeys();
    void setPrivateKeyFromFile();
    void setFileNameToSend();
    std::string getFileNameToSend() const;
    const Request& getRequestData() const;

    std::pair<bool, std::string> handleTraffic(ActionFunction);
    std::pair<bool, int> registration();
    std::pair<bool, int> sendPublicKey();
    std::pair<bool, int> reConnection();
    std::pair<bool, int> sendingFile();
    std::pair<bool, int> handleCRC(int);
    std::vector<char> packRequest(const Request&);
    void connectToServer();
    friend std::string readfile(const std::string&);

private:
    boost::asio::io_context io_context;
    tcp::socket socket;
    std::string clientName;
    AESWrapper aesWrapper;
    uint64_t contentSize;
    std::string filePathToSend;
    std::string fileNameToSend;
    Request requestData;
    Response responseData;
    std::vector<char> fileNameBytes;
    uint32_t srvCRC;
    uint32_t clCRC;

    std::vector<std::string> readServerConfig();
    void sendRequest();
    std::pair<bool, int> unpackResponse();
    bool handlePayloadContent();
    bool handleRegisSucc();
    bool handleReceivedPublicKeySendAes_ConfirmReconnectSendAes();
    bool handleReceivedFileOKCRC();
    bool handleConfirmReceiptMsg();
    bool extractNCompareClientIdInPayload();
    bool checkFileExistence(const std::string&);
    std::string encryptFile();
    bool compareCRCs();

    /*Helper function to convert a value to little-endian format*/ 
    template <typename T>
    static std::vector<char> toLittleEndian(const T& value) {
        std::vector<char> result(sizeof(T));
        for (size_t i = 0; i < sizeof(T); ++i) {
            result[i] = static_cast<char>((value >> (8 * i)) & 0xFF);
        }
        return result;
    }

    // Helper function to convert a little-endian buffer to a value
    template <typename T>
    static T fromLittleEndian(const std::vector<char>& buffer, size_t offset = 0) {
        T result = 0;
        for (size_t i = 0; i < sizeof(T); ++i) {
            result |= static_cast<T>(static_cast<unsigned char>(buffer[offset + i])) << (8 * i);
        }
        return result;
    }
};
