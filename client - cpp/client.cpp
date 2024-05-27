#include <filesystem>
#include <bitset>
#include "client.h"


Client::Client() : socket(io_context), aesWrapper() {
    requestData.version = CLIENT_VERSION;
    requestData.clientId = std::vector <uint8_t>(CLIENT_ID_SIZE, 0X0);
}

void Client::handleClient() {
    try {
        connectToServer();
        setClientName(); //setting client name for all requsts.
        std::pair<bool, std::string> result;
        if (checkFileExistence(CLIENT_INFO_FILE)) {
            setClientIDFromFile();
            result = handleTraffic([this]() { return this->reConnection(); }); //re-conneting to server in case client already registerd
        }
        else {
            result = handleTraffic([this]() { return this->registration(); }); //registration
            result = handleTraffic([this]() { return this->sendPublicKey(); }); //sending public key
        }
        setFileNameToSend(); //before starting to handle requests related to file, set its name
        result = handleTraffic([this]() { return this->sendingFile(); }); //request to send file
        bool crcsAreSame = compareCRCs();
        if (crcsAreSame) {
            result = handleTraffic([this]() { return this->handleCRC(VALID_CRC); });
        }
        else {
            int retry = 0;
            while (!crcsAreSame && retry < RETRY_SEND_CRC_WRONG) {
                result = handleTraffic([this]() { return this->handleCRC(IVALID_CRC_SEND_AGAIN); }); //crc is not valid, trying to send file again 
                result = handleTraffic([this]() { return this->sendingFile(); });
                crcsAreSame = compareCRCs();
                retry++;
            }
            if (!compareCRCs()) {
                result = handleTraffic([this]() { return this->handleCRC(IVALID_CRC_QUIT); }); //crc is not valid for fourth time, not trying again, just notify the server.
            }
            else {
                handleTraffic([this]() { return this->handleCRC(VALID_CRC); });
            }
        }
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "Connection error: " << e.what() << " \nPlease contact support at finalproject@defensive.com" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}

std::pair<bool, std::string> Client::handleTraffic(ActionFunction action) {
    std::string errorMsgToSend;
    std::string errorMsgToPrint = "Server responded with an error. Trying to send request again.";
    std::pair<bool, int > res;
    for (int attempt = 1; attempt <= ATTEMPTS_REACH_SRV; ++attempt) {
        res = action();

        if (res.first) {
            std::cout << ReqResDescriptions::getResponseDescription(responseData.srv_code) << std::endl;
            return { true, errorMsgToSend };
        }

        else {
            std::cout << "Action failed on attempt " << attempt << std::endl;
            errorMsgToSend = ReqResDescriptions::getResponseDescription(res.second);
            if (attempt < ATTEMPTS_REACH_SRV)
                std::cout << errorMsgToPrint << std::endl;
        }

        // Sleep for some time before retrying
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    throw FatalErrorException("Server responded with an Error for " + std::to_string(ATTEMPTS_REACH_SRV) + " times: \n" + errorMsgToSend + "\nExiting...");
}

void Client::sendRequest() {
    std::vector<char> req = packRequest(requestData);
    boost::asio::write(socket, boost::asio::buffer(req.data(), req.size()));
}

void Client::connectToServer() {
    std::vector<std::string> serverConfig = readServerConfig();
    if (serverConfig.size() == 2) {
        const char* address = serverConfig[0].c_str();
        const char* port = serverConfig[1].c_str();

        boost::asio::connect(socket, tcp::resolver(io_context).resolve(address, port));

    }
    else {
        throw FatalErrorException("Please make sure you have the needed file with all the requested details, and the file is accessible.");
    }
    std::cout << "connecting..." << std::endl;
}

std::vector<std::string> Client::readServerConfig() {
    std::vector<std::string> result;

    // Open the file
    std::ifstream file(CLIENT_INSTRC_FILE);

    if (!file.is_open()) {
        std::cerr << "Error opening file: " << CLIENT_INSTRC_FILE << std::endl;
        return result; // Return an empty vector
    }

    // Read the first line
    std::string line;
    if (std::getline(file, line)) {
        size_t colonPos = line.find(':'); // Find the position of the colon ':'

        if (colonPos != std::string::npos) {
            std::string addressStr = line.substr(0, colonPos);
            std::string portStr = line.substr(colonPos + 1);

            result.push_back(addressStr);
            result.push_back(portStr);
        }
        else {
            std::cerr << "Colon not found in the line: " << line << std::endl;
        }
    }
    else {
        std::cerr << "Error reading from file: " << CLIENT_INSTRC_FILE << std::endl;
    }

    file.close();

    return result;
}


/*Filling out the request struct according to the requested code*/
std::pair<bool, int> Client::registration() {
    setCode(REGISTRATION);
    std::cout << ReqResDescriptions::getRequestDescription(requestData.code) << std::endl;
    setPayload(std::vector<char>(clientName.begin(), clientName.end()));
    setPayloadSize(static_cast<uint32_t>(requestData.payload.size()));
    sendRequest();
    // Wait for the response from the server
    std::pair<bool, int> res = unpackResponse();
    return { res.first, res.second };
}

std::pair<bool, int> Client::sendPublicKey() {
    setCode(SEND_PUBLIC_KEY);
    std::cout << ReqResDescriptions::getRequestDescription(requestData.code) << std::endl;
    setAsymmetricalKeys();
    std::vector<char> combinedPayload(clientName.begin(), clientName.end());
    combinedPayload.insert(combinedPayload.end(), publicKey.begin(), publicKey.end());
    setPayload(combinedPayload);
    setPayloadSize(static_cast<uint32_t>(requestData.payload.size()));
    sendRequest();
    std::pair<bool, int> res = unpackResponse();
    return { res.first, res.second };
}

std::pair<bool, int> Client::reConnection() {
    setCode(RE_CONNECT);
    std::cout << ReqResDescriptions::getRequestDescription(requestData.code) << std::endl;
    std::vector<char> combinedPayload(clientName.begin(), clientName.end());
    setPayload(combinedPayload);
    setPayloadSize(static_cast<uint32_t>(requestData.payload.size()));
    sendRequest();
    std::pair<bool, int> res = unpackResponse();
    return { res.first, res.second };
}

std::pair<bool, int> Client::sendingFile() {
    setCode(SEND_FILE);
    std::cout << ReqResDescriptions::getRequestDescription(requestData.code) << std::endl;
    std::string encryptedFileContent = encryptFile();
    std::size_t encryptedFileContentSize = (encryptedFileContent.size());

    // Convert encryptedFileContentSize to a 4-byte little-endian representation
    std::vector<char> encrySizeInLittleEndian = toLittleEndian<std::uint32_t>(static_cast<std::uint32_t>(encryptedFileContentSize));

    // Convert fileNameToSend to bytes and pad it to FILE_NAME_MAX_SIZE bytes
    fileNameBytes.assign(fileNameToSend.begin(), fileNameToSend.end());
    fileNameBytes.resize(FILE_NAME_MAX_SIZE, '\0');

    std::vector<char> combinedPayload;
    combinedPayload.insert(combinedPayload.end(), encrySizeInLittleEndian.begin(), encrySizeInLittleEndian.end());
    combinedPayload.insert(combinedPayload.end(), fileNameBytes.begin(), fileNameBytes.end());
    combinedPayload.insert(combinedPayload.end(), encryptedFileContent.begin(), encryptedFileContent.end());
    setPayload(combinedPayload);
    setPayloadSize(static_cast<uint32_t>(requestData.payload.size()));
    sendRequest();
    std::pair<bool, int> res = unpackResponse();
    return { res.first, res.second };
}

std::pair<bool, int> Client::handleCRC(int code) {
    setCode(code);
    std::cout << ReqResDescriptions::getRequestDescription(requestData.code) << std::endl;
    if (code == IVALID_CRC_SEND_AGAIN) {
        return { true, GENE_ERR };  // Default values
    }
    fileNameBytes.assign(fileNameToSend.begin(), fileNameToSend.end());
    fileNameBytes.resize(FILE_NAME_MAX_SIZE, '\0');
    std::vector<char> combinedPayload;
    combinedPayload.insert(combinedPayload.end(), fileNameBytes.begin(), fileNameBytes.end());
    setPayload(combinedPayload);
    setPayloadSize(static_cast<uint32_t>(requestData.payload.size()));
    sendRequest();
    std::pair<bool, int> res = unpackResponse();
    return { res.first, res.second };
}

std::string Client::encryptFile() {
    std::ifstream inputFile(filePathToSend, std::ios::binary);
    if (!inputFile.is_open()) {
        std::cerr << "Error opening file: " << filePathToSend << std::endl;
        return "";
    }
    std::string fileContent((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    std::string encryptedContent = aesWrapper.encrypt(fileContent.c_str(), fileContent.length());
    return encryptedContent;
}

std::pair<bool, int> Client::unpackResponse() {
    std::pair<bool, int> result = { false, GENE_ERR };  // Default values

    // Read the header to get the payload size
    boost::asio::read(socket, boost::asio::buffer(&responseData.srv_version, sizeof(responseData.srv_version)));
    boost::asio::read(socket, boost::asio::buffer(&responseData.srv_code, sizeof(responseData.srv_code)));
    boost::asio::read(socket, boost::asio::buffer(&responseData.srv_payloadSize, sizeof(responseData.srv_payloadSize)));

    // Resize the payload vector to the received payload size
    responseData.srv_payload.resize(responseData.srv_payloadSize);

    // Read the variable-sized payload
    std::size_t bytesRead = 0;
    while (bytesRead < responseData.srv_payloadSize) {
        std::size_t chunkSize = std::min<std::size_t>(CHUNK_SIZE_TO_READ, responseData.srv_payloadSize - bytesRead);
        bytesRead += boost::asio::read(socket, boost::asio::buffer(responseData.srv_payload.data() + bytesRead, chunkSize));
    }
    // Check for error codes
    if (responseData.srv_code == REGIS_FAIL || responseData.srv_code == RECONNECT_FAILED || responseData.srv_code == GENE_ERR) {
        result.first = false;  // Failure
        result.second = responseData.srv_code;
    }
    else {
        result.first = handlePayloadContent();
    }
    return { result.first, result.second };
}

bool Client::handlePayloadContent() {
    if (responseData.srv_code == REGIS_SUCC) {
        return handleRegisSucc();
    }
    else if (responseData.srv_code == RECEIVED_PUBLIC_KEY_SEND_AES || responseData.srv_code == CONFIRM_RECONNECT_SEND_AES) {
        return handleReceivedPublicKeySendAes_ConfirmReconnectSendAes();
    }
    else if (responseData.srv_code == RECEIVED_FILE_OK_CRC) {
        return handleReceivedFileOKCRC();
    }
    else if (responseData.srv_code == CONFIRM_RECEIPT_MSG) {
        return handleConfirmReceiptMsg();
    }
    else {
        return false;
    }
}

// Handle REGIS_SUCC (2100) specific logic
bool Client::handleRegisSucc() {
    // Extract client ID from payload
    boost::uuids::uuid uuid;
    if (responseData.srv_payload.size() == CLIENT_ID_SIZE) {
        std::memcpy(uuid.data, responseData.srv_payload.data(), CLIENT_ID_SIZE);
        std::string uuidStr = boost::uuids::to_string(uuid);
        boost::erase_all(uuidStr, "-");

        // Convert UUID string to a const char* for setClientID
        const char* uuidStrCStr = uuidStr.c_str();
        setClientID(uuidStrCStr);
    }
    else {
        std::cerr << "Invalid binary data size." << std::endl;
        return false;
    }

    // Write to client info file
    std::ofstream meInfoFile(CLIENT_INFO_FILE);
    if (meInfoFile.is_open()) {
        meInfoFile << clientName << std::endl; // Write to the first line

        // Write the client ID in a readable format to the second line
        for (const auto& byte : requestData.clientId) {
            meInfoFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        meInfoFile << std::dec << std::endl;

        meInfoFile.close();
    }
    else {
        // Handle file opening error if needed
        std::cerr << "Error opening " << CLIENT_INFO_FILE << " file for writing." << std::endl;
        return false;
    }
    return true;
}

// Handle RECEIVED_PUBLIC_KEY_SEND_AES (2102) and CONFIRM_RECONNECT_SEND_AES (2105) specific logic, as response from server are the same
bool Client::handleReceivedPublicKeySendAes_ConfirmReconnectSendAes() {
    if (extractNCompareClientIdInPayload()) {
        size_t encryptedAESKeySize = responseData.srv_payload.size() - CLIENT_ID_SIZE;
        // Extract the binary data from responseData.srv_payload()
        const char* dataBegin = responseData.srv_payload.data() + CLIENT_ID_SIZE;
        const char* dataEnd = dataBegin + encryptedAESKeySize;

        if (responseData.srv_code == CONFIRM_RECONNECT_SEND_AES) {
            setPrivateKeyFromFile();
        }
        // Decrypt the AES key
        std::string decryptedAESKey = privateKeyPtr->decrypt(dataBegin, encryptedAESKeySize);
        // Convert the decryptedAESKey to an instance of AESWrapper
        aesWrapper = AESWrapper(reinterpret_cast<const unsigned char*>(decryptedAESKey.c_str()), decryptedAESKey.size());

        return true;
    }
    else {
        return false;
    }
}

// Handle RECEIVED_FILE_OK_CRC (2103) specific logic
bool Client::handleReceivedFileOKCRC() {
    if (extractNCompareClientIdInPayload()) {
        // handling here just the relevant parts from the server's payload
        std::string srvFileNameString(responseData.srv_payload.begin() + CLIENT_ID_SIZE + CONTENT_FILE_SIZE_IN_PROTOCAL,
            responseData.srv_payload.begin() + CLIENT_ID_SIZE + CONTENT_FILE_SIZE_IN_PROTOCAL + FILE_NAME_MAX_SIZE);
        srvFileNameString.erase(std::remove(srvFileNameString.begin(), srvFileNameString.end(), '\0'), srvFileNameString.end());
        if (srvFileNameString != fileNameToSend) {
            throw std::runtime_error("Received file name does not match expected file name");
        }
        std::vector<char> srvCRC_bytes(responseData.srv_payload.begin() + CLIENT_ID_SIZE + CONTENT_FILE_SIZE_IN_PROTOCAL + FILE_NAME_MAX_SIZE,
            responseData.srv_payload.begin() + CLIENT_ID_SIZE + CONTENT_FILE_SIZE_IN_PROTOCAL + FILE_NAME_MAX_SIZE + CRC_SIZE_IN_PROTOCAL);
        srvCRC = fromLittleEndian<int>(srvCRC_bytes);
        return true;
    }
    else {
        return false;
    }
}

// Handle CONFIRM_RECEIPT_MSG (2104) specific logic
bool Client::handleConfirmReceiptMsg() {
    if (extractNCompareClientIdInPayload()) {
        return true;
    }
    return false;
}

bool Client::extractNCompareClientIdInPayload() {
    if (responseData.srv_payload.size() >= CLIENT_ID_SIZE) {
        // Extract UUID from binary data
        boost::uuids::uuid uuid;
        std::memcpy(uuid.data, responseData.srv_payload.data(), CLIENT_ID_SIZE);
        std::string uuidStr = boost::uuids::to_string(uuid);
        boost::erase_all(uuidStr, "-");

        std::stringstream ss;
        for (uint8_t byte : requestData.clientId) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::string clientIdStr = ss.str();

        // Compare with the client ID
        return clientIdStr == uuidStr;
    }
    else {
        std::cerr << "Insufficient binary data size for UUID extraction." << std::endl;
        return false;
    }
}

void Client::setClientName() {
    std::string tmpClientName;
    std::ifstream clInfoFile(CLIENT_INFO_FILE);
    if (clInfoFile.is_open()) {
        if (!std::getline(clInfoFile, tmpClientName)) {
            clInfoFile.close();
            throw std::runtime_error("Error reading from file: " + CLIENT_INFO_FILE);
        }
        clInfoFile.close();
    }
    else {  // CLIENT_INFO_FILE does not exist, read from CLIENT_INSTRC_FILE
        std::ifstream instrcFile(CLIENT_INSTRC_FILE);

        if (!instrcFile.is_open()) {
            throw std::runtime_error("Error opening file: " + CLIENT_INSTRC_FILE);
        }

        for (int i = 0; i < CLIENT_NAME_LINE_INSTRC_FILE; ++i) {
            if (!std::getline(instrcFile, tmpClientName)) {
                instrcFile.close();
                throw std::runtime_error("Error reading from file: " + CLIENT_INSTRC_FILE);
            }
        }

        instrcFile.close();
        if (tmpClientName.empty()) {
            throw std::runtime_error("Client name not found in transfer.info");
        }
    }
    // Resize the clientName to 255 bytes (including null terminator)
    clientName = std::string(CLIENT_NAME_MAX_SIZE, '\0');

    // Copy the actual client name to clientName and ensure it doesn't exceed 255 bytes
    size_t copySize = std::min(tmpClientName.size(), CLIENT_NAME_MAX_SIZE - 1); // subtract 1 for null terminator
    std::copy_n(tmpClientName.begin(), copySize, clientName.begin());

    // Check the size of the client name
    if (clientName.size() > CLIENT_NAME_MAX_SIZE) {
        throw std::runtime_error("Client name exceeds maximum allowed size");
    }
}

std::string Client::getClientName() const {
    return clientName;
}

void Client::setAsymmetricalKeys() {
    privateKeyPtr = new RSAPrivateWrapper();
    RSAPublicWrapper publicKeyWrapper(privateKeyPtr->getPublicKey());
    publicKey = publicKeyWrapper.getPublicKey();
    Base64Wrapper base64Encoder;
    std::string privateKeyBase64 = base64Encoder.encode(privateKeyPtr->getPrivateKey());

    // Save private key to file priv.key
    std::ofstream privKeyFile(PRIVATE_KEY_FILE_NAME);

    if (!privKeyFile.is_open()) {
        throw std::runtime_error("Error opening file: " + PRIVATE_KEY_FILE_NAME);
    }

    privKeyFile << privateKeyBase64;
    privKeyFile.close();

    std::ofstream clientInfoFile(CLIENT_INFO_FILE, std::ios_base::app);  // Open in append mode
    if (!clientInfoFile.is_open()) {
        throw std::runtime_error("Error opening file: " + CLIENT_INFO_FILE);
    }

    clientInfoFile << privateKeyBase64 << std::endl;
    clientInfoFile.close();
}


void Client::setPrivateKeyFromFile() {
    std::ifstream privateKeyFile(PRIVATE_KEY_FILE_NAME);

    if (!privateKeyFile.is_open()) {
        throw std::runtime_error("Error opening private key file");
    }
    std::ostringstream privateKeyStream;
    privateKeyStream << privateKeyFile.rdbuf();  // Read the entire file into a stringstream
    std::string privateKeyContent = privateKeyStream.str();

    privateKeyFile.close();

    Base64Wrapper base64Decoder;
    std::string privateKeyBinary = base64Decoder.decode(privateKeyContent);

    privateKeyPtr = new RSAPrivateWrapper(privateKeyBinary);
}

void Client::setFileNameToSend() {
    std::ifstream file(CLIENT_INSTRC_FILE);

    if (!file.is_open()) {
        throw std::runtime_error("Error opening client instruction file");
    }

    std::string line;
    for (int i = 0; i < FILE_PATH_TO_SEND_LINE_INSTRC_FILE; ++i) {
        if (!std::getline(file, line)) {
            file.close();
            throw std::runtime_error("Error reading from " + std::string(CLIENT_INSTRC_FILE) + " file");
        }
    }
    file.close();

    if (line.empty()) {
        throw std::runtime_error("File path not found in line " + std::to_string(FILE_PATH_TO_SEND_LINE_INSTRC_FILE) +
            " of " + std::string(CLIENT_INSTRC_FILE) + " file, as it should be");
    }

    // Extract the entire line content
    filePathToSend = line;

    // Extract only the file name from the path
    size_t lastSeparatorPos = filePathToSend.find_last_of("/\\");
    if (lastSeparatorPos == std::string::npos) {
        throw std::runtime_error("Invalid file path format: " + filePathToSend);
    }

    fileNameToSend = filePathToSend.substr(lastSeparatorPos + 1);

    if (fileNameToSend.empty()) {
        throw std::runtime_error("Error extracting file name from the specified line");
    }

    if (fileNameToSend.size() > FILE_NAME_MAX_SIZE) {
        throw std::runtime_error("Error: File name size exceeds " + std::to_string(FILE_NAME_MAX_SIZE) + " bytes");
    }

    if (!checkFileExistence(fileNameToSend)) {
        throw std::runtime_error("File does not exist: " + fileNameToSend);
    }
}

std::string Client::getFileNameToSend() const {
    return fileNameToSend;
}

bool Client::checkFileExistence(const std::string& filePath) {
    return std::filesystem::exists(filePath);
}

void Client::setClientID(const char* newClientID) {
    const std::size_t expectedLength = requestData.clientId.size() * 2; // Two characters for each byte
    std::size_t len = std::min<std::size_t>(std::strlen(newClientID), expectedLength);

    // Convert the hex string to binary representation
    for (std::size_t i = 0; i < len / 2; ++i) {
        char byteString[3] = { newClientID[i * 2], newClientID[i * 2 + 1], '\0' };
        requestData.clientId[i] = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
    }
}

void Client::setClientIDFromFile() {
    std::ifstream file(CLIENT_INFO_FILE);

    if (!file.is_open()) {
        throw std::runtime_error("Error opening " + std::string(CLIENT_INSTRC_FILE) + " file");
    }

    std::string line;
    for (int i = 0; i < CLIENT_ID_LINE_INFO_FILE; ++i) {
        if (!std::getline(file, line)) {
            file.close();
            throw std::runtime_error("Error reading from " + std::string(CLIENT_INSTRC_FILE) + " file");
        }
    }

    // Reset the file pointer to the beginning
    file.clear();
    file.seekg(0, std::ios::beg);

    // Print all the content of the file together
    std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    file.close();

    if (line.empty()) {
        throw std::runtime_error("Error: Empty line in " + std::string(CLIENT_INSTRC_FILE) + " file");
    }

    line.erase(std::remove(line.begin(), line.end(), '-'), line.end());

    // Calculate the size of the string in bytes (each two hex characters represent 1 byte), as uuid definition
    std::size_t sizeInBytes = line.size() / 2;

    if (sizeInBytes > CLIENT_ID_SIZE) {
        throw std::runtime_error("Error: Client ID size exceeds " + std::to_string(CLIENT_ID_SIZE) + " bytes");
    }
    setClientID(line.c_str());
}

void Client::setCode(uint16_t newCode) {
    requestData.code = newCode;
}

void Client::setPayloadSize(uint32_t newPayloadSize) {
    requestData.payloadSize = newPayloadSize;
}

void Client::setPayload(const std::vector<char>& newPayload) {
    // Resize the payload to the size of the new payload
    requestData.payload.resize(newPayload.size());

    // Copy the payload content
    std::copy_n(newPayload.begin(), newPayload.size(), requestData.payload.begin());
}

void Client::setPayloadString(const std::string& payloadString) {
    requestData.payload.clear();
    requestData.payload.insert(requestData.payload.end(), payloadString.begin(), payloadString.end());
}

const Request& Client::getRequestData() const {
    return requestData;
}

std::vector<char> Client::packRequest(const Request& data) {
    std::vector<char> buffer(data.clientId.size() + sizeof(data.version) + sizeof(data.code) +
        sizeof(data.payloadSize) + data.payload.size());

    // Copy clientId into buffer
    memcpy(buffer.data(), data.clientId.data(), data.clientId.size());

    // Copy version, code, and payloadSize into buffer in little-endian format
    auto versionBytes = toLittleEndian(data.version);
    auto codeBytes = toLittleEndian(data.code);
    auto payloadSizeBytes = toLittleEndian(data.payloadSize);

    memcpy(buffer.data() + data.clientId.size(), versionBytes.data(), sizeof(data.version));
    memcpy(buffer.data() + data.clientId.size() + sizeof(data.version), codeBytes.data(), sizeof(data.code));
    memcpy(buffer.data() + data.clientId.size() + sizeof(data.version) + sizeof(data.code), payloadSizeBytes.data(), sizeof(data.payloadSize));
    memcpy(buffer.data() + data.clientId.size() + sizeof(data.version) + sizeof(data.code) + sizeof(data.payloadSize), data.payload.data(), data.payload.size());

    return buffer;
}

bool Client::compareCRCs() {
    std::string clCheckSum = readfile(fileNameToSend);
    std::size_t firstSpacePos = clCheckSum.find(' ');
    std::string clCRCString = clCheckSum.substr(0, firstSpacePos);
    uint32_t clCRC = std::stoul(clCRCString, nullptr, 10);
    return srvCRC == clCRC;
}

