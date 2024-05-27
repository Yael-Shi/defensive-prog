import logging
import socket
import struct
import threading
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto import Random

import cksum
import utils
from client_state import ClientState
from sql_mangr import DbManager
from constants import *
from custom_exceptions import *


logging.basicConfig(
    format=FORMAT,
    level=logging.INFO,
    datefmt='%H:%M:%S')


class Server:
    def __init__(self, port: int) -> None:
        """
        Initialize the Server instance.
	    """
        self.host = HOST
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.db = DbManager()
        self.client_states = {}  # Dictionary to store ClientState instances for each client connection
               
    def start(self) -> None:
        """
        Start the server and listen for incoming connections.
        """
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(MAX_NUM_QUEUED_CONN)
            logging.info(f"Server listening on {self.host}:{self.port}")

            while True:
                try:
                    conn, addr = self.server_socket.accept()
                except Exception as ex:
                    logging.error(f"Error accepting connection: {ex}")
                    self.cleanup_client_connection(conn)
                    continue  # Continue to the next iteration or add other appropriate handling
                logging.info(f"Accepted connection from {addr}")

                # Create a new ClientState instance for each client conn
                client_state = ClientState()
                self.client_states[conn] = (client_state, addr)
                threading.Thread(target=self.server_logic, args=(conn, client_state, addr)).start()
                
        except Exception as ex:
            logging.error(f"Error binding socket: {ex}")
            self.cleanup_and_exit()
            
    def cleanup_and_exit(self) -> None:
        """
        Cleanup resources and exit the server.
        """
        logging.info("Closing server socket and exiting...")
        self.server_socket.close()
        self.db.close_connection()  # Close the database connection
        exit()

    def server_logic(self, conn, client_state, addr) -> None:
        """
        Logic to handle communication with a client.

        Parameters:
        - conn: The client's connection socket.
        - client_state: An instance of ClientState representing the client's state.
        - addr: The client's address.
        """
        client_state.conn = conn
        try:
            while True:
                try:
                    client_state.cl_header_data = conn.recv(Cl_locs_sizes.HEADER_SIZE.value)
                    if not client_state.cl_header_data:
                        raise ConnectionResetError("Connection closed by client")
                    if len(client_state.cl_header_data) < Cl_locs_sizes.HEADER_SIZE.value:
                        raise IncompleteHeader("Incomplete header received")

                    # Unpack the header
                    self.extract_cl_id(client_state)
                    client_state.cl_payload_size = struct.unpack("<I", client_state.cl_header_data[Cl_locs_sizes.LOC_OF_PL_SIZE.value:])[0]
                    client_state.cl_payload_data = b''
                    while len(client_state.cl_payload_data) < client_state.cl_payload_size:
                        chunk = conn.recv(min(CHUNK_SIZE_TO_READ, client_state.cl_payload_size - len(client_state.cl_payload_data)))
                        if not chunk:
                            raise IncompletePayload("Unable processing payload")
                        client_state.cl_payload_data += chunk

                    self.unpack_req(client_state)
                except IncompleteHeader as ex:
                    logging.error(f"Error in getting header data: {ex}")
                    client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
                    self.send_response(client_state)
                    self.cleanup_client_connection(conn)  # Optionally close the connection for this specific client
                except IncompletePayload as ex:
                    logging.error(f"Error in getting payload data: {ex}")
                    client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
                    self.send_response(client_state)
                    self.cleanup_client_connection(conn)  # Optionally close the connection for this specific client
        except ConnectionResetError:
            logging.info(f"Client at {addr} disconnected.")
            self.cleanup_client_connection(conn)
            del self.client_states[conn]  # Remove the client from the clients dict

    def cleanup_client_connection(self, conn) -> None:
        """
        Perform cleanup steps for a client connection that encountered an error.
        Close the connection and any other necessary cleanup actions.

        Parameters:
        - conn: The client's connection socket.
        """
        try:
            logging.warning(f"Cleaning up connection for {conn.getpeername()}")
            conn.close()
        except Exception as ex:
            logging.error(f"Error during cleanup for {conn.getpeername()}: {ex}")

    def extract_cl_id(self, client_state) -> None:
        """
        Extract and set the client ID from the header data.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        packed_data = client_state.cl_header_data[:Cl_locs_sizes.SIZE_OF_CLIENT_ID.value]
        unpack_result = struct.unpack(">QQ", packed_data)
        hex_str_1 = format(unpack_result[0], '016x')
        hex_str_2 = format(unpack_result[1], '016x')
        hex_result = hex_str_1 + hex_str_2
                
        if (client_state.cl_id is None) and (hex_result != "0" * len(hex_result)):
            client_state.cl_id = hex_result

    def unpack_req(self, client_state) -> None:
        """
        Unpack the client's request from the header data.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        if client_state.cl_id is None:
            self.extract_cl_id(client_state)
        client_state.cl_version = struct.unpack("<B", client_state.cl_header_data[Cl_locs_sizes.LOC_OF_VERSION.value:Cl_locs_sizes.LOC_OF_CODE.value])[0]
        client_state.cl_code = struct.unpack("<H", client_state.cl_header_data[Cl_locs_sizes.LOC_OF_CODE.value:Cl_locs_sizes.LOC_OF_PL_SIZE.value])[0]
        logging.info(f"Handling request {Incoming_req_code(client_state.cl_code)} from client {client_state.cl_name}")
        self.handle_req_code(client_state)

    def handle_req_code(self, client_state) -> None:
        """
        Handle the client's request based on the request code.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        if client_state.cl_code != Incoming_req_code.REGISTRATION.value:
            self.db.update_last_seen(client_state.cl_id)

        if client_state.cl_code == Incoming_req_code.REGISTRATION.value:
            self.registration(client_state)
        elif client_state.cl_code == Incoming_req_code.SEND_PUBLIC_KEY.value:
            self.public_key(client_state)
        elif client_state.cl_code == Incoming_req_code.RE_CONNECT.value:
            self.re_connect(client_state)
        elif client_state.cl_code == Incoming_req_code.SEND_FILE.value:
            self.send_file(client_state)
        elif client_state.cl_code == Incoming_req_code.VALID_CRC.value:
            self.valid_crc(client_state)
        elif client_state.cl_code == Incoming_req_code.IVALID_CRC_SEND_AGAIN.value:
            # according to the protocol, the IVALID_CRC_SEND_AGAIN is more of a message than a request. meaning, no response is sent back.
            return  
        elif client_state.cl_code == Incoming_req_code.IVALID_CRC_QUIT.value:
            self.invalid_crc_quit(client_state)
        else:
            client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
            self.send_response(client_state)

    def registration(self, client_state) -> None:
        """
        Handle the client's registration request.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        try:
            cl_name = client_state.cl_payload_data.decode('utf-8')
            if not self.db.validate_name(cl_name):
                client_state.set_srv_code(Outgoing_res.REGIS_FAIL.value)
                raise NameExistsException("The name already exists in the system")
            
        except NameExistsException as ex:
            logging.error(f"Error during registration: {ex}")
            client_state.set_srv_code(Outgoing_res.REGIS_FAIL.value)
        except Exception as ex:
            logging.error(f"Error in registration due to {ex}")
            client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
        else:
            client_state.set_cl_name(cl_name)
            client_state.set_cl_id()
            self.db.add_client(client_state.cl_id, cl_name)
            logging.info("Finish registration in DB")

            # Set all values for response:
            client_state.set_srv_code(Outgoing_res.REGIS_SUCC.value)
            client_state.set_srv_payload_data(client_state.cl_id_binary)
        finally:
            self.send_response(client_state)

    def public_key(self, client_state) -> None:
        """
        Handle the client's public key exchange request.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        try:
            client_name = client_state.cl_payload_data[:Cl_locs_sizes.LOC_OF_PUBLICKEY.value].decode('utf-8')
            if not self.db.check_matching_client_name_and_id(client_name, client_state.cl_id):
                raise NoClientNameMatchIDException(f"Found no clientID for client name {client_name}")
            client_state.public_key = client_state.cl_payload_data[Cl_locs_sizes.LOC_OF_PUBLICKEY.value:]
            client_state.aes_key = self.generate_aes_key()
            self.db.update_public_key_and_aes(client_state.cl_id, client_state.public_key, client_state.aes_key)
            encrypted_aes_key = self.encrypt_aes_key(client_state.aes_key, client_state.public_key)

            # Set all values for response
            client_state.set_srv_code(Outgoing_res.RECEIVED_PUBLIC_KEY_SEND_AES.value)
            client_state.set_srv_payload_data(client_state.cl_id_binary, encrypted_aes_key)
            
        except NoClientNameMatchIDException as ex:
            logging.error(ex)
            client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
        except Exception as ex:
            logging.error(f"Error while processing AES/RSA keys due to {ex}")
            client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
        finally:
            self.send_response(client_state)

    def re_connect(self, client_state) -> None:
        """
        Handle the client's reconnection request.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        try:
            client_name = client_state.cl_payload_data[:Cl_locs_sizes.LOC_OF_PUBLICKEY.value].decode('utf-8')

            if not self.db.check_matching_client_name_and_id(client_name, client_state.cl_id):
                raise NoClientNameMatchIDException(f"Found no clientID for client name {client_name}")
            client_state.set_cl_id_binary()
            # Set all values for response
            if not client_state.aes_key:
                client_state.aes_key = self.db.get_aes_key_by_id(client_state.get_cl_id())
            if not client_state.public_key:
                client_state.public_key = self.db.get_public_key_by_id(client_state.get_cl_id())
            encrypted_aes_key = self.encrypt_aes_key(client_state.aes_key, client_state.public_key)
            client_state.set_srv_code(Outgoing_res.CONFIRM_RECONNECT_SEND_AES.value)
            client_state.set_srv_payload_data(client_state.cl_id_binary, encrypted_aes_key)

        except NoClientNameMatchIDException as ex:
            logging.error(ex)
            client_state.set_srv_code(Outgoing_res.RECONNECT_FAILED.value)
            client_state.set_srv_payload_data(client_state.cl_id_binary)
        except Exception as ex:
            logging.error(f"Error while processing AES/RSA keys due to {ex}")
            client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
        finally:
            self.send_response(client_state)
            
    def send_file(self, client_state) -> None:
        """
        Handle the client's file sending request.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        try:
            content_file_size_bytes = client_state.cl_payload_data[:File_Handling_locs_sizes.CONTENT_FILE_SIZE.value]
            content_file_size = int.from_bytes(content_file_size_bytes, byteorder='little')
            file_name_bytes = client_state.cl_payload_data[File_Handling_locs_sizes.CONTENT_FILE_SIZE.value: 
                                                            File_Handling_locs_sizes.CONTENT_FILE_SIZE.value + 
                                                            File_Handling_locs_sizes.FILE_NAME_SIZE.value]
            client_state.file_name = utils.remove_null_character(file_name_bytes.decode('utf-8'))
            encrypted_file_content = client_state.cl_payload_data[File_Handling_locs_sizes.CONTENT_FILE_SIZE.value + 
                                                                        File_Handling_locs_sizes.FILE_NAME_SIZE.value:]
            aes_cipher = AES.new(client_state.aes_key, AES.MODE_CBC, iv=bytes(16))
            file_content = unpad(aes_cipher.decrypt(encrypted_file_content), AES.block_size)
            file_content_str = utils.remove_null_character(file_content.decode('utf-8'))
            path_to_save_file = os.path.join(os.path.dirname(__file__), FILES_RECEIVED_DIR, client_state.cl_id, client_state.file_name)
            directory = os.path.dirname(path_to_save_file)
            os.makedirs(directory, exist_ok=True)
            with open(path_to_save_file, 'w') as file:
                file.write(file_content_str)

            # add record in db for the new file
            self.db.add_file(client_state.cl_id, client_state.file_name, path_to_save_file)
            checksum = cksum.readfile(path_to_save_file)
            checksum_list = checksum.split('\t')
            crc = int(checksum_list[0])
            # Set all values for response
            client_state.set_srv_code(Outgoing_res.RECEIVED_FILE_OK_CRC.value)
            aes_cipher = AES.new(client_state.aes_key, AES.MODE_CBC, iv=bytes(16))
            with open(path_to_save_file, 'r') as file:
                file_content_to_encrypt = file.read()
            file_content_to_encrypte_byte = file_content_to_encrypt.encode('utf-8')
            content_file_size_byte = utils.to_little_endian(len(aes_cipher.encrypt(pad(file_content_to_encrypte_byte, AES.block_size))), Protocol_sizes.CONTENT_FILE_SIZE_IN_PROTOCAL.value)
            crc_bytes = utils.to_little_endian(crc, Protocol_sizes.CRC_SIZE_IN_PROTOCAL.value)
            
            client_state.set_srv_payload_data(client_state.cl_id_binary, content_file_size_byte, file_name_bytes, crc_bytes)    
        except FileReceivingException as ex:
            logging.error(ex)
            client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
        except Exception as ex:
            logging.error(f"Error while handling received file due to {ex}")
            client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
        finally:
            self.send_response(client_state)

    def valid_crc(self, client_state) -> None:
        """
        Handle the client's confirmation CRC is valid request.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        try:
            file_name_bytes = client_state.cl_payload_data[:File_Handling_locs_sizes.FILE_NAME_SIZE.value]
            file_name_decode = file_name_bytes.decode('utf-8').rstrip('\x00')  # Assuming UTF-8 encoding and remove null bytes
            if file_name_decode != client_state.file_name:
                raise FileNameNotMatchException("The received file name does not much the one in the database, please check your request' details")
            
            # update record in db with verified CRC
            verified = True
            self.db.update_file_verification(client_state.cl_id, client_state.file_name, verified)

            # Set all values for response
            client_state.set_srv_code(Outgoing_res.CONFIRM_RECEIPT_MSG.value)
            client_state.set_srv_payload_data(client_state.cl_id_binary)
    
        except FileNameNotMatchException as ex:
            logging.error(ex)
            client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
        except Exception as ex:
            logging.error(f"Error while handling received crc due to {ex}")
            client_state.set_srv_code(Outgoing_res.GENE_ERR.value)
        finally:
            self.send_response(client_state)

    def invalid_crc_quit(self, client_state) -> None:
        """
        Handle the client's msg that crc is invalid and quit request.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        try:
            file_name_bytes = client_state.cl_payload_data[:File_Handling_locs_sizes.FILE_NAME_SIZE.value]
            file_name_decode = file_name_bytes.decode('utf-8').rstrip('\x00')  # Assuming UTF-8 encoding and remove null bytes
            if file_name_decode != client_state.file_name:
                raise FileNameNotMatchException("The received file name does not much the one in the database, please check your request' details")

            # Set all values for response
            client_state.set_srv_code(Outgoing_res.CONFIRM_RECEIPT_MSG.value)
            client_state.set_srv_payload_data(client_state.cl_id_binary)

        except FileNameNotMatchException as ex:
            logging.error(ex)
        except Exception as ex:
            logging.error(f"Error while handling received crc due to {ex}")
        finally:
            self.send_response(client_state)

    def generate_aes_key(self) -> bytes:
        """
        Generate a random AES key.
        """
        return Random.get_random_bytes(AES.block_size)

    def encrypt_aes_key(self, aes_key, public_key) -> bytes:
        """
        Encrypt the AES key using the client's public key.

        Parameters:
        - aes_key: The AES key to be encrypted.
        - public_key: The client's public key.
        """
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        return encrypted_aes_key
    
    def send_response(self, client_state) -> None:
        """
        Send a response to the client.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        res = self.pack_response(client_state)
        client_state.conn.sendall(res)

    def pack_response(self, client_state) -> bytes:
        """
        Pack the server's response data.

        Parameters:
        - client_state: An instance of ClientState representing the client's state.
        """
        code_bytes = utils.to_little_endian(client_state.srv_code, 2)
        if client_state.srv_code == Outgoing_res.REGIS_FAIL.value or client_state.srv_code == Outgoing_res.GENE_ERR.value:
            version_bytes = b'\x03'
            payload_size_bytes = b'\x00' * Protocol_sizes.PAYLOAD_SIZE_IN_PROTOCAL.value
            client_state.set_srv_payload_data()
        else: 
            version_bytes = utils.to_little_endian(client_state.srv_version, Protocol_sizes.VERSION_SIZE_IN_PROTOCOL.value)
            client_state.set_srv_payload_size(len(client_state.srv_payload_data))
            payload_size_bytes = utils.to_little_endian(client_state.srv_payload_size, Protocol_sizes.PAYLOAD_SIZE_IN_PROTOCAL.value)
        
        buffer = version_bytes + code_bytes + payload_size_bytes + client_state.srv_payload_data
        return buffer
