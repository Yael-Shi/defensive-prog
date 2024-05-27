import uuid
import ast
import logging

from constants import *

logging.basicConfig(
    format=FORMAT,
    level=logging.INFO,
    datefmt='%H:%M:%S')


class ClientState:
    def __init__(self):
        self.cl_name = None
        self.cl_header_data = None
        self.cl_id = None
        self.cl_id_binary = None
        self.cl_version = None
        self.cl_code = None
        self.cl_payload_size = None
        self.cl_payload_data = None

        self.srv_header_data = None
        self.srv_version = SRV_VERSION
        self.srv_code = None
        self.srv_payload_size = None
        self.srv_payload_data = None
        
        self.public_key = None
        self.aes_key = None
    
    def set_cl_name(self, name) -> None:
        """
        Set the client's name.

        Parameters:
        - name (str): The name of the client.
        """
        self.cl_name = name
        
    def set_cl_id(self) -> None:
        """
        Set a new random client ID.
        """
        self.cl_id = str(uuid.uuid4()).replace("-", "")
        self.set_cl_id_binary()
     
    def set_cl_id_binary(self) -> None:
        """
        Convert the hexadecimal client ID to binary representation.
        """
        self.cl_id_binary = bytes.fromhex(self.cl_id)
    
    def set_cl_id_for_old_cl(self, c_id) -> None:
        """
        Set the client ID for an existing client.

        Parameters:
        - c_id (str): The existing client ID.
        """
        try:
            self.cl_id = c_id
            self.cl_id_binary = ast.literal_eval(c_id)
        except Exception as ex:
            logging.error(f"Error setting client ID for old client: {ex}")

    def get_cl_id(self) -> str:
        """
        Get the client ID.
        """
        return self.cl_id

    def get_srv_code(self) -> int:
        """
        Get the server response code.
        """
        return self.srv_code

    def set_srv_code(self, value) -> None:
        """
        Set the server response code.

        Parameters:
        - value (int): The server response code.
        """
        self.srv_code = value

    def get_srv_payload_size(self) -> int:
        """
        Get the size of the server payload.
        """
        return self.srv_payload_size

    def set_srv_payload_size(self, value) -> None:
        """
        Set the size of the server payload.

        Parameters:
        - value (int): The size of the server payload.
        """
        self.srv_payload_size = value

    def get_srv_payload_data(self) -> bytes:
        """
        Get the server payload data.
        """
        return self.srv_payload_data

    def set_srv_payload_data(self, *args):
        """
        Set the server payload data.

        Parameters:
        - args (bytes): Variable number of payload data components.
        """
        try:
            payload_binary_data = b''.join(args)
            self.srv_payload_data = payload_binary_data
        except Exception as ex:
            logging.error(f"Error setting server payload data: {ex}")
     
    def get_aes_key(self) -> bytes:
        """
        Get the AES key.
        """
        return self.aes_key
