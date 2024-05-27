import os
import logging

from constants import *

logging.basicConfig(
    format=FORMAT,
    level=logging.INFO,
    datefmt='%H:%M:%S'
)

def extract_port_num():
    """
    Extracts the port number from the specified file.
    
    Returns:
        int: The extracted port number. If extraction fails, returns the default port number.
    """
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    port_file_path = os.path.join(curr_dir, PORT_FILE_NAME)
    port_num = 0

    try:
        with open(port_file_path, 'r') as file:
            port_num = file.read()
            port_num =  int(port_num)
    except Exception as e:
        logging.warning(f"An error occurred while extracting port number: {e}")
        port_num = DEFAULT_PORT_NUM

    return port_num


def remove_null_character(s):
    """
    Removes null characters from the given string.
    
    Args:
        s (str): The input string.
    
    Returns:
        str: The input string with null characters removed.
    """
    return s.replace('\0', '')


def to_little_endian(value, size) -> bytes:
    """
    Convert an integer value to little-endian bytes of a specified size.

    Parameters:
    - value: The integer value to be converted.
    - size: The size of the resulting bytes.
    """
    return value.to_bytes(size, byteorder='little')