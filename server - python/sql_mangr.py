import sqlite3
import os
from datetime import datetime
import threading
import logging

from constants import *

logging.basicConfig(
    format=FORMAT,
    level=logging.INFO,
    datefmt='%H:%M:%S')

class DbManager:
    def __init__(self, db_name=DB_NAME) -> None:
        """
        Initialize the DbManager object.

        Args:
        - db_name (str): The name of the SQLite database.
        """
        logging.info("Loading Database")
        self.connection = sqlite3.connect(DB_NAME, check_same_thread=False)
        self.cursor = self.connection.cursor()
        if not os.path.exists(db_name):
            self.create_db()
        self.lock = threading.Lock()
        
    def create_db(self) -> None:
        """
        Create the SQLite database.
        """
        try:
            self.create_clients_table()
            self.create_files_table()
        except Exception as ex:
            logging.error(f"Error creating database: {ex}")

    def create_clients_table(self) -> None:
        """
        Create the 'clients' table in the SQLite database.
        """
        try:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS clients (
                    ID BLOB PRIMARY KEY,
                    Name TEXT,
                    PublicKey BLOB,
                    LastSeen DATETIME,
                    AES BLOB
                )
            ''')
            self.connection.commit()
        except Exception as ex:
            logging.error(f"Error creating 'clients' table: {ex}")

    def create_files_table(self) -> None:
        """
        Create the 'files' table in the SQLite database.
        """
        try:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    ID BLOB PRIMARY KEY,
                    FileName TEXT,
                    PathName TEXT,
                    Verified BOOLEAN
                )
            ''')
            self.connection.commit()
        except Exception as ex:
            logging.error(f"Error creating 'files' table: {ex}")

    # Client Table
    def print_clients_table(self) -> None:
        """
        Print the contents of the 'clients' table.
        """
        try:
            # Fetch all rows from the "clients" table
            self.cursor.execute('SELECT * FROM clients')
            rows = self.cursor.fetchall()

            if not rows:
                logging.info("No data found in the 'clients' table.")
            else:
                # Print the header
                header = [description[0] for description in self.cursor.description]
                logging.info("\t".join(header))

                # Print each row
                for row in rows:
                    logging.info("\t".join(map(str, row)))
        except Exception as ex:
            logging.error(f"Error printing 'clients' table: {ex}")

    def add_client(self, ID, Name, LastSeen=datetime.now(), PublicKey=None, AES=None) -> None:
        """
        Add a new client to the 'clients' table.

        Args:
        - ID (str): The client ID.
        - Name (str): The client name.
        - LastSeen (datetime): The last seen timestamp (default: current timestamp).
        - PublicKey (bytes): The client's public key.
        - AES (bytes): The client's AES key.
        """
        with self.lock:
            try:
                self.cursor.execute('''
                    INSERT INTO clients (ID, Name, PublicKey, LastSeen, AES)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ID, Name, PublicKey, LastSeen, AES))
                self.connection.commit()
            except Exception as ex:
                logging.error(f"Error adding client to 'clients' table: {ex}")

    def get_client(self, ID):
        """
        Get client information based on the client ID.

        Args:
        - ID (str): The client ID.
        """
        with self.lock:
            try:
                self.cursor.execute('SELECT * FROM clients WHERE ID = ?', (ID,))
                return self.cursor.fetchone()
            except Exception as ex:
                logging.error(f"Error getting client from 'clients' table: {ex}")

    def get_client_by_name(self, cl_name) -> None:
        """
        Get client information based on the client name.

        Args:
        - cl_name (str): The client name.
        """
        with self.lock:
            try:
                self.cursor.execute('SELECT * FROM clients WHERE Name = ?', (cl_name,))
                return self.cursor.fetchone()
            except Exception as ex:
                logging.error(f"Error getting client from 'clients' table: {ex}")

    def update_public_key(self, ID, new_public_key) -> None:
        """
        Update the public key for a client.

        Args:
        - ID (str): The client ID.
        - new_public_key (bytes): The new public key.
        """
        try:
            self.cursor.execute('''
                UPDATE clients
                SET PublicKey=?
                WHERE ID=?
            ''', (new_public_key, ID))
            self.connection.commit()
        except Exception as ex:
            logging.error(f"Error updating public key in 'clients' table: {ex}")

    def update_public_key_and_aes(self, id, new_public_key, new_aes, last_seen=datetime.now()) -> None:
        """
        Update the public key, AES key, and last seen timestamp for a client.

        Args:
        - id (str): The client ID.
        - new_public_key (bytes): The new public key.
        - new_aes (bytes): The new AES key.
        - last_seen (datetime): The last seen timestamp (default: current timestamp).
        """
        try:
            self.cursor.execute('''
                UPDATE clients
                SET PublicKey=?, AES=?, LastSeen=?
                WHERE ID=?
            ''', (new_public_key, new_aes, last_seen, id))
            self.connection.commit()
        except Exception as ex:
            logging.error(f"Error updating public key and AES in 'clients' table: {ex}")

    def update_last_seen(self, id, last_seen=datetime.now()) -> None:
        """
        Update the last seen timestamp for a client.

        Args:
        - id (str): The client ID.
        - last_seen (datetime): The last seen timestamp (default: current timestamp).
        """
        try:
            self.cursor.execute('''
                UPDATE clients
                SET LastSeen=?
                WHERE ID=?
            ''', (last_seen, id))
            self.connection.commit()
        except Exception as ex:
            logging.error(f"Error updating last seen in 'clients' table: {ex}")

    def validate_name(self, cl_name):
        """
        Validate if a client name is unique.

        Args:
        - cl_name (str): The client name.
        """
        with self.lock:
            try:
                # Execute a query to check if the name exists
                self.cursor.execute('SELECT COUNT(*) FROM clients WHERE Name = ?', (cl_name,))
                count = self.cursor.fetchone()[0]

                # Return True if the name does not exist, False otherwise
                return count == 0
            except Exception as ex:
                logging.error(f"Error validating name in 'clients' table: {ex}")

    def check_matching_client_name_and_id(self, client_name, client_id) -> bool:
        """
        Check if the provided client name and ID match the records in the database.

        Args:
        - client_name (str): The client name to check.
        - client_id (str): The client ID to check.
        """
        with self.lock:
            try:
                # Execute a SELECT query to fetch the client ID based on the client name
                self.cursor.execute('SELECT ID FROM clients WHERE Name = ?', (client_name,))
                result = self.cursor.fetchone()

                # Check if a record was found
                if result:
                    fetched_client_id = result[0]  # Extracting the client ID from the result tuple

                    if fetched_client_id == client_id:
                        return True
                    else:
                        logging.info(f"Provided client ID {client_id} does not match the client ID associated with the name: {client_name}")
                        return False
                else:
                    logging.info(f"No client found with the name: {client_name}")
                    return False
            except Exception as ex:
                logging.error(f"Error checking client name and ID: {ex}")
                return False

    def get_aes_key_by_id(self, client_id):
        """
        Get the AES key based on the client ID.

        Args:
        - client_id (str): The client ID.
        """
        try:
            self.cursor.execute('''
                SELECT AES
                FROM clients
                WHERE ID=?
            ''', (client_id,))
            result = self.cursor.fetchone()
            return result if result is None else result[0]
        except Exception as ex:
            logging.error(f"Error getting AES key from 'clients' table: {ex}")

    def get_public_key_by_id(self, client_id):
        """
        Get the public key based on the client ID.

        Args:
        - client_id (str): The client ID.
        """
        try:
            self.cursor.execute('''
                SELECT PublicKey
                FROM clients
                WHERE ID=?
            ''', (client_id,))
            result = self.cursor.fetchone()
            return result if result is None else result[0]
        except Exception as ex:
            logging.error(f"Error getting public key from 'clients' table: {ex}")

    def delete_clients_table(self) -> None:
        """
        Delete all records from the 'clients' table.
        """
        with self.lock:
            try:
                self.cursor.execute('DELETE FROM clients')
                self.connection.commit()
                logging.info("All records deleted from the 'clients' table.")
            except Exception as ex:
                logging.error(f"Error deleting records in 'clients' table: {ex}")

    # Files Table
    def add_file(self, id, file_name, path_name, verified=False) -> None:
        """
        Add a new file to the 'files' table.

        Args:
        - id (str): The file ID.
        - file_name (str): The file name.
        - path_name (str): The file path.
        - verified (bool): The verification status of the file (default: False).
        """
        with self.lock:
            try:
                self.cursor.execute('''
                    INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified)
                    VALUES (?, ?, ?, ?)
                ''', (id, file_name, path_name, verified))
                self.connection.commit()
            except Exception as ex:
                logging.error(f"Error adding file to 'files' table: {ex}")

    def update_file_verification(self, cl_id, file_name, verified) -> None:
        """
        Update the verification status of a file.

        Args:
        - cl_id (str): The client ID.
        - file_name (str): The file name.
        - verified (bool): The new verification status.
        """
        with self.lock:
            try:
                self.cursor.execute('''
                    UPDATE files
                    SET Verified=?
                    WHERE ID=? AND FileName=?
                ''', (verified, cl_id, file_name))
                self.connection.commit()
            except Exception as ex:
                logging.error(f"Error updating file verification status: {ex}")

    def print_files_table(self) -> None:
        """
        Print the contents of the 'files' table.
        """
        try:
            # Fetch all rows from the "files" table
            self.cursor.execute('SELECT * FROM files')
            rows = self.cursor.fetchall()

            if not rows:
                logging.info("No data found in the 'files' table.")
            else:
                # Print the header
                header = [description[0] for description in self.cursor.description]
                logging.info("\t".join(header))

                # Print each row
                for row in rows:
                    logging.info("\t".join(map(str, row)))
        except Exception as ex:
            logging.error(f"Error printing 'files' table: {ex}")

    def delete_files_table(self) -> None:
        """
        Delete all records from the 'files' table.
        """
        with self.lock:
            try:
                self.cursor.execute('DELETE FROM files')
                self.connection.commit()
                logging.info("All records deleted from the 'files' table.")
            except Exception as ex:
                logging.error(f"Error deleting records in 'files' table: {ex}")

    def close_connection(self) -> None:
        """
        Close the SQLite database connection.
        """
        self.connection.close()
