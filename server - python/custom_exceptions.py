

class NameExistsException(Exception):
    "Raised when the name of a client already exists in the database"
    pass

class IncompleteHeader(Exception):
    "Raised when haeder is incomplete"
    pass

class IncompletePayload(Exception):
    "Raised when payload is incomplete"
    pass

class NoClientNameMatchIDException(Exception):
    "Raised when there is no match between client name to client id in the database"
    pass

class FileNameNotMatchException(Exception):
    "Raised when there is no match between already saved file name and the one recived on the next msg"
    pass
    
class FileReceivingException(Exception):
    "Raised when there is an issue with receiving and/or processing file sent by a client"
    pass