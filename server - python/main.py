from server import Server
from utils import extract_port_num


def main():
    port_num = extract_port_num()
    server = Server(port_num)
    server.start()


if __name__ == "__main__":
    main()

