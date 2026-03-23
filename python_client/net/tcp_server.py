
import socket
from threading import Thread

class TCPServer:

    def __init__(self, host: str, port: int, handler):
        self.host = host
        self.port = port
        self.handler = handler

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, self.port))
        s.listen()

        print(f"TCP server listening on {self.host}:{self.port}")

        while True:
            conn, addr = s.accept()
            Thread(target=self.handler, args=(conn, addr), daemon=True).start()
