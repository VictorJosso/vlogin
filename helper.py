import os
import dotenv
import threading
import socket
import json
import datetime
import time

from appwrite.client import Client
from appwrite.services.users import Users
from appwrite.services.storage import Storage
from appwrite.services.database import Database
from appwrite.services.account import Account
from appwrite.query import Query


dotenv.load_dotenv()

APPWRITE_ENDPOINT = os.getenv("APPWRITE_ENDPOINT")
APPWRITE_PROJECT = os.getenv("APPWRITE_PROJECT")
APPWRITE_APIKEY = os.getenv("APPWRITE_APIKEY")

appwrite_client = Client()
appwrite_client.set_endpoint(APPWRITE_ENDPOINT)
appwrite_client.set_project(APPWRITE_PROJECT)
appwrite_client.set_key(APPWRITE_APIKEY)

appwrite_users = Users(appwrite_client)


class Session:
    def __init__(self, session_id, client_id, expiration):
        self.session_id = session_id
        self.client_id = client_id
        self.expiration = expiration


class Cleaner(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.running = True
        self.sessions = []

    def run(self):
        while self.running:
            if len(self.sessions) > 0:
                current = self.sessions[0]
                if datetime.datetime.now().timestamp() >= current.expiration:
                    print("DELETE OF SESSION", current)
                    appwrite_users.delete_session(current.client_id, current.session_id)
                    self.sessions.pop(0)
                else:
                    time.sleep(10)
            else:
                time.sleep(60 * 15)


def listen():
    cleaner = Cleaner()
    cleaner.run()
    try:
        os.unlink("/tmp/vlogin.s")
    except OSError:
        if os.path.exists("/tmp/vlogin.s"):
            raise

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind("/tmp/vlogin.s")
    while True:
        print("Listening for incoming connections")
        server.listen(1)
        conn, addr = server.accept()
        datagram = conn.recv(1024)
        if datagram:
            data = json.loads(datagram)
            if data["event"] == "users.*.sessions.*.create":
                cleaner.sessions.append(Session(data["session_id"], data["client_id"], data["expiration"]))
                print("New session = ", data["session_id"], data["client_id"], data["expiration"])

        conn.close()


if __name__ == "__main__":
    print("Starting the helper...")
    listen()
