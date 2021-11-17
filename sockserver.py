import socksserver
import time

auth = [
    socksserver.UserPassAuth({
        "test":"123"
    })
]

server = socksserver.SocksServer(('127.0.0.1', 8080), auth, False, False)
server.start_server()

while True:
    time.sleep(1)
