import socksserver
import time

server = socksserver.SocksServer(('127.0.0.1', 1080)) # Create the server
server.start_server()

while True: # Block
    time.sleep(1)
