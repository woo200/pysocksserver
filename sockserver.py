import socksserver
import time

auth = [ # Array of acceptable authentication methods
    socksserver.IDAuth([  # Username / Password authentication method.
        "Username"
    ])
]

server = socksserver.SocksServer(('127.0.0.1', 1080), auth) # Create the server, and pass in the auth array as the second argument
server.start_server()

while True: # Block
    time.sleep(1)
