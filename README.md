# Socks Server

Simple and easy to set up SOCKS4/5 proxy server

### Getting Started
This project requires [Sockslib](https://pypi.org/project/sockslib/)<br />
`pip3 install sockslib`

To start, clone the repo, and run `sockserver.py`<br />
By default, this file will bind to `127.0.0.1:8080`, to chane this, go into the file and find the line that says `('127.0.0.1', 8080)` and change the ip and port to whatever you need.
```bash
git clone https://github.com/woo200/pysocksserver;
cd pysocksserver;
python3 sockserver.py;
```

## Advanced usage

### SocksServer class
The `socksserver.SocksServer` class can take up to 4 arguments
#### Arguments:
 - bind - Tuple containing address and port to bind server to `[ REQUIRED ]`
 - auth - Array of acceptable authentication methods `[ Default: [NoAuth()] ]`
 - allow_private - Allow proxy access to private IP ranges? (127.0.0.1, 192.168.0.x, 10.0.0.x, etc) `[ Default: False ]`
 - secure - WIP, Most likely will break server if enabled `[ Default: False ]`

#### Functions:
 - start_server() - Start the proxy server threads [ Note: This function does NOT block ]

### Username / Password Authentication
Note: Username / Password authentication is only supported by SOCKS5, See [ID Authentication](#id-authentication-socks4) for SOCKS4<br /><br />
To enable username / password authentication, you must pass an array of acceptable authentication methods into the server object when you create it. The class that is used for this type of authentication is `socksserver.UserPassAuth`. This class takes a dictionary containing username and passwords as such: `socksserver.UserPassAuth({"username": "password"})`.
```python
import socksserver
import time

auth = [ # Array of acceptable authentication methods
    socksserver.UserPassAuth({  # Username / Password authentication method.
        "Username": "password"
    })
]

server = socksserver.SocksServer(('127.0.0.1', 1080), auth) # Create the server, and pass in the auth array as the second argument
server.start_server()

while True: # Block
    time.sleep(1)
```

### ID Authentication (Socks4)
To enable ID authentication, you will use the `socksserver.IDAuth` class. This class takes an array of ID's that it will authenticate against.<br />
Following the example above, we can change the auth array to this:
```python
auth = [ # Array of acceptable authentication methods
    socksserver.IDAuth([  # ID authentication method. (Socks4)
        "Username"
    ])
]
```

### Implementing Custom Authentication
Note: Custom authentication methods are only supported by SOCKS5.<br />
To implement a custom authetication method, you will create a class that is derived from `socksserver.ServerAuthenticationMethod`. This class must contain at least two methods: `getId(self) -> int` and `authenticate(self, socket) -> bool`
#### getId(self)
The `getId` function returns the ID that the server will add to the acceptable auth list. The client will chose an authentication method and the server will check if it can authenticate with that.
```python
def getId(self):
    return 0x02  # Example ID
```

#### authenticate(self, socket)
the `authenticate` function is called when the client and server agree on an authentication method, and then the authentication is initialized. This function will handle checking whether or not the client should be allowed to continue, or the connection should be terminated. You will be given the direct socket to the client, and will handle authentication yourself. This function returns a boolean, True meaning the server will establish the connection, False meaning it will terminate the connection.
```python
# This is an example taken directly from socksserver.UserPassAuth
def authenticate(self, socket):
        ver, idlen = socket.recv(2)
        id = socket.recv(idlen)
        pwlen, = socket.recv(1)
        pw = socket.recv(pwlen)

        try:
            if id.decode() not in self.user_db:
                socket.sendall(b"\x01\x01")
                return False

            if self.user_db[id.decode()] != pw.decode():
                socket.sendall(b"\x01\x01")
                return False
        except Exception as e:
            socket.sendall(b"\x01\x01")
            return False

        socket.sendall(b"\x01\x00")
        return True
```

#### Full example
This is an example of a class that allows anyone to use the proxy server
```python
import socksserver

class NoAuth(socksserver.ServerAuthenticationMethod):
    def getId(self):
        return 0x00

    def authenticate(self, socket): # Always allow connection
        return True
```

## Hooks
Hooks are used as callbacks to certain events that happen when a client connects or sends a packet. Currently only 3 hooks exist
 - connect - Called as soon as a connection is established between client and the server. [ Arguments: sock, addr ]
 - handshake_finish - Called when the client and server have finished handshaking and authentication. [ Arguments: requestedConnectionAddr, sock, addr ]
 - packet - Called when a packet is sent between client and server [ Arguments: data, sock, origin_addr, socket_type ]

```python
import socksserver
import time

def connect_hook(sock, addr):
    print(f"{addr} connected!")

def handshake_finish_hook(requestedConnectionAddr, sock, addr):
    print(f"{addr} finished handshaking")

def packet_hook(data, sock, origin_addr, socket_type):
    if socket_type == socksserver.SocketType.CLIENT:
        print(f"Client sent data: {data}")
    elif socket_type == socksserver.SocketType.SERVER:
        print(f"Server sent data: {data}")

server = socksserver.SocksServer(('127.0.0.1', 1080)) # Create the server

server.set_hook("connect", connect_hook)
server.set_hook("handshake_finish", handshake_finish_hook)
server.set_hook("packet", packet_hook)

server.start_server()

while True:
    time.sleep(1)

```

## Notes

If you configure the server with UserPassAuth, due to the fact that socks4 does not support this, the socks4 part of the server will essentially be disabled. To combat this, you may add IDAuth along with UserPassAuth.
