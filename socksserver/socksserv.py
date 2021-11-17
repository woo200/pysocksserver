import struct
import socket
import ipaddress
import threading
import sockslib
import re

class ServerAuthenticationMethod():
    def getId(self) -> int:
        pass

    def authenticate(self, socket) -> bool:
        pass

class NoAuth(ServerAuthenticationMethod):
    def getId(self):
        return 0x00

    def authenticate(self, socket):
        return True

class Hooks:
    def __init__(self, defaults=[]):
        self.hooks = {k:None for k in defaults}

    def set_hook(self, hook, callback):
        self.hooks[hook] = callback

    def call_hook(self, hook, *args, **kwargs):
        if hook in self.hooks:
            if self.hooks[hook] != None:
                return self.hooks[hook](*args, **kwargs)

class SocketType:
    CLIENT = 1
    SERVER = 2

class SocksServer(Hooks):
    def __init__(self, bind, auth=[NoAuth()], allow_private = False, secure = False):
        super().__init__([
            "connect",
            "handshake_finish",
            "packet"
        ]);
        self.bind = bind
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.auth = auth
        self.allow_private = allow_private
        self.secure = secure

        self.valid_hops = [
            [('67.55.67.100', 5678), ('163.53.196.30', 5678), ('66.181.167.129', 5678)]
        ]

    def __proxy(self, p1, p2, p1addr, p2addr, doTerm, socketType):
        byte = b'\x00'
        try:
            while byte != b'' and not doTerm[0]:
                byte = p1.recv(1024)
                dhook = self.call_hook("packet", byte, p1, p1addr, socketType)
                if dhook != None:
                    byte = dhook
                p2.sendall(byte)

        except socket.error as e:
            print(f"Socket Error for {p1addr[0]}:{p1addr[1]} -> {p2addr[0]}:{p2addr[1]} : {e}")

        # Term p1
        try:
            p1.close()
        except:
            pass

        # Term p2
        try:
            p2.close()
        except:
            pass

        doTerm[0] = True
        print(f"{p1addr[0]}:{p1addr[1]} -> {p2addr[0]}:{p2addr[1]} : TERMINATED")

    def __start__v4(self, conn, addr, dst):
        if self.secure:
            s = sockslib.ProxyHopper(self.valid_hops[0], False, sockslib.Socks.SOCKS4)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(dst)

        doTerm = [False]

        threading.Thread (
            target=self.__proxy,
            args=[conn, s, addr, dst, doTerm, SocketType.CLIENT], # conn -> s // conn = addr
            daemon=True
        ).start()

        threading.Thread (
            target=self.__proxy,
            args=[s, conn, dst, addr, doTerm, SocketType.SERVER],
            daemon=True
        ).start()

    def __start__v6(self, conn, addr, dst):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.connect(dst)

        doTerm = [False]

        threading.Thread (
            target=self.__proxy,
            args=[conn, s, addr, dst, doTerm, SocketType.CLIENT], # conn -> s // conn = addr
            daemon=True
        ).start()

        threading.Thread (
            target=self.__proxy,
            args=[s, conn, dst, addr, doTerm, SocketType.SERVER],
            daemon=True
        ).start()

    def __start__domain(self, conn, addr, dst):
        self.__start__v4(conn, addr, dst)

    def __handle__4(self, conn, addr):
        GOOD_REQUEST = True

        cmd, = conn.recv(1)
        if cmd != 0x01:
            GOOD_REQUEST = False

        dstport, = struct.unpack("!H", conn.recv(2))
        dstip = ipaddress.IPv4Address(conn.recv(4)).exploded

        id = b''
        c = b''
        while c != b'\x00' and len(id) < 256:
            c = conn.recv(1)
            id += c

        id = id[:-1]
        reDst = self.call_hook("handshake_finish", (dstip, dstport), conn, addr)

        print(f"Recieved SOCKS4 request from {addr[0]}:{addr[1]} to connect to: {dstip}:{dstport} ({id})")
        if reDst != None:
            dstip, dstport = reDst

        if ipaddress.ip_address(dstaddr.getIp()).is_private and not self.allow_private:
            GOOD_REQUEST = False

        if GOOD_REQUEST:
            try:
                self.__start__v4(conn, addr, (dstaddr.getIp(), dstport))
            except:
                conn.sendall(b"\x00\x5B")
                conn.close()
                return

            conn.sendall(b"\x00\x5A" + struct.pack("!H", dstport) + ipaddress.IPv4Address(dstip).packed)
        else:
            conn.sendall(b"\x00\x5B")
            conn.close()

    def __handle__5(self, conn, addr, auth=[NoAuth()]):
        nauth, = conn.recv(1)
        methods = []

        for _ in range(nauth):
            methods.append(conn.recv(1)[0])

        choice = None

        for method in methods:
            for au in auth:
                if au.getId() == method:
                    choice = au
                    break

        if choice == None:
            conn.sendall(b"\x05\xFF")
            conn.close()
            return

        conn.sendall(b"\x05" + bytes([choice.getId()]))

        if not choice.authenticate(conn):
            conn.close()
            return

        ver, cmd, _ = conn.recv(3)
        if cmd != 0x01:
            conn.sendall(b"\x05\x07\x00")
            conn.close()
            return

        dstaddr = sockslib.Socks5Address.readAddr(conn)
        dstport, = struct.unpack("!H", conn.recv(2))

        reDst = self.call_hook("handshake_finish", (dstaddr, dstport), conn, addr)

        print(f"Recieved SOCKS5 request from {addr[0]}:{addr[1]} to connect to: {dstaddr.getIp()}:{dstport}")

        if reDst != None:
            dstaddr, dstport = reDst
            dstaddr = sockslib.Socks5Address(dstaddr, sockslib.IpIdentify.identify(dstaddr))

        try:
            if ipaddress.ip_address(dstaddr.getIp()).is_private and not self.allow_private:
                conn.sendall(b"\x05\x02\x00")
                conn.close()
                return
        except:
            pass

        try:
            if dstaddr.getType() == sockslib.AddrTypes.IPv4:
                self.__start__v4(conn, addr, (dstaddr.getIp(), dstport))
            elif dstaddr.getType() == sockslib.AddrTypes.IPv6:
                self.__start__v6(conn, addr, (dstaddr.getIp(), dstport))
            elif dstaddr.getType() == sockslib.AddrTypes.Domain:
                self.__start__domain(conn, addr, (dstaddr.getIp(), dstport))
        except socket.gaierror as e:
            conn.sendall(b"\x05\x04\x00")
            conn.close()
            return
        except socket.error as e:
            conn.sendall(b"\x05\x03\x00")
            conn.close()
            return

        conn.sendall(b"\x05\x00\x00" + dstaddr.getByteIp() + struct.pack("!H", dstport))

    def __handle_connection(self, conn, addr):
        self.call_hook("connect", conn, addr)
        ver, = conn.recv(1)

        if ver == sockslib.Socks.SOCKS4:
            self.__handle__4(conn, addr)
        elif ver == sockslib.Socks.SOCKS5:
            self.__handle__5(conn, addr, self.auth)
        else:
            print(f"Recieved unknown SOCKS request with version: {ver} from {addr}")
            return

    def __recv_thread(self):
        while True:
            conn, addr = self.socket.accept()

            threading.Thread(
                target=self.__handle_connection,
                args=[conn, addr],
                daemon=True
            ).start()


    def __start_recv_thread(self):
        threading.Thread(
            target=self.__recv_thread,
            daemon=True
        ).start()

    def start_server(self):
        self.socket.bind(self.bind)
        self.socket.listen()

        self.__start_recv_thread()
