# Copyright 2021 John Woo
# See LICENSE.md

from socksserver.socksserv import ServerAuthenticationMethod
import struct

class UserPassAuth(ServerAuthenticationMethod):
    def __init__(self, user_db):
        self.user_db = user_db

    def getId(self):
        return 0x02

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

class IDAuth(ServerAuthenticationMethod):
    def __init__(self, ids):
        self.ids = ids

    def getId(self):
        return 0xFF

    def authenticate(self, id):
        return id.decode() in self.ids
