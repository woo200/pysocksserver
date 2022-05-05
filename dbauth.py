# Copyright 2021 John Woo
# See LICENSE.md

from socksserver.socksserv import ServerAuthenticationMethod


class DBUserPassAuth(ServerAuthenticationMethod):
    def __init__(self, connection):
        self.connection = connection
        cursor = self.connection.cursor()
        cursor.execute("""create table if not exists users (username TEXT NOT NULL, password TEXT NOT NULL)""")

    def getId(self):
        return 0x02

    def __auth_user(self, username, password):
        cursor = self.connection.cursor()
        cursor.execute("""select * from users""")
        record = cursor.fetchall()
        for row in record:
            if row[0] == username.decode() and row[1] == password.decode():
                return True
        return False

    def authenticate(self, socket):
        ver, idlen = socket.recv(2)
        id = socket.recv(idlen)
        pwlen, = socket.recv(1)
        pw = socket.recv(pwlen)

        try:
            if not self.__auth_user(id, pw):
                socket.sendall(b"\x01\x01")
                return False
        except Exception:
            socket.sendall(b"\x01\x01")
            return False

        socket.sendall(b"\x01\x00")
        return True
