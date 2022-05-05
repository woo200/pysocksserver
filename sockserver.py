# Copyright 2021 John Woo
# See LICENSE.md

import socksserver
import sys
import time
import json
import os
import importlib

from dbauth import DBUserPassAuth

mysql_enabled = False
name = "mysql"
if name in sys.modules:
    import mysql.connector
    mysql_enabled = True
elif (spec := importlib.util.find_spec(name)) is not None:
    import mysql.connector
    mysql_enabled = True

config = json.load(open("config.json"))
ip, port = config["bind_addr"]

auth = []

if config["authentication"]["authfile"]["enabled"]:
    if not os.path.isfile(config["authentication"]["authfile"]["file"]):
        with open(config["authentication"]["authfile"]["file"], "w") as f:
            f.write("username:password")
    pdb = {}
    with open(config["authentication"]["authfile"]["file"], "r") as f:
        for line in f:
            username, password = line.rstrip().split(":")
            pdb[username] = password
    auth.append(socksserver.UserPassAuth(pdb))

if config["authentication"]["mysql"]["enabled"]:
    if mysql_enabled:
        try:
            ipc, portc = config["authentication"]["mysql"]["host"].split(":")
            db = mysql.connector.connect(
                host=ipc,
                port=int(portc),
                user=config["authentication"]["mysql"]["username"],
                password=config["authentication"]["mysql"]["password"],
                database=config["authentication"]["mysql"]["database"]
            )
            auth.append(DBUserPassAuth(db))
        except Exception as e:
            print(f"[WARNING] Error connecting to MySQL server. Error: {e}")
    else:
        print(f"[WARNING] You have enabled MySQL authentication, but you do not have the MySQL module for python installed. You can install this by running \"pip install mysql-connector-python\".")

if len(auth) == 0:
    print(f"[INFO] No valid authentication methods available, deferring to NoAuth")
    auth.append(socksserver.NoAuth())

server = socksserver.SocksServer((ip, port), auth)
server.start_server()
print(f"[INFO] Socks4/5 server listening on {ip}:{port}")

while True:  # Block
    time.sleep(1)
