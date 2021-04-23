import random
import socket
import argparse
import datetime
import json

parser = argparse.ArgumentParser()
parser.add_argument("ip")
parser.add_argument("port")
args = parser.parse_args()

s = socket.socket()
s.connect((args.ip, int(args.port)))

data = []
for _ in range(200):
    bt = random.getrandbits(64).to_bytes(8, "big")
    before = datetime.datetime.now()
    s.send(bt * 100 * 1024 * 128) # send 100MiB
    after = datetime.datetime.now()
    diff = (after - before).total_seconds()
    data.append(100 / diff)

with open("bandwidth.json", "w") as f:
    f.write(json.dumps([data]))