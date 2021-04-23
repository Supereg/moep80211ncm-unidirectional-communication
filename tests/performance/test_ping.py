import subprocess
import re
import json

def test_ping_cfg(target, count, interval, size):
    with subprocess.Popen(["ping", target, "-c", str(count), "-i", str(interval), "-s", str(size)], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        stdout = proc.stdout.read().decode().split("\n")[1:-5]
        output = []
        for line in stdout:
            data = re.search(r"time=(\d+.\d+)", line)
            if data:
                time = float(data.group(1))
            else:
                time = None
            output.append(time)
        return output

outputs = []
outputs.append(test_ping_cfg("192.168.137.98", 200, 1, 64))
outputs.append(test_ping_cfg("192.168.137.98", 200, 1, 1024))
outputs.append(test_ping_cfg("192.168.137.98", 200, 0.1, 64))
outputs.append(test_ping_cfg("192.168.137.98", 200, 0.1, 1024))
outputs.append(test_ping_cfg("192.168.137.98", 200, 0.01, 64))
outputs.append(test_ping_cfg("192.168.137.98", 200, 0.01, 1024))

with open("pinglog.json", "w") as f:
    f.write(json.dumps(outputs))