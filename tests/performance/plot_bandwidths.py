import matplotlib.pyplot as plt
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("inputs", nargs="+")
args = parser.parse_args()

for fn in args.inputs:
    with open(fn) as f:
        data = json.loads(f.read())

    x = list(range(len(data)))
    plt.plot(x, data, label=fn)

plt.ylabel("Bandwidth in Mbit/s")
plt.xlabel("Time in seconds")
plt.legend()
plt.show()