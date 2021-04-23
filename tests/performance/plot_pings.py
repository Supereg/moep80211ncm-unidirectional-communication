import matplotlib.pyplot as plt
import argparse
import json

WINDOW = 20

parser = argparse.ArgumentParser()
parser.add_argument("inputs", nargs="+")
args = parser.parse_args()

fig, axes = plt.subplots(1, len(args.inputs), sharey=True)

labels = [
    "1 64",
    "1 1024",
    "0.1 64",
    "0.1 1024",
    "0.01 64",
    "0.01 1024",
]

for ax_i, fn in enumerate(args.inputs):
    with open(fn) as f:
        data = json.loads(f.read())

    for el, lbl in zip(data, labels):
        el = el[1:]
        y = []
        for i in range(1, len(el) - WINDOW):
            y.append(sum(el[i:i + WINDOW]) / WINDOW)
        x = list(range(WINDOW + 1, len(el)))
        axes[ax_i].plot(x, y, label=lbl)
        axes[ax_i].set_title(fn)
        axes[ax_i].legend()

plt.ylabel("Response delay in ms")
plt.show()