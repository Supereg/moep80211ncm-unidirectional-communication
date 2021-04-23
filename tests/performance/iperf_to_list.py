import json
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("input")
args = parser.parse_args()

with open(args.input) as f:
    data = json.loads(f.read())

data = data["intervals"]
data = [el["streams"][0]["bits_per_second"] / (1024 * 1024) for el in data]

with open(args.input, "w") as f:
    f.write(json.dumps(data))