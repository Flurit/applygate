"""Count the lines of the text files next to this repository's README."""
import pathlib

root = pathlib.Path(__file__).resolve().parent.parent
for path in sorted(root.glob("*.txt")):
    print(path.name, len(path.read_text().splitlines()))
