import os
import pathlib

desktop = pathlib.Path.home() / "Desktop"

print("Exists:", desktop.exists())
print("Is directory:", desktop.is_dir())

try:
    print("Contents:")
    for item in desktop.iterdir():
        print(" -", item)
except Exception as e:
    print("Error reading Desktop:", e)
