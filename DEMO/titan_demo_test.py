import os
import socket
import subprocess
import time

print("=" * 60)
print("TITAN ENDPOINT - DEMO TEST FILE")
print("Harmless test script for demonstration purposes only.")
print("It does three ordinary things so TITAN's monitors have")
print("something real to see and log:")
print("  1. Creates and deletes a small text file")
print("  2. Opens a normal outbound network connection")
print("  3. Starts a short-lived child process (ping)")
print("=" * 60)

# 1) File activity (written next to this script, NOT in Temp -- TITAN's
# Files endpoint deliberately ignores short-lived Temp writes as noise,
# so a normal-folder write is used here to actually show up in the GUI)
demo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "titan_demo_test_output.txt")
print(f"[1/3] Writing test file: {demo_file}")
with open(demo_file, "w") as f:
    f.write("TITAN demo test file - safe to delete\n")
time.sleep(2)
os.remove(demo_file)
print("      File removed.")

# 2) Network activity
print("[2/3] Opening a network connection to example.com:80 ...")
try:
    with socket.create_connection(("example.com", 80), timeout=5) as s:
        s.sendall(b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        s.recv(100)
    print("      Connection completed.")
except Exception as e:
    print(f"      Network step skipped ({e})")

# 3) Process activity
print("[3/3] Starting a short child process (ping) ...")
subprocess.run(["ping", "-n", "2", "127.0.0.1"], capture_output=True)
print("      Child process finished.")

print("=" * 60)
print("DONE. Open the TITAN GUI and check the Process, Network,")
print("and Files tabs for entries matching this script (python.exe)")
print("and its child processes around the time it ran.")
print("=" * 60)
