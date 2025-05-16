import sys
import time
import os

container_name = sys.argv[1]
timeout = int(sys.argv[2])
time.sleep(timeout)
os.system(f"docker rm -f {container_name}")
