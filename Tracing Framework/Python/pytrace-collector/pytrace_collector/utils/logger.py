import os, datetime

os.makedirs('logs', exist_ok=True)
LOG_DIR = f'logs/{datetime.datetime.now().strftime("%m-%d-%H-%M-%S")}'
os.makedirs(LOG_DIR, exist_ok=True)

