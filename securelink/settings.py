from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = 3
CHUNK_SIZE = 64 * 1024
MAX_FRAME = 128 * 1024
MAX_HEADER = 2048
MAX_FILE = 32 * 1024 * 1024
MAX_STORAGE = 256 * 1024 * 1024
MAX_TRANSFERS = 1024
IO_TIMEOUT = 10.0
HANDSHAKE_TIMEOUT = 5.0
HANDSHAKE_CLOCK_SKEW = 60
MAX_CONNECTIONS = 8
MAX_ATTEMPTS_PER_MINUTE = 120
EXTENSIONS = {'.txt': 'text', '.png': 'image', '.jpg': 'image', '.jpeg': 'image',
              '.wav': 'audio', '.mp3': 'audio', '.mp4': 'video'}
