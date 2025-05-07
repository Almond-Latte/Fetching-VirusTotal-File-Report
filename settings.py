import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from zoneinfo import ZoneInfo

console = Console()


def get_env(key: str) -> str:
    """Load environment variable and return it."""
    val = os.getenv(key)
    if val is None:
        console.log(
            f"Error: {key} is not set as an environment variable. \
            Consider adding {key} to the .env file."
        )
        sys.exit()
    return val


dirname: Path = Path(__file__).parent

# Read .env File
dotenv_path: Path = Path.joinpath(dirname, ".env")
load_dotenv(dotenv_path, override=True)
API_KEY: str = get_env("API_KEY")
HASH_LIST_PATH: Path = Path(get_env("HASH_LIST_PATH"))
OVERWRITE: bool = get_env("OVERWRITE").lower() == "true"

# hash list path setup
if HASH_LIST_PATH.is_absolute():
    HASH_LIST_PATH: Path = HASH_LIST_PATH.resolve()
else:
    HASH_LIST_PATH: Path = (dirname / HASH_LIST_PATH).resolve()

if not HASH_LIST_PATH.is_file():
    console.log(
        f"Error: {HASH_LIST_PATH} does not exist. \
        Please check the path in the .env file."
    )
    sys.exit()


# download directory setup
DOWNLOAD_DIR_PATH: Path = Path(get_env("DOWNLOAD_DIR_PATH"))

if DOWNLOAD_DIR_PATH.is_absolute():
    DOWNLOAD_DIR_PATH: Path = DOWNLOAD_DIR_PATH.resolve()
else:
    # if the path is relative, join it with the script directory
    DOWNLOAD_DIR_PATH: Path = (dirname / DOWNLOAD_DIR_PATH).resolve()
if not DOWNLOAD_DIR_PATH.is_absolute():
    DOWNLOAD_DIR_PATH = dirname / download_dir_path

DOWNLOAD_DIR_PATH.mkdir(exist_ok=True, parents=True)

# create log directory
log_dir_path: Path = Path.joinpath(dirname, Path("log"))
log_dir_path.mkdir(exist_ok=True)

# create log file
LOG_FILE_PATH: Path = Path.joinpath(
    log_dir_path,
    Path(f"{datetime.now(ZoneInfo('Asia/Tokyo')):%Y%m%d_%H%M%S}.log"),
)
LOG_FILE_PATH.touch(exist_ok=True)