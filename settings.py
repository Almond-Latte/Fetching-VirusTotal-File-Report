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

# create log directory
log_dir_path: Path = Path.joinpath(dirname, Path("log"))
log_dir_path.mkdir(exist_ok=True)

# create log file
LOG_FILE_PATH: Path = Path.joinpath(
    log_dir_path,
    Path(f"{datetime.now(ZoneInfo('Asia/Tokyo')):%Y%m%d_%H%M%S}.log"),
)
LOG_FILE_PATH.touch(exist_ok=True)

# create download directory
DOWNLOAD_DIR: Path = Path.joinpath(dirname, "vt_reports")
DOWNLOAD_DIR.mkdir(exist_ok=True)

# Read .env File
dotenv_path: Path = Path.joinpath(dirname, ".env")
load_dotenv(dotenv_path, override=True)
API_KEY: str = get_env("API_KEY")
HASH_LIST_PATH: Path = Path(get_env("HASH_LIST_PATH"))
OVERWRITE: bool = get_env("OVERWRITE").lower() == "true"
