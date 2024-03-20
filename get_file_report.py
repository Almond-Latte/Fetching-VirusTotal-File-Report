import time
from datetime import datetime, timedelta, timezone
from logging import INFO, FileHandler, Formatter, getLogger
from pathlib import Path
from typing import Any

import requests
import ujson as json

import settings

# load settings
API_KEY: str = settings.API_KEY
HASH_LIST_PATH: Path = settings.HASH_LIST_PATH
LOG_FILE_PATH: Path = settings.LOG_FILE_PATH
DOWNLOAD_DIR: Path = settings.DOWNLOAD_DIR
VT_API_URL: str = "https://www.virustotal.com/api/v3/files/"

# init logger
logger = getLogger(__name__)
logger.setLevel(INFO)
handler = FileHandler(LOG_FILE_PATH)
formatter = Formatter("%(asctime)s %(levelname)-8s %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def call_vt_api(sha256: str) -> dict[str, Any] or None:
    """Call VirusTotal API and return response."""
    headers: dict[str, str] = {"x-apikey": API_KEY}
    try:
        logger.info(f"requesting {sha256}")
        # request to VirusTotal
        response = requests.get(VT_API_URL + sha256, headers=headers)

        # handle success
        if response.status_code == 200:
            return response.json()
        # handle QuotaExceededError
        elif response.status_code == 429:
            logger.warning(
                "QuotaExceededError... waiting until UTC 00:00 to request again."
            )
            wait_until_utc_midnight()
            return call_vt_api(sha256)  # retry
        # handle other errors
        else:
            logger.error(f"Error: {response.status_code} {response.text}")
            return None

    except Exception as e:
        logger.error(f"Exception: {e}")
        return None


def wait_until_utc_midnight() -> None:
    """Wait until UTC midnight."""
    now: datetime = datetime.now(timezone.utc)
    tomorrow: datetime = now + timedelta(days=1)
    midnight: datetime = datetime(
        year=tomorrow.year,
        month=tomorrow.month,
        day=tomorrow.day,
        hour=0,
        minute=0,
        second=0,
        tzinfo=timezone.utc,
    )
    # calculate wait seconds
    wait_seconds: int = (midnight - now).seconds
    time.sleep(wait_seconds)


def main() -> None:
    with HASH_LIST_PATH.open(mode="r") as f:
        for sha256 in f:
            sha256 = sha256.strip()
            response: dict[str, Any] | None = call_vt_api(sha256)
            if response is None:
                continue

            # save response to file
            file_path: Path = Path.joinpath(DOWNLOAD_DIR, f"{sha256}.json")
            with file_path.open(mode="w") as f:
                f.write(json.dumps(response))
                logger.info(f"saved {sha256}.json")

            time.sleep(15)  # 4 requests per minute


if __name__ == "__main__":
    main()
