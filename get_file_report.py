import time
from datetime import datetime, timedelta, timezone
from logging import INFO, FileHandler, Formatter, getLogger
from pathlib import Path
from string import Template
from typing import Any, Dict, Optional

import requests
import ujson as json # Using ujson for potentially faster JSON operations
import typer

# settings.py is expected to exist and be importable.
# It should define variables like API_KEY, HASH_LIST_PATH, etc.
import settings

app = typer.Typer(
    help="VirusTotal Report Downloader CLI: Downloads VirusTotal reports for a list of SHA256 hashes."
)

# --- Helper Functions ---

def wait_until_utc_one_am(logger_instance: Any) -> None:
    """
    Pauses execution until the next UTC 01:00 AM.
    This is used when an API quota is exceeded, allowing time for it to reset.

    Args:
        logger_instance: The logger instance to use for logging messages.
    """
    now_utc: datetime = datetime.now(timezone.utc)
    
    target_time_utc: datetime
    # Determine the next 01:00 AM UTC.
    if now_utc.hour < 1: 
        target_time_utc = now_utc.replace(
            hour=1, minute=0, second=0, microsecond=0, tzinfo=timezone.utc
        )
    else: 
        target_time_utc = (now_utc + timedelta(days=1)).replace(
            hour=1, minute=0, second=0, microsecond=0, tzinfo=timezone.utc
        )

    wait_seconds: float = (target_time_utc - now_utc).total_seconds()
    
    if wait_seconds < 1: 
        target_time_utc = (now_utc + timedelta(days=1)).replace(
             hour=1, minute=0, second=0, microsecond=0, tzinfo=timezone.utc
        )
        wait_seconds = (target_time_utc - now_utc).total_seconds()

    logger_instance.info(
        f"Waiting for {wait_seconds:.0f} seconds (until {target_time_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}) for API quota to reset."
    )
    time.sleep(wait_seconds)


def call_vt_api(
    sha256: str,
    api_key: str,
    vt_api_url_template: Template,
    logger_instance: Any
) -> Optional[Dict[str, Any]]:
    """
    Calls the VirusTotal API to get a file report for the given SHA256 hash.
    Handles API errors, including rate limiting (429) and API key errors (401).

    Args:
        sha256: The SHA256 hash of the file to look up.
        api_key: The VirusTotal API key.
        vt_api_url_template: A string.Template object for the VirusTotal API URL.
        logger_instance: The logger instance for logging.

    Returns:
        A dictionary containing the API response JSON if successful, None otherwise.
        Exits program on 401 error.
    """
    headers: Dict[str, str] = {"x-apikey": api_key}
    api_url = vt_api_url_template.substitute(id=sha256)
    logger_instance.info(f"Requesting VT report for {sha256} from {api_url}")

    try:
        response = requests.get(api_url, headers=headers, timeout=30) 
        response.raise_for_status() 
        return response.json()
        
    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 429: 
            logger_instance.warning(
                f"QuotaExceededError for {sha256}. Waiting until UTC 01:00 AM for quota to reset."
            )
            wait_until_utc_one_am(logger_instance)
            return call_vt_api(sha256, api_key, vt_api_url_template, logger_instance) 
        elif http_err.response.status_code == 401: # Specific check for 401 Unauthorized
            error_content = http_err.response.text
            error_message_detail = "Could not parse error response."
            error_code_detail = "UnknownErrorCode"
            try:
                # Attempt to parse the error message from JSON for better logging
                error_json = http_err.response.json()
                error_message_detail = error_json.get("error", {}).get("message", error_content)
                error_code_detail = error_json.get("error", {}).get("code", "WrongCredentialsError") # Default to WrongCredentialsError if code field missing
            except ValueError: # If response is not JSON
                pass # error_message_detail will remain the raw error_content or default

            logger_instance.critical(
                f"CRITICAL: API Authentication Error for {sha256}. Status: 401, Code: {error_code_detail}, Message: '{error_message_detail}'. "
                "This usually indicates a wrong or revoked API key. Please check your API key. Terminating program."
            )
            raise typer.Exit(code=2) # Exit with code 2 for API key errors
        else:
            # For other HTTP errors, log the error and return None to continue with next hash
            logger_instance.error(f"HTTP error for {sha256}: {http_err.response.status_code} {http_err.response.text}")
            return None
    except requests.exceptions.RequestException as req_err:
        # Handle other request-related errors (e.g., network issues)
        logger_instance.error(f"Request error for {sha256}: {req_err}")
        return None


@app.command()
def main(
    hash_list_path: Path = typer.Option(
        lambda: Path(settings.HASH_LIST_PATH).resolve(), 
        "--hash-list", "-f",
        help="Path to the file containing SHA256 hashes (one per line).",
        exists=True, file_okay=True, dir_okay=False, readable=True, show_default=True,
    ),
    download_dir: Path = typer.Option(
        lambda: Path(settings.DOWNLOAD_DIR).resolve(), 
        "--download-dir", "-d",
        help="Directory to save the downloaded VirusTotal reports. Will be created if it doesn't exist.",
        file_okay=False, dir_okay=True, show_default=True,
    ),
    api_key: str = typer.Option(
        lambda: settings.API_KEY if settings.API_KEY is not None else "",
        "--api-key", "-k",
        help="VirusTotal API Key. Can also be set via VT_API_KEY environment variable or in settings.py.",
        envvar="VT_API_KEY", show_default=False, 
    ),
    overwrite: bool = typer.Option(
        lambda: settings.OVERWRITE, 
        "--overwrite", "-o",
        help="Overwrite existing report files if they are already downloaded.",
        show_default=True,
    ),
    log_file_path: Path = typer.Option(
        lambda: Path(settings.LOG_FILE_PATH).resolve(), 
        "--log-file", "-l",
        help="Path to the log file. The log directory will be created if it doesn't exist.",
        show_default=True,
    ),
    api_interval: int = typer.Option(
        15, 
        "--interval", "-i",
        help="Interval in seconds between API calls (e.g., 15 for ~4 requests/minute).",
        min=0, show_default=True,
    )
):
    """
    Downloads VirusTotal reports for a list of SHA256 hashes.
    Configuration is primarily sourced from 'settings.py', but can be overridden by CLI options.
    The API key can also be provided via the VT_API_KEY environment variable.
    CLI options take precedence over environment variables, which take precedence over settings.py.
    """
    logger = getLogger(__name__) 
    logger.setLevel(INFO)        
    
    if logger.hasHandlers():
        logger.handlers.clear()

    log_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = FileHandler(log_file_path, encoding='utf-8')
    formatter = Formatter(
        "%(asctime)s %(levelname)-8s %(message)s", 
        datefmt='%Y-%m-%d %H:%M:%S'                  
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.info("--- VT Report Downloader Start ---")
    logger.info(f"Using Hash List: {hash_list_path}")
    logger.info(f"Download Directory: {download_dir}")
    logger.info(f"Log File: {log_file_path}")
    logger.info(f"Overwrite Mode: {'Enabled' if overwrite else 'Disabled'}")
    logger.info(f"API Call Interval: {api_interval}s")

    if not api_key:
        logger.error(
            "API Key is not provided. "
            "Please set it via the --api-key option, the VT_API_KEY environment variable, "
            "or ensure it is defined in settings.py."
        )
        raise typer.Exit(code=1) 

    try:
        download_dir.mkdir(parents=True, exist_ok=True) 
    except Exception as e:
        logger.error(f"Failed to create download directory {download_dir}: {e}")
        raise typer.Exit(code=1)

    vt_api_url_template = Template("https://www.virustotal.com/api/v3/files/${id}")
    existing_files = [file.stem.lower() for file in download_dir.glob("*.json")]
    
    processed_count = 0
    skipped_count = 0
    error_count = 0

    try:
        with hash_list_path.open(mode="r", encoding='utf-8') as f_hashes:
            hashes_to_process = [line.strip().lower() for line in f_hashes if line.strip()]
        
        if not hashes_to_process:
            logger.info("No hashes found in the hash list file.")
        else:
            logger.info(f"Found {len(hashes_to_process)} unique hashes to process.")

        for idx, sha256 in enumerate(hashes_to_process):
            if not (len(sha256) == 64 and all(c in "0123456789abcdef" for c in sha256)):
                logger.warning(f"Invalid SHA256 format for hash: '{sha256}'. Skipping.")
                error_count +=1
                continue

            logger.info(f"Processing hash {idx + 1}/{len(hashes_to_process)}: {sha256}")

            if not overwrite and sha256 in existing_files:
                logger.info(f"Skipped {sha256} (report already exists and overwrite is False).")
                skipped_count += 1
                continue

            response_data = call_vt_api(sha256, api_key, vt_api_url_template, logger)
            
            if response_data is None:
                # This path is now only taken for non-401, non-429 HTTP errors, or RequestExceptions
                logger.warning(f"Failed to get report for {sha256}. Skipping this hash.")
                error_count +=1
                if idx < len(hashes_to_process) - 1: 
                    time.sleep(api_interval)
                continue

            output_file_path: Path = download_dir / f"{sha256}.json"
            try:
                with output_file_path.open(mode="w", encoding='utf-8') as f_out:
                    f_out.write(json.dumps(response_data, indent=4)) 
                logger.info(f"Saved report for {sha256} to {output_file_path}")
                processed_count +=1
            except IOError as e:
                logger.error(f"Failed to save report for {sha256} to {output_file_path}: {e}")
                error_count +=1

            if idx < len(hashes_to_process) - 1:
                time.sleep(api_interval)

    except FileNotFoundError:
        logger.error(f"Hash list file not found: {hash_list_path}")
        raise typer.Exit(code=1)
    except typer.Exit: # Re-raise typer.Exit to ensure it propagates
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred during processing: {e}", exc_info=True)
        raise typer.Exit(code=1)
    finally:
        logger.info("--- VT Report Downloader End ---")
        logger.info(f"Summary: Reports Downloaded/Updated = {processed_count}, Skipped = {skipped_count}, Errors = {error_count}")

if __name__ == "__main__":
    app()
