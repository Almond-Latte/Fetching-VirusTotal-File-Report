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

def wait_until_utc_midnight(logger_instance: Any) -> None:
    """
    Pauses execution until the next UTC midnight.

    Args:
        logger_instance: The logger instance to use for logging messages.
    """
    now_utc: datetime = datetime.now(timezone.utc)
    # Calculate the next UTC midnight.
    # 
    next_midnight_utc: datetime = (now_utc + timedelta(days=1)).replace(
        hour=1, minute=0, second=0, microsecond=0, tzinfo=timezone.utc
    )
    
    wait_seconds: float = (next_midnight_utc - now_utc).total_seconds()
    
    logger_instance.info(
        f"Waiting for {wait_seconds:.0f} seconds (until {next_midnight_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}) to retry."
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
    Handles API errors, including rate limiting (429), by waiting and retrying.

    Args:
        sha256: The SHA256 hash of the file to look up.
        api_key: The VirusTotal API key.
        vt_api_url_template: A string.Template object for the VirusTotal API URL.
        logger_instance: The logger instance for logging.

    Returns:
        A dictionary containing the API response JSON if successful, None otherwise.
    """
    headers: Dict[str, str] = {"x-apikey": api_key}
    api_url = vt_api_url_template.substitute(id=sha256)
    logger_instance.info(f"Requesting VT report for {sha256} from {api_url}")

    try:
        # Make the GET request to VirusTotal API
        response = requests.get(api_url, headers=headers, timeout=30) # 30-second timeout
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        
        # If successful (status code 200), return the JSON response
        return response.json()
        
    except requests.exceptions.HTTPError as http_err:
        # Handle HTTP errors
        if http_err.response.status_code == 429: # HTTP 429: Too Many Requests (Quota Exceeded)
            logger_instance.warning(
                f"QuotaExceededError for {sha256}. Waiting until UTC midnight to request again."
            )
            wait_until_utc_midnight(logger_instance)
            # Retry the API call after waiting
            return call_vt_api(sha256, api_key, vt_api_url_template, logger_instance)
        else:
            # For other HTTP errors, log the error and return None
            logger_instance.error(f"HTTP error for {sha256}: {http_err.response.status_code} {http_err.response.text}")
            return None
    except requests.exceptions.RequestException as req_err:
        # Handle other request-related errors (e.g., network issues)
        logger_instance.error(f"Request error for {sha256}: {req_err}")
        return None


@app.command()
def main(
    hash_list_path: Path = typer.Option(
        lambda: Path(settings.HASH_LIST_PATH).resolve(), # Default from settings.py, resolved to absolute path
        "--hash-list", "-f",
        help="Path to the file containing SHA256 hashes (one per line).",
        exists=True,        # Path must exist
        file_okay=True,     # Must be a file
        dir_okay=False,     # Cannot be a directory
        readable=True,      # Must be readable
        show_default=True,  # Show default value in --help
    ),
    download_dir: Path = typer.Option(
        lambda: Path(settings.DOWNLOAD_DIR).resolve(), # Default from settings.py, resolved to absolute path
        "--download-dir", "-d",
        help="Directory to save the downloaded VirusTotal reports. Will be created if it doesn't exist.",
        file_okay=False,    # Cannot be a file
        dir_okay=True,      # Must be a directory (or creatable as one)
        show_default=True,
    ),
    api_key: str = typer.Option(
        # Default from settings.py. If settings.API_KEY is None, use empty string.
        # CLI/env var will override. Empty string will be caught by `if not api_key_to_use:` check.
        lambda: settings.API_KEY if settings.API_KEY is not None else "",
        "--api-key", "-k",
        help="VirusTotal API Key. Can also be set via VT_API_KEY environment variable or in settings.py.",
        envvar="VT_API_KEY", # Allow setting via environment variable
        show_default=False, # Do not show API key default in help message for security
    ),
    overwrite: bool = typer.Option(
        lambda: settings.OVERWRITE, # Default from settings.py
        "--overwrite", "-o",
        help="Overwrite existing report files if they are already downloaded.",
        show_default=True,
    ),
    log_file_path: Path = typer.Option(
        lambda: Path(settings.LOG_FILE_PATH).resolve(), # Default from settings.py, resolved to absolute path
        "--log-file", "-l",
        help="Path to the log file. The log directory will be created if it doesn't exist.",
        show_default=True,
    ),
    api_interval: int = typer.Option(
        15, # Default API call interval in seconds
        "--interval", "-i",
        help="Interval in seconds between API calls (e.g., 15 for ~4 requests/minute).",
        min=0, # Minimum interval is 0 seconds
        show_default=True,
    )
):
    """
    Downloads VirusTotal reports for a list of SHA256 hashes.
    Configuration is primarily sourced from 'settings.py', but can be overridden by CLI options.
    The API key can also be provided via the VT_API_KEY environment variable.
    CLI options take precedence over environment variables, which take precedence over settings.py.
    """
    # --- 1. Initialize Logger ---
    logger = getLogger(__name__) # Get a logger instance for this module
    logger.setLevel(INFO)        # Set minimum logging level to INFO
    
    # Clear any existing handlers to prevent duplicate logs if main() is called multiple times (e.g., in tests)
    if logger.hasHandlers():
        logger.handlers.clear()

    # Ensure the parent directory for the log file exists
    log_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure file handler for logging
    file_handler = FileHandler(log_file_path, encoding='utf-8')
    formatter = Formatter(
        "%(asctime)s %(levelname)-8s %(message)s", # Log format
        datefmt='%Y-%m-%d %H:%M:%S'                  # Timestamp format
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.info("--- VT Report Downloader Start ---")
    logger.info(f"Using Hash List: {hash_list_path}")
    logger.info(f"Download Directory: {download_dir}")
    logger.info(f"Log File: {log_file_path}")
    logger.info(f"Overwrite Mode: {'Enabled' if overwrite else 'Disabled'}")
    logger.info(f"API Call Interval: {api_interval}s")

    # --- 2. Validate API Key ---
    # The api_key parameter already holds the value resolved by Typer (CLI > env var > default lambda)
    if not api_key:
        logger.error(
            "API Key is not provided. "
            "Please set it via the --api-key option, the VT_API_KEY environment variable, "
            "or ensure it is defined in settings.py."
        )
        raise typer.Exit(code=1) # Exit if API key is missing

    # --- 3. Prepare Download Directory ---
    try:
        download_dir.mkdir(parents=True, exist_ok=True) # Create download directory if it doesn't exist
    except Exception as e:
        logger.error(f"Failed to create download directory {download_dir}: {e}")
        raise typer.Exit(code=1)

    # --- 4. Initialize Variables ---
    vt_api_url_template = Template("https://www.virustotal.com/api/v3/files/${id}")
    # Get a list of already downloaded report file stems (SHA256 hashes) for checking overwrite logic
    existing_files = [file.stem.lower() for file in download_dir.glob("*.json")]
    
    processed_count = 0
    skipped_count = 0
    error_count = 0

    # --- 5. Process Hashes ---
    try:
        # Read all hashes from the list file
        with hash_list_path.open(mode="r", encoding='utf-8') as f_hashes:
            hashes_to_process = [line.strip().lower() for line in f_hashes if line.strip()]
        
        if not hashes_to_process:
            logger.info("No hashes found in the hash list file.")
        else:
            logger.info(f"Found {len(hashes_to_process)} unique hashes to process.")

        for idx, sha256 in enumerate(hashes_to_process):
            # Basic validation for SHA256 hash format (length 64, hex characters)
            # This is a simple check; more robust validation could be added if needed.
            if not (len(sha256) == 64 and all(c in "0123456789abcdef" for c in sha256)):
                logger.warning(f"Invalid SHA256 format for hash: '{sha256}'. Skipping.")
                error_count +=1
                continue

            logger.info(f"Processing hash {idx + 1}/{len(hashes_to_process)}: {sha256}")

            # Skip if file exists and overwrite is not enabled
            if not overwrite and sha256 in existing_files:
                logger.info(f"Skipped {sha256} (report already exists and overwrite is False).")
                skipped_count += 1
                continue

            # Call the VirusTotal API
            response_data = call_vt_api(sha256, api_key, vt_api_url_template, logger)
            
            if response_data is None:
                logger.warning(f"Failed to get report for {sha256}. Skipping this hash.")
                error_count +=1
                # If there was an API error (not a quota error that caused a long wait),
                # still sleep for the normal interval before trying the next hash.
                if idx < len(hashes_to_process) - 1: # Sleep if not the last hash
                    time.sleep(api_interval)
                continue

            # Save the API response to a JSON file
            output_file_path: Path = download_dir / f"{sha256}.json"
            try:
                with output_file_path.open(mode="w", encoding='utf-8') as f_out:
                    # Dump JSON with an indent for better readability
                    f_out.write(json.dumps(response_data, indent=4)) 
                logger.info(f"Saved report for {sha256} to {output_file_path}")
                processed_count +=1
            except IOError as e:
                logger.error(f"Failed to save report for {sha256} to {output_file_path}: {e}")
                error_count +=1

            # Wait for the specified interval before the next API call, if not the last hash
            if idx < len(hashes_to_process) - 1:
                time.sleep(api_interval)

    except FileNotFoundError:
        logger.error(f"Hash list file not found: {hash_list_path}")
        raise typer.Exit(code=1)
    except Exception as e:
        # Catch any other unexpected errors during processing
        logger.error(f"An unexpected error occurred during processing: {e}", exc_info=True)
        raise typer.Exit(code=1)
    finally:
        # --- 6. Log Summary and End ---
        logger.info("--- VT Report Downloader End ---")
        logger.info(f"Summary: Reports Downloaded/Updated = {processed_count}, Skipped = {skipped_count}, Errors = {error_count}")

if __name__ == "__main__":
    # Entry point for the Typer CLI application
    app()