# settings.py
import os
from pathlib import Path
from typing import Optional
from datetime import datetime # For default timestamped log file
from zoneinfo import ZoneInfo # For timezone (Python 3.9+)

from dotenv import load_dotenv

# --- Determine Base Directory for Relative Paths ---
# Paths defined in this settings file (if relative) or in .env (if relative)
# will be based on this directory (where settings.py is located).
SETTINGS_DIR = Path(__file__).resolve().parent

# --- Load .env File ---
# Load environment variables from a .env file located in the same directory as settings.py.
# Variables in .env can be overridden by actual system environment variables.
DOTENV_PATH: Path = SETTINGS_DIR / ".env"
if DOTENV_PATH.exists():
    load_dotenv(DOTENV_PATH, override=True)
    # For debugging, you might want to know if .env was loaded:
    # print(f"DEBUG: Loaded environment variables from: {DOTENV_PATH}")
else:
    # Optional: Notify if .env is not found, as it might be expected.
    # print(f"DEBUG: .env file not found at {DOTENV_PATH}. Using system environment variables or hardcoded defaults.")
    pass

# --- Helper Functions to Get Environment Variables ---

def get_env_var(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Fetches an environment variable, returning a default value if not set.
    The main Typer application will handle cases where essential settings are ultimately missing.
    """
    return os.getenv(key, default)

def get_env_var_bool(key: str, default: bool = False) -> bool:
    """
    Fetches an environment variable and converts it to a boolean.
    Considers "true", "1", "yes", "t" (case-insensitive) as True.
    """
    value = os.getenv(key)
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes", "t")

def get_env_var_path(key: str, default_filename_or_path: str, base_dir: Path = SETTINGS_DIR) -> Path:
    """
    Fetches an environment variable representing a path.
    If the path from env var is absolute, it's used as is (resolved).
    If relative, it's resolved relative to `base_dir`.
    If not in env var, `default_filename_or_path` is used (also resolved relative to `base_dir`).
    """
    value = os.getenv(key)
    path_to_resolve: Path
    if value:
        path_val = Path(value)
        if path_val.is_absolute():
            path_to_resolve = path_val
        else:
            # Interpret relative paths from .env as relative to where .env is (SETTINGS_DIR)
            path_to_resolve = base_dir / path_val
    else:
        # Default path, relative to base_dir (SETTINGS_DIR)
        path_to_resolve = base_dir / default_filename_or_path
    
    return path_to_resolve.resolve()

# --- Application Settings ---
# These values serve as defaults for the Typer CLI application.
# The Typer application will access these as `settings.VARIABLE_NAME`.
# The main Typer app handles final validation (e.g., path existence, writability),
# path resolution (if not already absolute by Typer's Path handling),
# and directory creation.

# VirusTotal API Key
# Defaulting to None if not found in environment; Typer app will error out if it's still None
# and not provided via CLI or its specific env var.
API_KEY: Optional[str] = get_env_var("API_KEY") # .env variable: API_KEY

# Default path to the file containing SHA256 hashes.
# The Typer app expects `settings.HASH_LIST_PATH`.
# Default is 'hashes.txt' in the same directory as settings.py.
HASH_LIST_PATH: Path = get_env_var_path("HASH_LIST_PATH", "hashes.txt") # .env variable: HASH_LIST_PATH

# Default for whether to overwrite existing report files.
# The Typer app expects `settings.OVERWRITE`.
OVERWRITE: bool = get_env_var_bool("OVERWRITE", False) # .env variable: OVERWRITE

# Default directory to save downloaded VirusTotal reports.
# The Typer app expects `settings.DOWNLOAD_DIR`.
# Note: The original settings.py used DOWNLOAD_DIR_PATH from .env.
# We'll check for "DOWNLOAD_DIR_PATH" for backward compatibility with an old .env,
# but prefer "DOWNLOAD_DIR" if available, then use a hardcoded default.
_download_dir_env = get_env_var("DOWNLOAD_DIR", get_env_var("DOWNLOAD_DIR_PATH")) # Prioritize DOWNLOAD_DIR
DOWNLOAD_DIR: Path = get_env_var_path(
    "DOWNLOAD_DIR", # This key is primarily for documentation, value is already in _download_dir_env
    "vt_reports_downloaded", # Default folder name if neither env var is set
)
if _download_dir_env: # If DOWNLOAD_DIR or DOWNLOAD_DIR_PATH was in .env, use that value for get_env_var_path
    _env_path = Path(_download_dir_env)
    if _env_path.is_absolute():
        DOWNLOAD_DIR = _env_path.resolve()
    else:
        DOWNLOAD_DIR = (SETTINGS_DIR / _env_path).resolve()


# Default path for the log file.
# The Typer app expects `settings.LOG_FILE_PATH`.
# This version restores the timestamped log file name as a default behavior,
# with logs placed in a 'logs' subdirectory relative to settings.py,
# unless LOG_FILE_PATH is specified in .env.
_log_dir_default: Path = SETTINGS_DIR / "logs" # Default log directory
_log_filename_default: str = f"vt_downloader_{datetime.now(ZoneInfo('Asia/Tokyo')):%Y%m%d_%H%M%S}.log"

_log_file_env_value = get_env_var("LOG_FILE_PATH")
if _log_file_env_value:
    _log_path_from_env = Path(_log_file_env_value)
    if _log_path_from_env.is_absolute():
        LOG_FILE_PATH = _log_path_from_env.resolve()
    else:
        # Relative path from .env is resolved against SETTINGS_DIR
        LOG_FILE_PATH = (SETTINGS_DIR / _log_path_from_env).resolve()
else:
    # Default timestamped log file in the default log directory
    LOG_FILE_PATH: Path = (_log_dir_default / _log_filename_default).resolve()

# --- End of settings.py ---
# This file should not perform actions like creating directories or exiting the program.
# It serves solely as a configuration provider for the main application.
# The main Typer application is responsible for validating these settings
# (e.g., checking if HASH_LIST_PATH exists and is a file before trying to read it,
# or creating DOWNLOAD_DIR and log_file_path.parent if they don't exist).
