# Fetching VirusTotal File Report

![Static Badge](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue) ![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-orange)

This Python script retrieves file reports using the [VirusTotal API v3](https://www.virustotal.com/gui/home/upload). With just the file's hash value and a VirusTotal API Key, anyone can easily execute it.

[**日本語版はこちら**](README-ja.md)
## 🚀 Features
- **Easy File Report Retrieval**: Utilizes VirusTotal's [Get a file report](https://docs.virustotal.com/reference/file-info) API to easily fetch file reports.
- **Automation**: Sequentially and automatically retrieves data based on a list of hash values.
- **Error Handling**: Implements error handling, including processing for reaching [API limits](https://docs.virustotal.com/reference/public-vs-premium-api).
  - **Request Rate**: Accounts for the limit of 4 requests per minute and 500 requests per day.
  - **Waiting Function**: Automatically waits until the next day (Default, UTC 01:00) if the limit is exceeded.
- **Log Output**: Outputs execution logs in the `logs` directory. Log names are recorded in Japan Standard Time. 
- **Data Saving**: Saves the retrieved data in JSON format in the `vt_reports` directory.

## 📦 Installation

Clone from GitHub and install the necessary packages.

This project recommends using `uv` for package management.

```sh
git clone https://github.com/almond-latte/fetching-virustotal-file-report.git
cd fetching-virustotal-file-report
# If you don't have uv installed, please install it first.
# e.g., pip install uv  or  curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync
mv .env.sample .env
```
## 🔑 Setting Up the API Key and Hash Value List
In the `.env` file, write down the VirusTotal API key and the path to the file containing the list of hash values you want to investigate.

> [!NOTE]
> If you have not obtained a VirusTotal API Key, please follow the [VirusTotal API Reference](https://docs.virustotal.com/reference/overview) to obtain one.
## ▶ How to Execute
Run the script with the following command.

```sh
python3 get_file_report.py
```
🙏 Have a safe and secure digital life!
If you have any questions or feedback, feel free to post them on [Issues](https://github.com/almond-latte/fetching-virustotal-file-report/issues).
