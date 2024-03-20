# Fetching VirusTotal File Report

![Static Badge](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue) ![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-orange)

このPythonスクリプトは[VirusTotal API v3](https://www.virustotal.com/gui/home/upload)を用いてファイルレポートを取得します。調べたいファイルのハッシュ値とVirusTotal API Keyさえあれば、簡単に実行することができます。

## 🚀 特徴
- **ファイルレポートの簡単取得**: VirusTotalの[Get a file report](https://docs.virustotal.com/reference/file-info) APIを利用して、簡単にファイルレポートを取得できます。
- **自動化**: ハッシュ値リストをもとに、順次自動的にデータを取得します。
- **エラーハンドリング**: [API制限](https://docs.virustotal.com/reference/public-vs-premium-api)に達した場合の処理を含む、エラーハンドリングを実装。
  - **リクエストレート**: 1分に4リクエスト、1日500リクエストの制限を考慮。
  - **待機機能**: 制限を超えた場合は、次の日(UTC 00:00)まで自動的に待機。
- **ログ出力**: `log`ディレクトリに実行ログを出力。ログ名は日本標準時で記録されます。
- **データ保存**: `vt_reports`ディレクトリに、取得したデータをJSON形式で保存します。

## 📦 インストール

GitHubからクローンし、必要なパッケージをインストールしてください。

```sh
git clone https://github.com/almond-latte/fetching-virustotal-file-report.git
cd fetching-virustotal-file-report
pip3 install -r requirements.txt
mv .env.sample .env
```
## 🔑 APIキーとハッシュ値リストの設定
`.env` ファイルにVirusTotalのAPIキーと、調べたいファイルのハッシュ値リストファイルのパスを記述してください。

> [!NOTE]
>  VirusTotal API Keyを取得していない場合は、[VirusTotal API Reference](https://docs.virustotal.com/reference/overview)に従いAPI Keyを取得してください。

## ▶ 実行方法
下記のコマンドでスクリプトを実行します。

```sh
Copy code
python3 get_file_report.py
```

🙏 よいセキュリティライフを！
質問やフィードバックがある場合は、お気軽に[Issues](https://github.com/almond-latte/fetching-virustotal-file-report/issues)に投稿してください。

