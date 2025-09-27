# Phishing URL Risk Analyzer

## 📌 Overview
Scores URLs for phishing risk using simple heuristics (suspicious TLDs, keywords like “verify/login”, IP hosts, long URLs, many hyphens, `@`, no HTTPS). Outputs explainable results to CSV.

## 🛠️ Tech
Python 3 (optional: matplotlib for a quick bar chart)

## 🚀 Run
```bash
python phishing_url_analyzer.py --input urls.csv --output results.csv --plot
