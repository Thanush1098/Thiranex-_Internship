# 🎣 Phishing Email Detection Model

> Powered by Scikit-learn — Educational Edition

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run full training + evaluation + interactive mode
python phishing_detector.py

# Train, evaluate, skip interactive mode
python phishing_detector.py --no-interactive

# Train and save model to disk
python phishing_detector.py --save

# Load saved model and classify one email
python phishing_detector.py --load phishing_model.joblib \
  --predict "Your account has been compromised! Verify at http://scam.xyz now!"
```

---

## 📊 Results (Built-in Dataset)

| Model               | Accuracy | Precision | Recall | F1     | ROC-AUC |
|---------------------|----------|-----------|--------|--------|---------|
| Logistic Regression | 100.0%   | 100.0%    | 100.0% | 100.0% | 1.000   |
| Random Forest       | 96.0%    | 100.0%    | 91.7%  | 95.7%  | 1.000   |
| Gradient Boosting   | 96.0%    | 100.0%    | 91.7%  | 95.7%  | 1.000   |
| Linear SVM          | 96.0%    | 100.0%    | 91.7%  | 95.7%  | 1.000   |

---

## 🧩 Feature Engineering

### TF-IDF Text Features
- Unigrams + Bigrams (up to 3,000 features)
- Sublinear TF scaling
- English stopword removal

### Structural / Heuristic Features (24 total)

| Feature | Description |
|---------|-------------|
| `url_count` | Number of URLs in email |
| `suspicious_tld` | Detects .xyz, .tk, .ml, .ga, .cf domains |
| `url_mismatch` | Brand name (PayPal, Amazon…) in suspicious TLD |
| `has_ip_url` | URL contains raw IP instead of domain |
| `long_url` | URL length > 75 characters |
| `hyphen_in_domain` | Hyphens in domain (e.g. paypal-secure.xyz) |
| `urgent_count` | Count of urgency words |
| `phish_kw_hits` | Phishing keyword matches |
| `safe_kw_hits` | Professional/safe keyword matches |
| `has_winning` | Win/prize/lottery language |
| `asking_credentials` | Requests passwords, SSN, bank details |
| `caps_ratio` | Proportion of ALL CAPS characters |
| `exclamation_count` | Number of `!` marks |
| `has_money_amount` | Detects `$X,XXX` patterns |
| `sender_mismatch` | Brand name + free email provider |

---

## 🗂️ Dataset

- **122 labelled emails** (61 phishing, 61 legitimate)
- Fully embedded in the script — no downloads required
- Phishing examples cover: credential theft, lottery scams, fake alerts, CEO fraud, romance scams, package delivery, government impersonation
- Legitimate examples cover: work emails, GitHub notifications, newsletters, team messages, billing confirmations

---

## 🎓 Concepts Learned

- **TF-IDF Vectorization** — Term Frequency × Inverse Document Frequency
- **Feature Engineering** — Combining text + heuristic features
- **Model Comparison** — Logistic Regression vs. Random Forest vs. Gradient Boosting vs. SVM
- **Evaluation Metrics** — Accuracy, Precision, Recall, F1-Score, ROC-AUC
- **Confusion Matrix** — True Positives, False Positives, False Negatives, True Negatives
- **Class Imbalance** — Stratified train/test split
- **Model Persistence** — Save/load with joblib

---

## ⚠️ Disclaimer

This is an educational project. For production phishing detection, use dedicated security APIs (Google Safe Browsing, VirusTotal, etc.) in addition to ML models.
