#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║        🎣  Phishing Email Detection Model                       ║
║        Powered by Scikit-learn — Educational Edition            ║
╚══════════════════════════════════════════════════════════════════╝

Features:
  • Rich built-in labelled dataset (phishing + legitimate emails)
  • Multi-feature extraction: TF-IDF, URL features, header signals
  • Trains & compares 4 ML models
  • Detailed evaluation: accuracy, precision, recall, F1, ROC-AUC
  • Confusion matrix (ASCII + optional matplotlib)
  • Interactive email classifier (type your own email to test)
  • Model persistence (save/load with joblib)
"""

# ── Stdlib ────────────────────────────────────────────────────────────
import re
import sys
import json
import time
import datetime
import warnings
import argparse
from urllib.parse import urlparse

warnings.filterwarnings("ignore")

# ── Third-party ───────────────────────────────────────────────────────
try:
    import numpy as np
    import pandas as pd
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline, FeatureUnion
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.svm import LinearSVC
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix,
        classification_report, roc_curve
    )
    from sklearn.base import BaseEstimator, TransformerMixin
    import joblib
except ImportError as e:
    print(f"\n❌  Missing dependency: {e}")
    print("    Install with:  pip install scikit-learn pandas numpy joblib\n")
    sys.exit(1)

# ── ANSI colours ─────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m";  BOLD   = "\033[1m";  DIM    = "\033[2m"
    RED    = "\033[91m"; YELLOW = "\033[93m"; GREEN  = "\033[92m"
    CYAN   = "\033[96m"; BLUE   = "\033[94m"; MAGENTA= "\033[95m"
    WHITE  = "\033[97m"

def clr(t, *codes): return "".join(codes) + str(t) + C.RESET
def sep(char="─", n=65): return clr(char * n, C.DIM)

# ══════════════════════════════════════════════════════════════════════
#  DATASET  — 120 labelled emails (60 phishing, 60 legitimate)
# ══════════════════════════════════════════════════════════════════════
DATASET = [
    # ── PHISHING (label=1) ────────────────────────────────────────────
    ("Urgent: Your account has been compromised! Click http://secure-login.xyz/verify now to restore access before it's permanently deleted.", 1),
    ("Congratulations! You have won $1,000,000 in the International Lottery. Send your bank details to claim@prize-winner.net immediately.", 1),
    ("Dear Customer, your PayPal account is limited. Verify your identity at http://paypal-secure.update-info.com/login or lose access.", 1),
    ("ALERT: Unauthorized login detected on your Netflix account from Russia. Reset password: http://netflix-alert.support-reset.com/pw", 1),
    ("Your Amazon order #29384 is on hold. Confirm payment details at http://amazon-verify.billing-update.xyz/confirm within 24 hours.", 1),
    ("FINAL WARNING: IRS owes you $3,200 tax refund. Claim at http://irs-refund.gov-claim.net/apply before deadline expires today.", 1),
    ("Your bank account will be suspended. Provide your SSN and card number at http://citibank-secure.verify-now.com/update immediately.", 1),
    ("FREE iPhone 15 Pro! You were selected. Click http://iphone-giveaway.win-prizes.xyz/claim and enter details to receive your prize.", 1),
    ("SECURITY ALERT: Your Apple ID was used to purchase $499.99. Cancel at http://apple-support.id-secure.net/cancel if not you.", 1),
    ("Dear user, your email storage is 99% full. Upgrade FREE at http://mail-storage.cloud-upgrade.xyz/extend or lose your emails.", 1),
    ("Verify your account now! Your access expires in 2 hours. Login at http://secure.account-verify.info/login or be locked out.", 1),
    ("You have a pending wire transfer of $5,000 awaiting approval. Authorize at http://bank-wire.transfer-now.net/approve immediately.", 1),
    ("HR Department: Click this link http://company-portal.login-update.xyz/hr to update your direct deposit info before Friday payroll.", 1),
    ("Your crypto wallet was accessed from an unknown device. Secure it NOW at http://binance-secure.wallet-protect.com/verify", 1),
    ("Congratulations! Your survey is complete. Claim your $500 Amazon gift card at http://survey-reward.amazon-gifts.xyz/redeem today!", 1),
    ("URGENT: Your Microsoft 365 license expires TODAY. Renew at http://microsoft-license.renew-now.xyz/pay or lose access immediately.", 1),
    ("DHL Delivery Failed: Package 3847291 could not be delivered. Reschedule at http://dhl-tracking.delivery-failed.net/reschedule", 1),
    ("Your social security number has been suspended due to suspicious activity. Call 1-800-555-0199 or visit http://ssa-alert.gov-verify.net", 1),
    ("ACCOUNT DEACTIVATION NOTICE: Confirm you still use this account by clicking http://email-verify.account-active.xyz/confirm now.", 1),
    ("You have 1 unread voicemail. Listen at http://voicemail.access-now.xyz/play — message expires in 24 hours. Click immediately!", 1),
    ("Your Google account password was recently changed. If this wasn't you, recover at http://google-recovery.accounts-secure.net", 1),
    ("WINNER! Your phone number was selected in our weekly draw. Claim $750 reward at http://mobile-winner.cash-prize.xyz/claim", 1),
    ("Suspicious transaction: $299 charged to your Visa ending 4839. Dispute at http://visa-dispute.card-secure.net/report right away.", 1),
    ("IT Support: Your VPN credentials have expired. Update them at http://vpn-portal.company-login.xyz/renew before Monday morning.", 1),
    ("LAST CHANCE: Your Dropbox files will be permanently deleted in 24hrs. Recover them: http://dropbox-recover.files-restore.net", 1),
    ("Click here to receive your $200 Walmart gift card reward! Limited time: http://walmart-rewards.gift-now.xyz/redeem expires soon.", 1),
    ("Federal Bureau Notice: You are under investigation. Respond at http://fbi-notice.legal-action.xyz/respond or face arrest warrant.", 1),
    ("Unusual sign-in activity detected on your LinkedIn. Verify at http://linkedin-secure.profile-verify.net/confirm immediately.", 1),
    ("Your Spotify Premium subscription could not be renewed. Update billing: http://spotify-billing.payment-update.xyz/update now.", 1),
    ("VIRUS DETECTED on your device! Remove it immediately: http://antivirus-alert.scan-now.xyz/remove — act within 30 minutes!", 1),
    ("Your inheritance of $4.5M is ready for transfer. Contact barrister.james@inheritance-claim.net with your bank details.", 1),
    ("Tax authority: You have an unpaid fine of $850. Pay immediately at http://tax-fine.gov-payment.net/pay to avoid legal action.", 1),
    ("Admin alert: Multiple failed login attempts on your WordPress site. Review access log: http://wp-admin.security-alert.xyz/log", 1),
    ("Your Uber account was logged in from a new device. If not you, reset: http://uber-account.security-reset.net/verify now!", 1),
    ("PRIZE NOTIFICATION: You won a luxury cruise vacation! Register at http://cruise-winner.vacation-prize.xyz/register by midnight.", 1),
    ("Hello Dear, I am a prince from Nigeria seeking your assistance to transfer $18 million. Reply to help.transfer@yahoo.com for details.", 1),
    ("Warning: Child Support Services issued a warrant for your arrest. Resolve at http://child-support.legal-warrant.net immediately.", 1),
    ("Your iCloud storage is full. Get 200GB FREE at http://icloud-upgrade.apple-storage.xyz/free — offer expires tonight at midnight.", 1),
    ("Confirm your identity to receive your COVID-19 stimulus check of $1,400 at http://irs-stimulus.gov-relief.xyz/claim today.", 1),
    ("SECURITY BREACH: Your Instagram password was changed. Undo this at http://instagram-recovery.account-secure.net/undo now!", 1),
    ("Package could not be delivered. USPS requires $1.99 fee: http://usps-delivery.package-hold.xyz/pay — pay within 24 hours.", 1),
    ("Your loan application was pre-approved for $50,000 at 0% interest! Accept at http://loan-approved.quick-cash.xyz/accept today.", 1),
    ("CEO request: Wire $25,000 to vendor account immediately. This is urgent and confidential. Reply to ceo.transfer@gmail-corp.net", 1),
    ("Dear beneficiary, your ATM card with $2.5M has been dispatched. Provide details at funds.release@claimcenter.net to receive.", 1),
    ("Your subscription to Adobe Creative Cloud failed. Update payment: http://adobe-billing.account-update.xyz/payment or cancel.", 1),
    ("Attention employee: Complete mandatory security training at http://hr-training.company-portal.xyz/login using your work credentials.", 1),
    ("Your Twitter/X account has been flagged for unusual activity. Verify: http://twitter-verify.account-restore.net/confirm now.", 1),
    ("FINAL DEMAND: Pay overdue utility bill of $389 at http://utility-payment.bill-now.xyz/pay before service disconnection tonight.", 1),
    ("Claim your free $1,000 Costco membership card: http://costco-reward.free-card.xyz/claim — only 3 remaining! Act fast.", 1),
    ("Your WhatsApp account was registered on a new phone. Not you? Verify at http://whatsapp-secure.account-protect.net/verify", 1),
    ("STUDENT LOAN FORGIVENESS approved for $37,500. Claim at http://student-relief.loan-forgive.xyz/apply before program ends Friday.", 1),
    ("Your FedEx package requires customs clearance fee of $3.49. Pay at http://fedex-customs.package-release.xyz/pay to release.", 1),
    ("Account locked: Too many failed attempts on your Chase Bank app. Unlock at http://chase-unlock.bank-secure.net/restore now.", 1),
    ("You have been selected for a clinical trial paying $5,000. Register: http://clinical-trial.paid-study.xyz/register — limited spots!", 1),
    ("Zoom security update required. Download patch at http://zoom-update.security-patch.xyz/install — mandatory for all employees.", 1),
    ("Your renewal for Norton 360 has been processed: $449.99. Cancel within 24hrs at http://norton-cancel.billing-refund.xyz/cancel", 1),
    ("BITCOIN ALERT: Your Coinbase wallet requires verification. Complete at http://coinbase-verify.wallet-secure.net/kyc to continue.", 1),
    ("Romance scam: Hello dear, I found you online. I am a widow with $3M inheritance seeking a trustworthy person. Email me back.", 1),
    ("Your DocuSign document is ready for signature. Click http://docusign-sign.esignature.xyz/document to review and sign immediately.", 1),
    ("EXCLUSIVE: Make $5,000/week from home guaranteed! Start at http://work-from-home.cash-daily.xyz/register — no experience needed.", 1),
    ("Microsoft tech support: Critical virus found on your PC. Call 1-888-555-0123 or visit http://microsoft-support.fix-now.xyz/scan", 1),

    # ── LEGITIMATE (label=0) ──────────────────────────────────────────
    ("Hi John, just a reminder about our team meeting tomorrow at 10 AM in conference room B. Please bring your project updates. Thanks!", 0),
    ("Your GitHub pull request #142 has been reviewed and approved by @teammate. You can now merge into the main branch.", 0),
    ("Hello, your order #ORD-20948 has shipped and will arrive by Thursday. Track it at amazon.com/orders using your account.", 0),
    ("Monthly newsletter: Check out our latest blog posts on Python best practices, Docker tips, and cloud architecture patterns.", 0),
    ("Your flight booking PNR: XYZ789 is confirmed for Dec 15. Check-in opens 24 hours before departure at united.com or the app.", 0),
    ("Hi Sarah, attached is the Q3 financial report we discussed. Let me know if you need any clarifications. Best, Michael", 0),
    ("Your Spotify playlist 'Chill Vibes' was updated with 3 new songs. Open the Spotify app to listen.", 0),
    ("Welcome to GitHub! Your account has been created. Start by exploring repositories or creating your first project.", 0),
    ("Stack Overflow: Someone answered your question about Python list comprehensions. Click to view the accepted answer.", 0),
    ("Your scheduled AWS maintenance window is this Sunday from 2-4 AM UTC. No action needed; services will resume automatically.", 0),
    ("Hi team, please review the updated project timeline I shared on Google Drive. Comments and feedback are welcome by Friday.", 0),
    ("Your LinkedIn connection request from Jane Doe (Senior Engineer at Google) has been accepted. View her profile to connect.", 0),
    ("Reminder: Your dentist appointment is scheduled for tomorrow at 3:30 PM with Dr. Smith. Call 555-0100 to reschedule.", 0),
    ("Your npm package 'react-utils' version 2.3.1 has been published successfully. View it at npmjs.com/package/react-utils.", 0),
    ("Dear student, your assignment submission for CS101 has been received and graded. Log in to the student portal to view feedback.", 0),
    ("Hi there, just checking in to see how the proposal is coming along. Let me know if you need any help. Cheers, David", 0),
    ("Your annual subscription to The New York Times has been renewed at $17/month. Manage at nytimes.com/account.", 0),
    ("Security tip of the week: Enable two-factor authentication on all your accounts to significantly reduce breach risk.", 0),
    ("Your Google Drive storage usage report: 8.2 GB of 15 GB used. Manage storage at drive.google.com/settings.", 0),
    ("Meeting notes from today's standup are now available in Confluence. Action items have been assigned in Jira.", 0),
    ("Congratulations on completing the Python Data Science course! Your certificate is ready to download from Coursera.", 0),
    ("Your pull request to fix the database connection bug has been merged. Thanks for the quick turnaround, great work!", 0),
    ("Hi, the client has approved the final design mockups. We can proceed to the development phase starting Monday.", 0),
    ("Your electricity bill for November is $87.42. Payment is due by December 15. Pay at your utility provider's website.", 0),
    ("The Docker image you pushed to ECR has passed all security scans. Deployment to staging is now unblocked.", 0),
    ("Your Medium article 'Introduction to Machine Learning' received 500 claps. Great engagement from the community!", 0),
    ("Reminder: Please submit your timesheet for the week ending Friday by 5 PM. Contact HR if you have questions.", 0),
    ("Your Zoom license has been renewed for another year. No action needed. Manage settings at zoom.us/account.", 0),
    ("Hi Dr. Johnson, the lab results are ready. Please log in to the patient portal at healthsystem.org to review.", 0),
    ("Your two-factor authentication code is 847291. This code expires in 10 minutes. Do not share it with anyone.", 0),
    ("New comment on your GitHub issue #89: 'I reproduced the bug on Python 3.11 as well. Working on a fix now.'", 0),
    ("Your weekly summary from Slack: 47 messages, 12 channels active. You were mentioned 5 times. Check the app.", 0),
    ("Team lunch is planned for Friday at noon at Chipotle on Main St. RSVP to this email if you're joining us.", 0),
    ("Your Jenkins CI pipeline 'backend-prod' passed all tests. Build #347 is ready for manual deployment approval.", 0),
    ("Dear valued customer, your bank statement for October is now available. Log in to your bank's official website to view.", 0),
    ("Hi Professor, I wanted to follow up on our last discussion about neural networks. Could we schedule a call next week?", 0),
    ("Your Adobe subscription was renewed. You can manage your plan, payment method, and apps from account.adobe.com.", 0),
    ("The code review for feature/user-auth is complete. Two minor comments added — please address before merging.", 0),
    ("Your annual performance review has been scheduled for December 3rd at 2 PM. Details in the HR portal.", 0),
    ("Hello, your library book 'Clean Code' by Robert Martin is due in 3 days. Renew at the library website or app.", 0),
    ("Your Heroku app detected a memory alert at 512MB. Review dyno metrics and consider scaling at dashboard.heroku.com.", 0),
    ("Invitation: You've been added to the 'Q4 Planning' Google Calendar event on November 28. RSVP from your calendar.", 0),
    ("Hi, the API rate limiting issue has been resolved in production. All endpoints are operating normally now.", 0),
    ("Your freelance invoice #INV-1047 to Acme Corp for $2,400 has been paid. View receipt in your QuickBooks account.", 0),
    ("Good morning! Your daily standup starts in 15 minutes. Join via the Zoom link saved in the team channel.", 0),
    ("The npm audit report found 2 moderate vulnerabilities in your project dependencies. Run npm audit fix to resolve.", 0),
    ("Your package from Best Buy has been delivered to your front door at 2:34 PM. Photo proof in the UPS app.", 0),
    ("We've updated our Terms of Service effective January 1. Review the changes at our official website. No action needed.", 0),
    ("Hi, just wanted to share this great article on microservices architecture I found: martinfowler.com/articles/microservices.html", 0),
    ("Your PostgreSQL database backup completed successfully at 03:00 UTC. Backup size: 4.2 GB. Next backup: tomorrow.", 0),
    ("Reminder: Company all-hands meeting is this Thursday at 3 PM EST. Dial-in info in the calendar invite.", 0),
    ("Your Kaggle notebook 'EDA on Titanic Dataset' received 150 upvotes. Thank you for contributing to the community!", 0),
    ("Hi, the client reported a bug in the checkout flow. I've opened ticket PROJ-412 and assigned it to the team.", 0),
    ("Your monthly gym membership of $35 has been charged to your card ending in 4521. Manage at gymportal.com.", 0),
    ("New Slack message from @devteam: 'The staging environment is ready for QA testing. Please prioritize login flows.'", 0),
    ("Your annual tax documents (W-2) are now available from your employer's payroll portal. Download before March 15.", 0),
    ("Hello, this is a reminder that the board meeting is on the 20th. Please submit your department reports by the 18th.", 0),
    ("Your GitHub Copilot subscription has been renewed. Continue coding smarter at github.com/features/copilot.", 0),
    ("Hi, following up on the project proposal — the client loved the approach and wants to start the next sprint early.", 0),
    ("Your Duolingo streak is on fire! You've been learning Spanish for 30 days. Keep it up — practice today to maintain it.", 0),
    ("Security reminder from IT: Please update your corporate password before December 1 per our 90-day rotation policy.", 0),
]


# ══════════════════════════════════════════════════════════════════════
#  FEATURE EXTRACTION
# ══════════════════════════════════════════════════════════════════════
class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extracts numerical features from raw email text."""

    # Known phishing / suspicious URL keywords
    PHISHING_KEYWORDS = [
        "urgent", "verify", "confirm", "click here", "limited time",
        "expire", "suspend", "unusual activity", "unauthorized", "immediately",
        "free", "winner", "congratulations", "claim", "selected",
        "prize", "lottery", "reward", "gift card", "lucky",
        "bank", "account", "password", "login", "credit card", "ssn",
        "social security", "wire transfer", "bitcoin", "cryptocurrency",
        "invoice", "payment due", "overdue", "arrest", "warrant",
        "irs", "tax refund", "stimulus", "government",
        "prince", "inheritance", "million", "beneficiary",
    ]
    SAFE_KEYWORDS = [
        "meeting", "schedule", "team", "project", "update",
        "report", "newsletter", "subscription", "renewed",
        "pull request", "merged", "deployment", "standup",
        "github", "jira", "confluence", "slack",
    ]

    def fit(self, X, y=None): return self

    def transform(self, X):
        return np.array([self._extract(text) for text in X])

    def _extract(self, text: str) -> list:
        t = text.lower()
        urls = re.findall(r'https?://\S+', t)
        words = re.findall(r'\b\w+\b', t)
        word_count = len(words) or 1

        # URL features
        url_count          = len(urls)
        has_ip_url         = int(bool(re.search(r'https?://\d+\.\d+\.\d+\.\d+', t)))
        suspicious_tld     = int(any(re.search(r'\.(xyz|net|info|tk|ml|ga|cf|click|top|gq|pw)', u) for u in urls))
        long_url           = int(any(len(u) > 75 for u in urls))
        url_mismatch       = int(bool(re.search(r'(paypal|amazon|google|apple|microsoft|netflix|bank)[^.]*\.(xyz|net|info|tk|ml|ga|cf)', t)))
        hyphen_in_domain   = int(any('-' in urlparse(u).netloc for u in urls))
        numeric_in_domain  = int(any(re.search(r'\d{4,}', urlparse(u).netloc) for u in urls))
        subdomain_depth    = max((urlparse(u).netloc.count('.') for u in urls), default=0)

        # Text / urgency features
        urgent_count       = sum(t.count(k) for k in ["urgent", "immediately", "expire", "final warning", "last chance"])
        exclamation_count  = text.count('!')
        caps_ratio         = sum(1 for c in text if c.isupper()) / (len(text) or 1)
        phish_kw_hits      = sum(1 for k in self.PHISHING_KEYWORDS if k in t)
        safe_kw_hits       = sum(1 for k in self.SAFE_KEYWORDS if k in t)
        has_money_amount   = int(bool(re.search(r'\$[\d,]+', text)))
        has_phone_number   = int(bool(re.search(r'\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b', text)))
        has_winning        = int(bool(re.search(r'\b(won|winner|congratulations|prize|lottery|selected)\b', t)))
        asking_credentials = int(bool(re.search(r'\b(password|ssn|social security|bank account|credit card|cvv|pin)\b', t)))
        sender_mismatch    = int(bool(re.search(r'(gmail|yahoo|hotmail)\.(com)', t) and re.search(r'(bank|irs|microsoft|apple|amazon)', t)))
        reply_to_different = int(bool(re.search(r'reply.?to.{0,30}@', t)))
        has_tracking_pixel = int('<img' in t and 'width=1' in t or 'height=1' in t)
        html_in_text       = int(bool(re.search(r'<[a-z]+>', t)))

        # Text stats
        avg_word_len       = sum(len(w) for w in words) / word_count
        text_length        = len(text)
        unique_word_ratio  = len(set(words)) / word_count

        return [
            url_count, has_ip_url, suspicious_tld, long_url, url_mismatch,
            hyphen_in_domain, numeric_in_domain, subdomain_depth,
            urgent_count, exclamation_count, caps_ratio,
            phish_kw_hits, safe_kw_hits, has_money_amount,
            has_phone_number, has_winning, asking_credentials,
            sender_mismatch, reply_to_different,
            has_tracking_pixel, html_in_text,
            avg_word_len, text_length, unique_word_ratio,
        ]

    FEATURE_NAMES = [
        "url_count","has_ip_url","suspicious_tld","long_url","url_mismatch",
        "hyphen_in_domain","numeric_in_domain","subdomain_depth",
        "urgent_count","exclamation_count","caps_ratio",
        "phish_kw_hits","safe_kw_hits","has_money_amount",
        "has_phone_number","has_winning","asking_credentials",
        "sender_mismatch","reply_to_different",
        "has_tracking_pixel","html_in_text",
        "avg_word_len","text_length","unique_word_ratio",
    ]


# ══════════════════════════════════════════════════════════════════════
#  DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════
BANNER = f"""
{C.CYAN}{C.BOLD}
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝
  ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
  ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝
{C.RESET}{C.DIM}       Email Phishing Detection Model — Educational Edition v1.0{C.RESET}
"""

def print_banner(): print(BANNER)

def print_confusion_matrix(cm, labels=("Safe","Phishing")):
    print(clr("\n  Confusion Matrix:", C.BOLD))
    print(f"  {'':<12} {'Pred Safe':>10} {'Pred Phish':>12}")
    print(f"  {sep('─',35)}")
    row_labels = ["Actual Safe ", "Actual Phish"]
    for i, row in enumerate(cm):
        cells = []
        for j, val in enumerate(row):
            colour = C.GREEN if i == j else C.RED
            cells.append(clr(f"{val:^10}", colour + C.BOLD))
        print(f"  {row_labels[i]:<12} {''.join(cells)}")
    print()

def progress_bar(val, total, width=30, colour=C.GREEN):
    filled = int(width * val / total) if total else 0
    bar = "█" * filled + "░" * (width - filled)
    return clr(bar, colour) + f" {val/total*100:.1f}%" if total else ""

def print_model_table(results):
    print(clr(f"\n  {'Model':<26} {'Acc':>7} {'Prec':>7} {'Recall':>7} {'F1':>7} {'AUC':>7}", C.BOLD + C.WHITE))
    print("  " + sep("─", 63))
    best_f1  = max(r["f1"]  for r in results.values())
    best_acc = max(r["acc"] for r in results.values())
    for name, r in results.items():
        acc_c  = C.GREEN  if r["acc"] == best_acc else C.WHITE
        f1_c   = C.CYAN   if r["f1"]  == best_f1  else C.WHITE
        star   = clr(" ★", C.YELLOW) if r["f1"] == best_f1 else "  "
        acc_str  = f"{r['acc']*100:.1f}%"
        prec_str = f"{r['prec']*100:.1f}%"
        rec_str  = f"{r['rec']*100:.1f}%"
        f1_str   = f"{r['f1']*100:.1f}%"
        auc_str  = f"{r['auc']:.3f}"
        print(f"  {name:<26}{star}"
              f" {clr(acc_str, acc_c):>14}"
              f" {prec_str:>7}"
              f" {rec_str:>7}"
              f" {clr(f1_str, f1_c):>14}"
              f" {auc_str:>7}")

def print_top_features(vectorizer, model, n=15):
    """Print top TF-IDF features for Random Forest / LogReg."""
    try:
        feature_names = vectorizer.get_feature_names_out()
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
        elif hasattr(model, "coef_"):
            importances = np.abs(model.coef_[0])
        else:
            return
        # Only TF-IDF portion
        top_idx = np.argsort(importances[:len(feature_names)])[-n:][::-1]
        print(clr(f"\n  Top {n} Predictive Words (TF-IDF):", C.BOLD))
        for rank, i in enumerate(top_idx, 1):
            bar = "█" * int(importances[i] / importances[top_idx[0]] * 20)
            word = clr(f"{feature_names[i]:<20}", C.CYAN)
        print(f"  {rank:>3}. {word} {clr(bar, C.MAGENTA)} {importances[i]:.4f}")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════
#  CORE PIPELINE
# ══════════════════════════════════════════════════════════════════════
class PhishingDetector:
    def __init__(self):
        self.tfidf     = TfidfVectorizer(ngram_range=(1, 2), max_features=3000,
                                          sublinear_tf=True, stop_words="english")
        self.struct_ex = StructuralFeatureExtractor()
        self.models    = {
            "Logistic Regression":      LogisticRegression(max_iter=1000, C=1.0),
            "Random Forest":            RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1),
            "Gradient Boosting":        GradientBoostingClassifier(n_estimators=150, random_state=42),
            "Linear SVM":               LinearSVC(max_iter=2000, C=1.0),
        }
        self.best_model      = None
        self.best_model_name = None
        self.results         = {}
        self._tfidf_matrix   = None   # for feature display

    # ── Data Prep ────────────────────────────────────────────────────
    def prepare_data(self):
        texts  = [d[0] for d in DATASET]
        labels = [d[1] for d in DATASET]
        df = pd.DataFrame({"text": texts, "label": labels})
        print(clr(f"  Dataset: {len(df)} samples — "
                  f"{sum(labels)} phishing, {len(labels)-sum(labels)} legitimate", C.DIM))
        return df

    def build_features(self, texts, fit=False):
        """Combine TF-IDF + structural features."""
        if fit:
            tfidf_mat  = self.tfidf.fit_transform(texts).toarray()
        else:
            tfidf_mat  = self.tfidf.transform(texts).toarray()
        struct_mat = self.struct_ex.transform(texts)
        return np.hstack([tfidf_mat, struct_mat])

    # ── Training ─────────────────────────────────────────────────────
    def train(self, visualize=False):
        print(clr("\n[1/4] Loading and preparing dataset…", C.BOLD))
        df = self.prepare_data()
        X_train, X_test, y_train, y_test = train_test_split(
            df["text"].tolist(), df["label"].tolist(),
            test_size=0.2, random_state=42, stratify=df["label"].tolist()
        )
        print(clr(f"  Train: {len(X_train)} | Test: {len(X_test)}", C.DIM))

        print(clr("\n[2/4] Extracting features (TF-IDF + Structural)…", C.BOLD))
        X_train_f = self.build_features(X_train, fit=True)
        X_test_f  = self.build_features(X_test,  fit=False)
        self._tfidf_matrix = X_train_f
        print(clr(f"  Feature matrix shape: {X_train_f.shape}", C.DIM))

        print(clr("\n[3/4] Training & evaluating models…", C.BOLD))
        best_f1   = -1
        skf       = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

        for name, model in self.models.items():
            t0 = time.time()
            model.fit(X_train_f, y_train)
            y_pred = model.predict(X_test_f)

            # AUC — not all models have predict_proba
            try:
                y_prob = model.predict_proba(X_test_f)[:, 1]
                auc = roc_auc_score(y_test, y_prob)
            except AttributeError:
                try:
                    y_score = model.decision_function(X_test_f)
                    auc = roc_auc_score(y_test, y_score)
                except Exception:
                    auc = 0.0

            acc  = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, zero_division=0)
            rec  = recall_score(y_test, y_pred, zero_division=0)
            f1   = f1_score(y_test, y_pred, zero_division=0)
            cm   = confusion_matrix(y_test, y_pred)
            elapsed = time.time() - t0

            self.results[name] = dict(
                acc=acc, prec=prec, rec=rec, f1=f1, auc=auc,
                cm=cm, model=model, elapsed=elapsed, y_pred=y_pred, y_test=y_test
            )
            icon = clr("✅", C.GREEN) if f1 > 0.85 else clr("⚠️ ", C.YELLOW)
            print(f"  {icon} {name:<28} F1={clr(f'{f1*100:.1f}%', C.CYAN)}  "
                  f"Acc={f'{acc*100:.1f}%'}  ({elapsed:.2f}s)")

            if f1 > best_f1:
                best_f1              = f1
                self.best_model      = model
                self.best_model_name = name
                self._best_cm        = cm
                self._y_test         = y_test
                self._y_pred         = y_pred

        print(clr(f"\n  🏆 Best model: {self.best_model_name} (F1={best_f1*100:.1f}%)", C.GREEN + C.BOLD))

    # ── Report ───────────────────────────────────────────────────────
    def report(self):
        print(clr(f"\n[4/4] Generating evaluation report…", C.BOLD))
        print(sep())
        print(clr("  📊  MODEL COMPARISON", C.BOLD + C.WHITE))
        print(sep())
        print_model_table(self.results)

        print(f"\n{sep()}")
        print(clr(f"  🏆  BEST MODEL DETAILS: {self.best_model_name}", C.BOLD + C.YELLOW))
        print(sep())

        r = self.results[self.best_model_name]
        metrics = [
            ("Accuracy",  r["acc"],  C.GREEN),
            ("Precision", r["prec"], C.CYAN),
            ("Recall",    r["rec"],  C.BLUE),
            ("F1-Score",  r["f1"],   C.MAGENTA),
            ("ROC-AUC",   r["auc"],  C.YELLOW),
        ]
        for label, val, colour in metrics:
            bar = progress_bar(val, 1.0, width=28, colour=colour)
            print(f"  {label:<12} {clr(f'{val*100:.2f}%', colour + C.BOLD):>12}  {bar}")

        print_confusion_matrix(r["cm"])

        print(clr("  📋  Classification Report:", C.BOLD))
        print(classification_report(
            r["y_test"], r["y_pred"],
            target_names=["✅ Safe", "🎣 Phishing"],
            digits=3
        ))

        # Feature importance
        print_top_features(self.tfidf, self.best_model)

    # ── Predict ──────────────────────────────────────────────────────
    def predict_email(self, email_text: str) -> dict:
        if self.best_model is None:
            raise RuntimeError("Model not trained yet. Call .train() first.")
        X = self.build_features([email_text], fit=False)
        pred = self.best_model.predict(X)[0]

        # Confidence
        try:
            prob = self.best_model.predict_proba(X)[0]
            confidence = prob[pred]
            phish_prob = prob[1]
        except AttributeError:
            try:
                score = self.best_model.decision_function(X)[0]
                phish_prob = 1 / (1 + np.exp(-score))
                confidence = phish_prob if pred == 1 else 1 - phish_prob
            except Exception:
                confidence = 1.0
                phish_prob = float(pred)

        # Structural signals
        extractor = StructuralFeatureExtractor()
        feats = extractor._extract(email_text)
        feat_dict = dict(zip(StructuralFeatureExtractor.FEATURE_NAMES, feats))

        return {
            "label":       "Phishing" if pred == 1 else "Safe",
            "prediction":  int(pred),
            "confidence":  float(confidence),
            "phish_prob":  float(phish_prob),
            "features":    feat_dict,
        }

    # ── Save / Load ──────────────────────────────────────────────────
    def save(self, path="phishing_model.joblib"):
        joblib.dump({
            "tfidf":    self.tfidf,
            "struct":   self.struct_ex,
            "model":    self.best_model,
            "name":     self.best_model_name,
            "results":  {k: {kk: vv for kk, vv in v.items() if kk != "model"}
                         for k, v in self.results.items()},
        }, path)
        print(clr(f"\n  💾 Model saved → {path}", C.GREEN))

    def load(self, path="phishing_model.joblib"):
        data = joblib.load(path)
        self.tfidf          = data["tfidf"]
        self.struct_ex      = data["struct"]
        self.best_model     = data["model"]
        self.best_model_name= data["name"]
        self.results        = data.get("results", {})
        print(clr(f"  ✅ Model loaded ← {path}", C.GREEN))


# ══════════════════════════════════════════════════════════════════════
#  INTERACTIVE TESTER
# ══════════════════════════════════════════════════════════════════════
def interactive_mode(detector: PhishingDetector):
    print(clr("\n" + "═" * 65, C.DIM))
    print(clr("  🔍  INTERACTIVE EMAIL CLASSIFIER", C.BOLD + C.CYAN))
    print(clr("  Paste an email body and press Enter twice. Type 'quit' to exit.", C.DIM))
    print(clr("═" * 65, C.DIM))

    TEST_EXAMPLES = [
        ("URGENT: Your account will be suspended! Verify at http://secure-login.xyz/verify NOW or lose access permanently!", 1),
        ("Hi team, meeting tomorrow at 10 AM in conference room B. Please bring your quarterly reports. Thanks!", 0),
        ("You won $500 Amazon gift card! Claim at http://amazon-gifts.xyz/claim before midnight tonight!", 1),
        ("Your GitHub pull request has been approved and merged into main branch. Great work on the authentication fix!", 0),
    ]

    print(clr("\n  🧪 Running built-in test examples first…\n", C.DIM))
    for email_text, expected in TEST_EXAMPLES:
        result = detector.predict_email(email_text)
        label  = result["label"]
        conf   = result["confidence"] * 100
        colour = C.RED if label == "Phishing" else C.GREEN
        icon   = "🎣" if label == "Phishing" else "✅"
        correct= "✓" if (result["prediction"] == expected) else "✗"
        print(f"  {icon} {clr(f'[{label}]', colour + C.BOLD)} "
              f"Confidence: {clr(f'{conf:.1f}%', colour)}  "
              f"{clr(correct, C.GREEN if correct=='✓' else C.RED)}")
        print(clr(f"     {email_text[:90]}…" if len(email_text)>90 else f"     {email_text}", C.DIM))

        # Show key signals
        feats = result["features"]
        signals = []
        if feats["url_count"] > 0:         signals.append(f"URLs: {int(feats['url_count'])}")
        if feats["suspicious_tld"]:        signals.append("⚠ Suspicious TLD")
        if feats["phish_kw_hits"] > 2:     signals.append(f"Phish keywords: {int(feats['phish_kw_hits'])}")
        if feats["has_winning"]:           signals.append("⚠ Win/Prize language")
        if feats["urgent_count"] > 0:      signals.append(f"Urgency signals: {int(feats['urgent_count'])}")
        if feats["asking_credentials"]:    signals.append("⚠ Credential request")
        if signals:
            print(clr(f"     Signals: {' | '.join(signals)}", C.YELLOW))
        print()

    # Interactive loop
    while True:
        print(clr("\n  Paste email text (or type 'quit'):", C.BOLD))
        lines = []
        try:
            while True:
                line = input("  > ")
                if line.lower() in ("quit", "exit", "q"):
                    print(clr("\n  Goodbye! Stay safe online. 🛡️\n", C.CYAN))
                    return
                if line == "" and lines:
                    break
                lines.append(line)
        except (EOFError, KeyboardInterrupt):
            print(clr("\n  Goodbye!\n", C.CYAN))
            return

        if not lines:
            continue

        email_text = "\n".join(lines)
        result     = detector.predict_email(email_text)
        label      = result["label"]
        conf       = result["confidence"] * 100
        phish_p    = result["phish_prob"] * 100
        colour     = C.RED if label == "Phishing" else C.GREEN
        icon       = "🎣 PHISHING" if label == "Phishing" else "✅ SAFE"

        print(sep())
        print(f"  Verdict     : {clr(icon, colour + C.BOLD)}")
        print(f"  Confidence  : {clr(f'{conf:.1f}%', colour)}")
        print(f"  Phish Prob  : {clr(f'{phish_p:.1f}%', C.RED if phish_p>50 else C.GREEN)}")
        print(f"  Model Used  : {clr(detector.best_model_name, C.CYAN)}")

        print(clr("\n  Key Signals Detected:", C.BOLD))
        feats = result["features"]
        signal_map = [
            ("url_count",          "URL count",           lambda v: v > 0),
            ("suspicious_tld",     "Suspicious TLD",      lambda v: v > 0),
            ("url_mismatch",       "Brand/TLD mismatch",  lambda v: v > 0),
            ("has_ip_url",         "IP-based URL",        lambda v: v > 0),
            ("long_url",           "Unusually long URL",  lambda v: v > 0),
            ("phish_kw_hits",      "Phishing keywords",   lambda v: v > 1),
            ("urgent_count",       "Urgency language",    lambda v: v > 0),
            ("has_winning",        "Win/prize language",  lambda v: v > 0),
            ("asking_credentials", "Credential request",  lambda v: v > 0),
            ("has_money_amount",   "Money amount",        lambda v: v > 0),
            ("exclamation_count",  "Exclamation marks",   lambda v: v > 2),
            ("caps_ratio",         "ALL CAPS usage",      lambda v: v > 0.15),
            ("safe_kw_hits",       "Professional language",lambda v: v > 1),
        ]
        for key, label_str, check in signal_map:
            val = feats.get(key, 0)
            if check(val) or key == "safe_kw_hits":
                risk = key not in ("safe_kw_hits",)
                colour2 = C.RED if risk else C.GREEN
                icon2   = "⚠️ " if risk else "✅"
                print(f"    {icon2} {label_str:<26} : {clr(val, colour2)}")
        print(sep())


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════
def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Phishing Email Detection Model",
        epilog="Examples:\n"
               "  python phishing_detector.py\n"
               "  python phishing_detector.py --save\n"
               "  python phishing_detector.py --load phishing_model.joblib\n"
               "  python phishing_detector.py --predict 'Your account has been hacked!'",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--save",    action="store_true", help="Save trained model")
    parser.add_argument("--load",    type=str, metavar="FILE", help="Load a saved model")
    parser.add_argument("--predict", type=str, metavar="EMAIL", help="Classify a single email")
    parser.add_argument("--no-interactive", action="store_true", help="Skip interactive mode")
    args = parser.parse_args()

    detector = PhishingDetector()

    if args.load:
        detector.load(args.load)
    else:
        detector.train()
        detector.report()
        if args.save:
            detector.save()

    if args.predict:
        result = detector.predict_email(args.predict)
        colour = C.RED if result["label"] == "Phishing" else C.GREEN
        print(f"\n  {clr(result['label'], colour + C.BOLD)} "
              f"(confidence: {result['confidence']*100:.1f}%)")
        return

    if not args.no_interactive:
        interactive_mode(detector)


if __name__ == "__main__":
    main()
