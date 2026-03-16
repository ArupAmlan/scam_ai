# Setup Guide

## Quick Start (5 minutes)

### 1. Install Python Packages
```bash
pip install pandas numpy scikit-learn kagglehub pillow
```

### 2. Setup Chrome Extension
```
1. Open Chrome → chrome://extensions/
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select: scam_ai/extension/
```

### 3. Test the Extension
- Go to https://mail.google.com
- Look for blue banner: "Scam Guard is active on Gmail"
- Check console (F12) for "Found X emails"

## Detailed Setup

### Option A: Automatic Dataset Download (Requires Kaggle Account)

1. Create Kaggle account at https://www.kaggle.com
2. Go to Account → API → Create New API Token
3. Save `kaggle.json` to:
   - Windows: `C:\Users\<username>\.kaggle\kaggle.json`
   - Linux/Mac: `~/.kaggle/kaggle.json`
4. Run: `python scam_detection.py`

### Option B: Manual Dataset Download

1. Download SMS dataset:
   - https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset
   - Save as `spam.csv` in project folder

2. Download Email dataset:
   - https://github.com/rokibulroni/Phishing-Email-Dataset
   - Save as `Phishing_Email.csv` in project folder

3. Run: `python scam_detection.py`

## Verify Installation

### Test ML Model
```bash
python scam_detection.py
```

Expected output:
```
Accuracy: 0.95
Precision: 0.87
Recall: 0.71
F1 Score: 0.78

WhatsApp Prediction: safe
Email Prediction: scam
```

### Test Chrome Extension
1. Open Gmail
2. Press F12 → Console
3. Look for:
   - "Gmail Scam Detector loaded"
   - "Found X emails with selector"
   - Blue banner at bottom-right

## Common Issues

### "Cannot load extension with file or directory name __pycache__"
**Solution**: Load the `extension` subfolder, not the main project folder.

### "No email rows found"
**Solution**: Refresh Gmail page. The extension needs Gmail to fully load first.

### "Failed to load dataset"
**Solution**: Download datasets manually or setup Kaggle API credentials.

### Extension not showing on WhatsApp
**Solution**: Make sure you're on https://web.whatsapp.com (not mobile app).

## Next Steps

1. Train model: `python scam_detection.py`
2. Load extension in Chrome
3. Open WhatsApp Web or Gmail
4. Look for active banner
5. Test with scam-like messages
