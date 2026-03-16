# Scam Guard - WhatsApp & Email Scam Detection

A Chrome extension that detects potential scam messages on WhatsApp Web and Gmail using machine learning and rule-based analysis.

## Features

- **Real-time Detection**: Automatically scans messages as you browse
- **Dual Platform Support**: Works on both WhatsApp Web and Gmail
- **Visual Warnings**: Red banners and highlights for suspicious messages
- **Risk Scoring**: Shows scam probability score (0-100)
- **Active Indicator**: Shows when protection is active

## Project Structure

```
scam_ai/
├── extension/              # Chrome Extension Files
│   ├── manifest.json       # Extension configuration
│   ├── whatsapp-content.js # WhatsApp Web detection
│   ├── email-content.js    # Gmail detection
│   ├── popup.html          # Extension popup UI
│   └── icon*.png           # Extension icons
├── dataset_loader.py       # Dataset loading module
├── scam_detection.py       # ML model training & evaluation
└── README.md              # This file
```

## Installation

### Prerequisites
- Google Chrome browser
- Python 3.x (for ML model)
- pip packages: `pandas`, `numpy`, `scikit-learn`, `kagglehub`

### Step 1: Install Python Dependencies

```bash
pip install pandas numpy scikit-learn kagglehub
```

### Step 2: Load Chrome Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **"Developer mode"** (toggle in top right)
3. Click **"Load unpacked"**
4. Select the `extension` folder from this project
5. Extension icon will appear in your toolbar

### Step 3: Run ML Model (Optional)

```bash
python scam_detection.py
```

This trains the model on SMS and Email datasets and shows accuracy metrics.

## Usage

### On WhatsApp Web
1. Go to https://web.whatsapp.com
2. Green banner appears: "Scam Guard is active on WhatsApp"
3. Suspicious messages get red warning labels

### On Gmail
1. Go to https://mail.google.com
2. Blue banner appears: "Scam Guard is active on Gmail"
3. Scam emails highlighted in red in inbox
4. Warning banners on opened scam emails

## How It Works

### Detection Algorithm
The extension uses a scoring system (0-100):

| Indicator | Points |
|-----------|--------|
| Scam keywords (won, prize, urgent, etc.) | +10 each |
| Money requests | +20 |
| Urgency pressure | +15 |
| Phishing indicators | +15 |
| Suspicious patterns (URLs, numbers) | +5 each |

**Threshold**: Score ≥ 40 = Scam detected

### Keywords Detected
- `won`, `prize`, `lottery`, `congratulations`
- `urgent`, `verify`, `suspended`, `account locked`
- `bitcoin`, `crypto`, `investment`, `double your money`
- `send money`, `processing fee`, `click here`
- `inheritance`, `million`, `OTP`, `call now`

## Datasets Used

1. **SMS Spam Collection Dataset** (Kaggle)
   - 5,574 messages
   - Source: https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset

2. **Phishing Email Dataset** (GitHub)
   - Thousands of phishing/safe emails
   - Source: https://github.com/rokibulroni/Phishing-Email-Dataset

## ML Model Performance

```
Accuracy:  95%
Precision: 87%
Recall:    71%
F1 Score:  78%
```

## Troubleshooting

### Extension not loading
- Make sure you're loading the `extension` folder, not the main project folder
- Check that no files start with `_` or `.`

### Not detecting scams
- Check browser console (F12) for debug messages
- Ensure you're on web.whatsapp.com or mail.google.com
- Look for emails with scam keywords to test

### Dataset download fails
- Install kagglehub: `pip install kagglehub`
- Or download manually and place in project folder

## Files Description

| File | Purpose |
|------|---------|
| `manifest.json` | Chrome extension configuration |
| `whatsapp-content.js` | Content script for WhatsApp Web |
| `email-content.js` | Content script for Gmail |
| `popup.html` | Extension popup interface |
| `dataset_loader.py` | Loads and preprocesses datasets |
| `scam_detection.py` | ML model training and evaluation |

## License

MIT License - Free to use and modify.

## Credits

- SMS Dataset: UCI Machine Learning Repository
- Email Dataset: rokibulroni/Phishing-Email-Dataset
