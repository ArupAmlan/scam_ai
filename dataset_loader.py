import pandas as pd
import os


def load_sms_dataset():
    """Load SMS Spam Collection Dataset from Kaggle."""
    # Download from: https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset
    # File: spam.csv, encoding='latin-1'
    
    # Try to download using kagglehub if available
    try:
        import kagglehub
        path = kagglehub.dataset_download("uciml/sms-spam-collection-dataset")
        spam_path = os.path.join(path, 'spam.csv')
        if os.path.exists(spam_path):
            sms_data = pd.read_csv(spam_path, encoding='latin-1')
            sms_data = sms_data[['v1', 'v2']]
            sms_data.columns = ['label', 'message']
            sms_data['source'] = 'sms'
            sms_data['label'] = sms_data['label'].map({'ham': 'safe', 'spam': 'scam'})
            return sms_data
    except:
        pass
    
    # Fallback to local file
    if os.path.exists('spam.csv'):
        sms_data = pd.read_csv('spam.csv', encoding='latin-1')
        sms_data = sms_data[['v1', 'v2']]
        sms_data.columns = ['label', 'message']
        sms_data['source'] = 'sms'
        sms_data['label'] = sms_data['label'].map({'ham': 'safe', 'spam': 'scam'})
        return sms_data
    
    # Sample SMS data if file not found
    return pd.DataFrame({
        'label': ['safe', 'scam', 'safe', 'scam', 'safe', 'scam', 'safe', 'scam', 'safe', 'scam'],
        'message': [
            'Hey, are we still meeting for lunch today?',
            'Your OTP is 123456. Do not share it with anyone.',
            'Can you pick up some milk on your way home?',
            'Congratulations! You won $1000. Call now to claim your prize!',
            'See you at the gym later?',
            'Send money immediately via Paytm to receive your prize.',
            'Thanks for the birthday wishes!',
            'You have been selected for a cash reward. Send your bank details.',
            'The package has been delivered to your address.',
            'URGENT: Share your OTP to complete the transaction.'
        ],
        'source': ['sms'] * 10
    })


def load_email_dataset():
    """Load Phishing Email Dataset from GitHub."""
    # Download from: https://github.com/rokibulroni/Phishing-Email-Dataset
    # File: Phishing_Email.csv
    if os.path.exists('Phishing_Email.csv'):
        email_data = pd.read_csv('Phishing_Email.csv')
        email_data = email_data[['Email Type', 'Email Text']]
        email_data.columns = ['label', 'message']
        email_data['source'] = 'email'
        email_data['label'] = email_data['label'].map({'Safe Email': 'safe', 'Phishing Email': 'scam'})
        return email_data
    else:
        # Sample Email data if file not found
        return pd.DataFrame({
            'label': ['safe', 'scam', 'safe', 'scam', 'safe', 'scam', 'safe', 'scam', 'safe', 'scam'],
            'message': [
                'Subject: Meeting rescheduled to 3 PM tomorrow.',
                'Subject: Urgent! You have won a free iPhone. Click here to claim.',
                'Subject: Invoice #5678 has been paid. Thank you for your business.',
                'Subject: Your account has been suspended. Verify your details immediately.',
                'Subject: The quarterly report is now available on the shared drive.',
                'Subject: You won the lottery! Call this number to claim your money.',
                'Subject: Please update your timesheet by end of day Friday.',
                'Subject: Your credit card has been compromised. Provide details to secure it.',
                'Subject: Your subscription has been renewed successfully.',
                'Subject: Send Bitcoin to this address and receive 10x returns!'
            ],
            'source': ['email'] * 10
        })


def load_combined_dataset():
    """Load and combine both datasets."""
    sms_data = load_sms_dataset()
    email_data = load_email_dataset()
    data = pd.concat([sms_data, email_data], ignore_index=True)
    data = data.dropna()
    return data
