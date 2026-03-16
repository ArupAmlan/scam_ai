import pandas as pd
import numpy as np
from dataset_loader import load_combined_dataset

# Load combined dataset from SMS and Email sources
data = load_combined_dataset()

data.head()

# Check for null values
data.isnull().sum()

# Prepare features and target
from sklearn.feature_extraction.text import TfidfVectorizer

vectorizer = TfidfVectorizer(stop_words='english', max_features=100)
X = vectorizer.fit_transform(data['message']).toarray()
y = data['label'].values

# Split data
from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)

# Train model
from sklearn.naive_bayes import MultinomialNB

model = MultinomialNB()
model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)

# Evaluate
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, pos_label='scam')
recall = recall_score(y_test, y_pred, pos_label='scam')
f1 = f1_score(y_test, y_pred, pos_label='scam')

print(f"Accuracy: {accuracy:.2f}")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")

# Test on WhatsApp message
whatsapp_message = ["Your OTP is 123456. Do not share it."]
whatsapp_vectorized = vectorizer.transform(whatsapp_message)
whatsapp_pred = model.predict(whatsapp_vectorized)
print(f"\nWhatsApp Prediction: {whatsapp_pred[0]}")

# Test on Email message
email_message = ["Subject: You won $1000! Click here to claim your prize."]
email_vectorized = vectorizer.transform(email_message)
email_pred = model.predict(email_vectorized)
print(f"Email Prediction: {email_pred[0]}")
