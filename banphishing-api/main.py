from fastapi import FastAPI
from pydantic import BaseModel
import joblib
from urllib.parse import urlparse
import re
from scipy.sparse import hstack
import pandas as pd

app = FastAPI()

# Load the saved model and vectorizer
model = joblib.load('model.joblib')
vectorizer = joblib.load('vectorizer.joblib')

# Feature Extraction Function
def extract_features(url):
    features = {}
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        features['url_length'] = len(url)
        features['hostname_length'] = len(domain)
        features['num_dots'] = url.count('.')
        features['num_slashes'] = url.count('/')
        suspicious_keywords = ['login', 'secure', 'account', 'verify', 'password', 'update']
        for keyword in suspicious_keywords:
            features[f'has_{keyword}'] = 1 if keyword in url.lower() else 0
        features['is_ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) else 0
    except:
        feature_names = ['url_length', 'hostname_length', 'num_dots', 'num_slashes', 'is_ip'] + [f'has_{kw}' for kw in suspicious_keywords]
        return {fn: 0 for fn in feature_names}
    return features

# Define the request model
class URLRequest(BaseModel):
    url: str

# Create the API Endpoint
@app.post("/analyze-url")
def analyze_url(request: URLRequest):
    url_to_check = request.url
    numerical_features_df = pd.DataFrame([extract_features(url_to_check)])
    url_text_features = vectorizer.transform([url_to_check])
    features_combined = hstack([numerical_features_df, url_text_features])
    prediction = model.predict(features_combined)[0]

    if prediction == 1:
        return {"status": "PHISHING"}
    else:
        return {"status": "SAFE"}

@app.get("/")
def read_root():
    return {"message": "BanPhishing API is live and ready for analysis."}
