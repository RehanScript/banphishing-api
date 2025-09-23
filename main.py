from fastapi import FastAPI
from pydantic import BaseModel
import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
import requests
from bs4 import BeautifulSoup

app = FastAPI()

# --- 1. Load the Fine-Tuned Model ---
# This happens once when the API starts up
try:
    MODEL_PATH = 'banphishing-bert-model'
    tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_PATH)
    model = DistilBertForSequenceClassification.from_pretrained(MODEL_PATH)
    print("✅ Fine-tuned BERT model loaded successfully!")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    model = None

# --- 2. Real-time Text Scraping Function ---
def scrape_text_from_url(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            return ' '.join(soup.body.get_text().split())
        return ""
    except:
        return ""

# --- 3. Define the request model ---
class URLRequest(BaseModel):
    url: str

# --- 4. Create the API Endpoint ---
@app.post("/analyze-url")
def analyze_url(request: URLRequest):
    if not model:
        return {"status": "ERROR", "detail": "Model not loaded"}

    # Scrape the text from the URL in real-time
    text_to_analyze = scrape_text_from_url(request.url)
    if not text_to_analyze:
        # If we can't get text, we can't analyze it with this model
        return {"status": "SAFE", "detail": "Could not retrieve page content"}
        
    # Prepare the text for the model
    inputs = tokenizer(text_to_analyze, return_tensors="pt", truncation=True, padding=True, max_length=512)
    
    # Make the prediction
    with torch.no_grad():
        logits = model(**inputs).logits
    
    predicted_class_id = logits.argmax().item()
    
    # Return the result (1 for phishing, 0 for benign)
    if predicted_class_id == 1:
        return {"status": "PHISHING"}
    else:
        return {"status": "SAFE"}

@app.get("/")
def read_root():
    return {"message": "BanPhishing API v2 (BERT) is live and ready."}
