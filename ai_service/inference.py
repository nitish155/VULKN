# ai_service/inference.py

#------------------boilerplate code to load models and make predictions------------------#

import joblib
import os

# Get the absolute path to the models folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

# Load models into memory when the server starts (so it's fast)
try:
    sqli_model = joblib.load(os.path.join(MODELS_DIR, "sqli_model.pkl"))
    xss_model = joblib.load(os.path.join(MODELS_DIR, "xss_model.pkl"))
    print("[+] AI Models loaded successfully into memory.")
except Exception as e:
    print(f"[-] Waiting for models to be added: {e}")
    sqli_model = None

def predict_sqli(payload: str) -> bool:
    """Returns True if the model thinks the payload is a real SQLi attack"""
    if not sqli_model:
        return True # Fallback if model isn't loaded yet
    
    # Example: Your friend's model might need the text vectorized first
    prediction = sqli_model.predict([payload])
    return prediction[0] == 1