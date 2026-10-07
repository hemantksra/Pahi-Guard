# Pahi-Guard

Pahi-Guard is a full-stack URL phishing detection demo built for hackathons. It combines a clean React interface with a FastAPI backend and a URL-focused machine learning pipeline.

## Stack

- Frontend: React, TypeScript, Vite, lucide-react
- Backend: FastAPI, scikit-learn, NumPy, SciPy
- Model: Character n-gram TF-IDF plus lexical URL features with Logistic Regression

## Why This Model

For URL-only phishing detection, character n-grams are a strong baseline because phishing URLs often reveal themselves through token shape, brand impersonation, odd separators, risky paths, and suspicious query strings. Pahi-Guard combines those n-grams with explicit URL features such as IP-host usage, subdomain depth, HTTPS presence, suspicious keywords, shortening domains, entropy, and path/query length.

## Run Locally

### Backend

```bash
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal. By default, the frontend calls `http://localhost:8000`.

## API

- `GET /api/health` - service and model status
- `GET /api/model/info` - model metadata
- `POST /api/analyze` - analyze one URL
- `POST /api/batch` - analyze multiple URLs

Example:

```bash
curl -X POST http://localhost:8000/api/analyze ^
  -H "Content-Type: application/json" ^
  -d "{\"url\":\"https://secure-paypal-login.example.com/verify\"}"
```
