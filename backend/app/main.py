from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.ml.model import phishing_model
from app.schemas import AnalyzeRequest, AnalyzeResponse, BatchAnalyzeRequest, BatchAnalyzeResponse

app = FastAPI(
    title="Pahi-Guard API",
    description="URL phishing detection API powered by a URL-focused ML pipeline.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def train_model() -> None:
    phishing_model.train()


@app.get("/api/health")
def health() -> dict[str, object]:
    return {"status": "ok", "model_ready": phishing_model.is_ready}


@app.get("/api/model/info")
def model_info() -> dict[str, object]:
    return phishing_model.info()


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    return phishing_model.analyze(payload.url)


@app.post("/api/batch", response_model=BatchAnalyzeResponse)
def batch_analyze(payload: BatchAnalyzeRequest) -> BatchAnalyzeResponse:
    results = [phishing_model.analyze(url) for url in payload.urls]
    return BatchAnalyzeResponse(results=results)
