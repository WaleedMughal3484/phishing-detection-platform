from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.url_analysis import router as url_analysis_router

app = FastAPI(
    title="Phishing Detection Platform",
    description="Analyze URLs and emails for common phishing indicators.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(url_analysis_router)


@app.get("/")
def root():
    return {
        "name": "Phishing Detection Platform",
        "version": "0.1.0",
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
    }