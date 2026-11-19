import io
import os
from pathlib import Path
from typing import List

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pypdf import PdfReader

from agent import DealShieldAgent
from models import (
    AnalyzeRequest,
    AnalyzeResponse,
    ChatRequest,
    ChatResponse,
    ConfigRequest,
    DocumentInput,
    UserRole,
)

load_dotenv()

app = FastAPI(
    title="DealShield AI — Deloitte | Google Cloud Hackathon",
    description="Agent autonome de Due Diligence M&A sécurisé (Security-by-Design)",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SAMPLE_DIR = Path(__file__).parent / "sample_dataroom"
agent = DealShieldAgent()


@app.get("/api/health")
def health():
    has_key = bool(os.getenv("GEMINI_API_KEY", "").strip())
    return {
        "status": "ok",
        "agent": "DealShield AI",
        "mode": "gemini_live" if has_key else "deterministic_engine",
        "gcp_project_id": os.getenv("GCP_PROJECT_ID", "deloitteinnov26par-599"),
        "gemini_model": os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
    }


@app.post("/api/config")
def update_config(cfg: ConfigRequest):
    """Permet de configurer GEMINI_API_KEY et GCP_PROJECT_ID en direct depuis l'interface."""
    if cfg.gemini_api_key is not None:
        os.environ["GEMINI_API_KEY"] = cfg.gemini_api_key.strip()
    os.environ["GEMINI_MODEL"] = cfg.gemini_model.strip() or "gemini-2.5-flash"
    os.environ["GCP_PROJECT_ID"] = cfg.gcp_project_id.strip() or "deloitteinnov26par-599"
    has_key = bool(os.getenv("GEMINI_API_KEY", "").strip())
    return {
        "status": "updated",
        "mode": "gemini_live" if has_key else "deterministic_engine",
        "gcp_project_id": os.environ["GCP_PROJECT_ID"],
        "gemini_model": os.environ["GEMINI_MODEL"],
    }


@app.get("/api/dataroom/samples")
def get_sample_dataroom():
    """Retourne les documents de démo (3 sains + 1 document piégé pour le test cyberattaque)."""
    docs = []
    if SAMPLE_DIR.exists():
        for path in sorted(SAMPLE_DIR.glob("*.txt")):
            docs.append(
                {
                    "name": path.name,
                    "is_malicious_sample": "PIEGE" in path.name.upper(),
                    "content": path.read_text(encoding="utf-8"),
                }
            )
    return {"documents": docs}


@app.post("/api/parse-files")
async def parse_uploaded_files(files: List[UploadFile] = File(...)):
    """Extrait le texte des fichiers (.pdf, .txt, .md, .csv) pour les ajouter à la Data Room."""
    parsed = []
    for f in files:
        raw = await f.read()
        filename = f.filename or "document.txt"
        if filename.lower().endswith(".pdf"):
            reader = PdfReader(io.BytesIO(raw))
            pages_text = [
                f"[Page {idx}]\n{page.extract_text() or ''}"
                for idx, page in enumerate(reader.pages, start=1)
            ]
            content = "\n".join(pages_text)
        else:
            content = raw.decode("utf-8", errors="replace")
        parsed.append(
            {
                "name": filename,
                "is_malicious_sample": False,
                "content": content,
                "size_kb": round(len(raw) / 1024, 1),
            }
        )
    return {"documents": parsed}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_dataroom(request: AnalyzeRequest):
    return agent.run(request)


@app.post("/api/analyze-upload", response_model=AnalyzeResponse)
async def analyze_uploaded_files(
    user_role: UserRole = Form("analyst"),
    files: List[UploadFile] = File(...),
):
    docs: List[DocumentInput] = []
    for f in files:
        raw = await f.read()
        filename = f.filename or "document.txt"
        if filename.lower().endswith(".pdf"):
            reader = PdfReader(io.BytesIO(raw))
            pages_text = [
                f"[Page {idx}]\n{page.extract_text() or ''}"
                for idx, page in enumerate(reader.pages, start=1)
            ]
            content = "\n".join(pages_text)
        else:
            content = raw.decode("utf-8", errors="replace")
        docs.append(DocumentInput(name=filename, content=content))

    return agent.run(AnalyzeRequest(user_role=user_role, documents=docs))


@app.post("/api/chat", response_model=ChatResponse)
def chat_with_agent(request: ChatRequest):
    return agent.chat(request)


# Servir le frontend buildé (production / Cloud Run) s'il est présent
_CANDIDATE_DIST_DIRS = [
    Path(__file__).parent / "static",
    Path(__file__).parent.parent / "frontend" / "dist",
]
_DIST_DIR = next((d for d in _CANDIDATE_DIST_DIRS if (d / "index.html").exists()), None)

if _DIST_DIR is not None:
    if (_DIST_DIR / "assets").exists():
        app.mount("/assets", StaticFiles(directory=_DIST_DIR / "assets"), name="assets")

    @app.get("/{full_path:path}")
    def serve_frontend(full_path: str):
        candidate = (_DIST_DIR / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(_DIST_DIR.resolve()):
            return FileResponse(candidate)
        return FileResponse(_DIST_DIR / "index.html")
