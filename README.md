# DealShield AI — Deloitte | Google Cloud Hackathon

Agent autonome de **Due Diligence M&A sécurisé (Security-by-Design)** propulsé par **Gemini 2.5 Flash**, **FastAPI**, **React (Vite)** et déployé sur **Google Cloud Run**.

**Démo en ligne (Cloud Run — `europe-west1`) :**  
https://dealshield-ai-184095331577.europe-west1.run.app

---

## Architecture (`DealShieldAgent` — 4 outils)

1. **`security_sanitizer` (Sas d'entrée Security-by-Design)** : neutralise les tentatives d'*Indirect / Direct Prompt Injection* (patterns + caractères *zero-width*), masque les données sensibles DLP (IBAN, emails, téléphones) et applique le contrôle d'accès RBAC (`analyst` vs `partner` sur les rémunérations dirigeants).
2. **`extract_red_flags` (Extraction M&A sourcée)** : identifie les risques juridiques, financiers et contractuels avec citation exacte (document, page, extrait) via **Gemini 2.5 Flash** (ou moteur déterministe de repli sans clé API).
3. **`cross_check_financials` (Contrôles financiers déterministes)** : vérifie en Python exact la concentration client, les engagements hors-bilan et le levier EBITDA (zéro calcul approximatif par LLM).
4. **`generate_dd_memo` (Synthèse, Piste d'Audit & Export PDF)** : génère le mémo exécutif, la piste d'audit étape par étape (`ToolTrace`), un chat vocal/texte sécurisé et un export PDF (`jsPDF`).

---

## Structure du projet

```text
dealshield-ai/
├── backend/
│   ├── main.py              # API FastAPI (/api/health, /api/analyze, /api/chat, etc.)
│   ├── agent.py             # Orchestrateur DealShieldAgent
│   ├── tools.py             # 4 outils (Sanitizer, Red Flags, FinChecks, Mémo)
│   ├── models.py            # Schémas Pydantic
│   ├── sample_dataroom/     # 4 documents de démo (3 sains + 1 document piégé)
│   ├── tests/test_agent.py  # Tests unitaires pytest
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/App.jsx          # Dashboard React + Chat vocal/texte + Config GCP
│   ├── src/pdfExport.js     # Export PDF exécutif (jsPDF)
│   ├── vite.config.js       # Serveur Vite (port 5173) + proxy /api -> 127.0.0.1:8001
│   └── package.json
├── Dockerfile               # Image Python 3.12 + frontend buildé pour Cloud Run
└── .dockerignore
```

---

## 1. Lancer en local

### Backend (FastAPI — port `8001`)

```bash
cd backend
cp .env.example .env   # Optionnel : renseigner GEMINI_API_KEY pour le mode gemini_live
.venv/bin/uvicorn main:app --reload --port 8001
```

*(Sans `GEMINI_API_KEY`, DealShield AI bascule automatiquement sur le moteur déterministe `deterministic_engine`.)*

### Frontend (React + Vite — port `5173`)

```bash
cd frontend
npm install
npm run dev
```

Ouvrir `http://127.0.0.1:5173` dans le navigateur.

---

## 2. Lancer les tests unitaires Backend

```bash
cd backend
.venv/bin/pytest -v
```

---

## 3. Déployer sur Google Cloud Run

```bash
# 1. Construire le frontend statique
cd frontend && npm run build && cd ..

# 2. Déployer sur Cloud Run
gcloud run deploy dealshield-ai \
  --source . \
  --project <VOTRE_GCP_PROJECT_ID> \
  --region europe-west1 \
  --allow-unauthenticated \
  --port 8080 \
  --set-env-vars "GEMINI_API_KEY=<VOTRE_CLE_GEMINI>,GEMINI_MODEL=gemini-2.5-flash,GCP_PROJECT_ID=<VOTRE_GCP_PROJECT_ID>"
```
