# 🛡️ Trustiva AI

**Verify Before You Trust.**

Trustiva AI is a Generative AI-powered digital trust and fraud intelligence platform. It investigates suspicious digital communication, correlates observable evidence, retrieves trusted cybersecurity guidance with RAG, produces an explainable risk assessment, and recommends practical protection or recovery actions.

## Hackathon MVP

Trustiva currently supports:

- 📝 Suspicious message analysis
- 🔗 URL investigation
- 📸 Screenshot analysis with OCR
- 📄 PDF/TXT document investigation
- 🧠 Generative AI investigation
- 📚 Trusted-source RAG verification
- 🕸️ Evidence correlation
- 📊 Explainable 0–100 risk assessment
- 🛡️ Prevention and response guidance
- 🌍 English, Urdu and Roman Urdu-oriented evidence patterns

## Investigation Flow

```text
User Evidence
     ↓
Evidence Extraction
     ↓
URL Intelligence
     ↓
Generative AI Investigation
     ↓
Trusted Knowledge Retrieval (RAG)
     ↓
Evidence Correlation
     ↓
Risk Assessment
     ↓
Protection / Recovery Guidance
```

## Local Setup

### 1. Clone or copy the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd trustiva-ai
```

### 2. Create and activate a virtual environment

Windows:

```bat
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bat
pip install -r requirements.txt
```

### 4. Configure environment variables

Create `.env` from the following template:

```env
APP_NAME=Trustiva AI
APP_ENV=development
DEBUG=true

LLM_PROVIDER=openrouter
LLM_API_KEY=YOUR_OPENROUTER_KEY
LLM_MODEL=openrouter/free

EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
VECTOR_DB_PATH=data/vectorstore
MAX_UPLOAD_SIZE_MB=10
LOG_LEVEL=INFO
```

Never commit `.env` or API keys.

### 5. Install Tesseract OCR

Windows: install Tesseract OCR and make sure it is available at the standard installation path or in `PATH`.

Linux/Streamlit Cloud: `packages.txt` installs `tesseract-ocr`.

### 6. Run

```bat
python -m streamlit run app\main.py
```

Open the local Streamlit URL shown in the terminal.

## Deployment — Streamlit Community Cloud

1. Push the repository to GitHub.
2. Open Streamlit Community Cloud.
3. Create a new app from the GitHub repository.
4. Set the main file to:

```text
app/main.py
```

5. Add the following secrets in Streamlit Cloud:

```toml
LLM_PROVIDER = "openrouter"
LLM_API_KEY = "YOUR_OPENROUTER_KEY"
LLM_MODEL = "openrouter/free"
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
VECTOR_DB_PATH = "data/vectorstore"
MAX_UPLOAD_SIZE_MB = "10"
LOG_LEVEL = "INFO"
```

The application reads these values through `pydantic-settings` environment configuration.

## Demo Scenario

Use this as the primary hackathon demonstration:

```text
Your bank account has been suspended. Click
https://secure-bank-login.com immediately and enter
your OTP and password to restore access.
```

Demonstrate:

1. Evidence extraction
2. URL intelligence
3. GenAI investigation
4. RAG verification
5. Evidence correlation
6. Risk score
7. Recommended protection actions

Then demonstrate a screenshot of a similar message to show the OCR pipeline.

## Privacy & Safety

Trustiva provides evidence-based risk intelligence. It does not make definitive criminal accusations about people, organizations, phone numbers, URLs, or accounts. An unknown sender is not automatically fraudulent, and retrieved cybersecurity guidance is supporting context rather than proof of a specific incident.

For production use, minimize collection of personal data, configure retention, add authentication and audit controls, and integrate jurisdiction-specific official reporting/recovery workflows.

## Future Scale

The MVP is intentionally Streamlit-based for rapid validation. A production version can separate the UI, investigation API, retrieval layer, risk service, threat-intelligence integrations, observability, authentication, and scalable storage without changing the core investigation concept.
