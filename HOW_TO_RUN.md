# Create Environment
`python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt`

# Tests
`.venv/bin/pytest tests/unit/ -v`
# Backend API (port 8000)
`.venv/bin/uvicorn pa00_web.backend.api:app --reload --port 8000`
# Frontend (port 5173)
`cd pa00_web/frontend && npm run dev`
