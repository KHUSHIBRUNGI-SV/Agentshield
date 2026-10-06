# AgentShield
A security layer between AI agents and their tools. The agent proposes; AgentShield returns
ALLOW, SANDBOX, HUMAN_APPROVAL or BLOCK, and logs everything.

## Run locally
    pip install -r requirements.txt
    uvicorn app.main:app --reload
    open http://localhost:8000      (API docs: /docs)

## Test
    pytest -q

## Docker
    docker build -t agentshield . && docker run -p 8000:8000 agentshield

## Deploy (Render / Railway / Fly.io)
Push to GitHub, create a Web Service from the repo (Docker runtime). The app reads $PORT.
Health check path: /health. For persistent logs, mount a disk and set AGENTSHIELD_DB=/data/agentshield.db.

## Roadmap
JWT auth for agents, PostgreSQL + Redis, scikit-learn IsolationForest for behavior anomalies,
Docker-based sandbox runner, 100-scenario benchmark (with vs without AgentShield).
