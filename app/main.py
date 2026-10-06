"""AgentShield: a security layer between AI agents and the tools they use.
The agent proposes an action; AgentShield decides ALLOW / SANDBOX / HUMAN_APPROVAL / BLOCK."""
import os, re, sqlite3, time, json
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DB = os.getenv("AGENTSHIELD_DB", "agentshield.db")
STATIC = Path(__file__).parent / "static"

# ---------- Policies (the "company rules") ----------
POLICIES = {
    "support-bot": {"role": "Customer Support", "allow": ["read", "update", "create_ticket", "export"],
                    "max_export": 1000, "approval": [], "sandbox": []},
    "finance-bot": {"role": "Finance Assistant", "allow": ["read", "export", "payment"],
                    "max_export": 200, "approval": ["payment"], "sandbox": []},
    "devops-bot": {"role": "DevOps Helper", "allow": ["read", "run_code", "deploy"],
                   "max_export": 0, "approval": ["deploy"], "sandbox": ["run_code"]},
}
INJECTION = re.compile(r"ignore (all |any )?(previous|prior) instructions|disregard .*(rules|polic)|"
                       r"reveal .*(system prompt|password|api key)|you are now|bypass (security|policy)", re.I)
RATE_WARN, RATE_BLOCK = 8, 15  # requests per 60s per agent

app = FastAPI(title="AgentShield", version="1.0.0")

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, agent TEXT,
                 action TEXT, records INTEGER, prompt TEXT, decision TEXT, risk INTEGER, reason TEXT, checks TEXT)""")
    return c

class ActionRequest(BaseModel):
    agent: str
    action: str
    records: int = Field(0, ge=0)
    prompt: str = ""

def evaluate(req: ActionRequest, recent: int):
    checks, p = [], POLICIES.get(req.agent)
    def add(name, ok, detail): checks.append({"name": name, "ok": ok, "detail": detail})

    add("Identity", p is not None, f"{req.agent} ({p['role']})" if p else "Unknown agent")
    if not p: return "BLOCK", 100, "Unknown agent identity", checks

    bad = INJECTION.search(req.prompt or "")
    add("Prompt safety", not bad, "No injection patterns" if not bad else f"Injection pattern: '{bad.group(0)}'")
    if bad: return "BLOCK", 95, "Prompt injection attempt detected", checks

    permitted = req.action in p["allow"]
    add("Permission", permitted, f"'{req.action}' is permitted" if permitted else f"'{req.action}' is not permitted for this role")
    if not permitted: return "BLOCK", 90, f"{req.action} is not allowed for {p['role']}", checks

    within = req.action != "export" or req.records <= p["max_export"]
    add("Data limits", within, "Within limits" if within else f"{req.records:,} records exceeds the {p['max_export']:,} export limit")
    if not within: return "BLOCK", 85, f"Export of {req.records:,} records exceeds the {p['max_export']:,} limit", checks

    calm = recent < RATE_WARN
    add("Behavior", calm, f"{recent} requests in the last minute" + ("" if calm else " (unusual)"))
    if recent >= RATE_BLOCK: return "BLOCK", 88, "Abnormal request rate: agent suspended for this window", checks
    if not calm: return "HUMAN_APPROVAL", 65, "Unusual activity: a human must confirm", checks

    if req.action in p["approval"]:
        add("Policy", True, "Policy requires human sign-off")
        return "HUMAN_APPROVAL", 55, f"{req.action} always needs human approval", checks
    if req.action in p["sandbox"]:
        add("Policy", True, "Policy requires isolation")
        return "SANDBOX", 40, f"{req.action} runs in an isolated container", checks
    add("Policy", True, "Allowed by policy")
    return "ALLOW", 10, "Safe and permitted", checks

@app.post("/api/evaluate")
def api_evaluate(req: ActionRequest):
    t0 = time.perf_counter()
    with db() as c:
        recent = c.execute("SELECT COUNT(*) n FROM audit WHERE agent=? AND ts>?", (req.agent, time.time() - 60)).fetchone()["n"]
        decision, risk, reason, checks = evaluate(req, recent)
        c.execute("INSERT INTO audit(ts,agent,action,records,prompt,decision,risk,reason,checks) VALUES(?,?,?,?,?,?,?,?,?)",
                  (time.time(), req.agent, req.action, req.records, req.prompt[:300], decision, risk, reason, json.dumps(checks)))
    return {"decision": decision, "risk": risk, "reason": reason, "checks": checks,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}

@app.get("/api/logs")
def logs(limit: int = 30):
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

@app.get("/api/stats")
def stats():
    with db() as c:
        rows = c.execute("SELECT decision, COUNT(*) n FROM audit GROUP BY decision").fetchall()
    out = {"ALLOW": 0, "SANDBOX": 0, "HUMAN_APPROVAL": 0, "BLOCK": 0}
    out.update({r["decision"]: r["n"] for r in rows})
    return {**out, "total": sum(out.values())}

@app.get("/api/agents")
def agents():
    return POLICIES

@app.post("/api/reset")
def reset():
    with db() as c: c.execute("DELETE FROM audit")
    return {"ok": True}

@app.get("/health")
def health(): return {"status": "ok"}

app.mount("/static", StaticFiles(directory=STATIC), name="static")

@app.get("/")
def index(): return FileResponse(STATIC / "index.html")
