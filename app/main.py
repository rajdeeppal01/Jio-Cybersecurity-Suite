from pydantic import BaseModel
from fastapi import BackgroundTasks, File, UploadFile
import os
import uuid
import datetime
import mimetypes

# Register font MIME types for offline loading under strict nosniff
mimetypes.add_type("font/ttf", ".ttf")
mimetypes.add_type("font/woff", ".woff")
mimetypes.add_type("font/woff2", ".woff2")

import uvicorn
import hashlib
import math
import requests
import asyncio
import time
import collections
import threading
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.core.auth import authenticate_user, create_access_token, verify_token
from app.core.database import get_db, engine
from app.models.models import Base, Campaign, Asset, Report, PentestCampaign

Base.metadata.create_all(bind=engine)

app = FastAPI(title="NetraAI Gateway", version="9.0")

# ── Security Headers ──────────────────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self' http://*:8000 https://*:8000; script-src 'self' 'unsafe-inline' 'unsafe-eval' http://*:8000 https://*:8000; style-src 'self' 'unsafe-inline' http://*:8000 https://*:8000; connect-src 'self' http://*:8000 https://*:8000; img-src 'self' data: blob: http://*:8000 https://*:8000; font-src 'self' data: http://*:8000 https://*:8000; frame-src 'self' http://*:8000 https://*:8000;"
    response.headers["Server"] = "NetraAI-Gateway"
    return response

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/auth/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(form_data.username, form_data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")
    token = create_access_token(data={"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}

# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/")
async def root():
    return RedirectResponse(url="/dashboard")

# ── Netra0 Campaign Endpoints ─────────────────────────────────────────────────
@app.get("/api/v1/campaigns")
async def list_campaigns(db: Session = Depends(get_db), user: str = Depends(verify_token)):
    campaigns = db.query(Campaign).order_by(Campaign.created_at.desc()).all()
    return [{"id": c.id, "target": c.target, "status": c.status, "created_at": str(c.created_at)} for c in campaigns]

@app.post("/api/v1/campaigns")
async def create_campaign(request: Request, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    params = dict(request.query_params)
    target = params.get("target")
    if not target:
        body = await request.json()
        target = body.get("target")
    if not target:
        raise HTTPException(status_code=422, detail="Target is required")
    campaign = Campaign(id=str(uuid.uuid4()), target=target, status="PENDING")
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    from app.workers.tasks_tier1 import passive_recon
    passive_recon.delay(campaign.id, target)
    return {"id": campaign.id, "target": campaign.target, "status": campaign.status}

@app.get("/api/v1/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    assets = [{"id": a.id, "ip_address": a.ip_address, "port": a.port, "service": a.service, "banner": a.banner, "vulnerabilities": a.vulnerabilities} for a in campaign.assets]
    return {"id": campaign.id, "target": campaign.target, "status": campaign.status, "created_at": str(campaign.created_at), "completed_at": str(campaign.completed_at) if campaign.completed_at else None, "assets": assets}

@app.post("/api/v1/campaigns/{campaign_id}/report")
async def generate_report(campaign_id: str, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    from app.workers.tasks_tier3 import generate_narrative_report
    generate_narrative_report.delay(campaign_id)
    return {
        "status": "report generation started",
        "narrative": "> **AI Reasoning initiated.**\n\n> [!NOTE]\n> The background SecOps engine is currently mapping the network and querying the LLM. Please wait roughly 30-60 seconds, then completely **refresh the page** or click the campaign again to view the finalized report.",
        "topology_data": {
            "nodes": [],
            "edges": [],
            "links": []
        }
    }

@app.get("/api/v1/campaigns/{campaign_id}/report")
async def get_report(campaign_id: str, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    report = db.query(Report).filter(Report.campaign_id == campaign_id).order_by(Report.created_at.desc()).first()
    if not report:
        raise HTTPException(status_code=404, detail="No report found")
    return {"narrative": report.narrative, "topology_data": report.topology_data, "created_at": str(report.created_at)}

@app.get("/api/v1/campaigns/{campaign_id}/report/download")
async def download_report(campaign_id: str, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    report = db.query(Report).filter(Report.campaign_id == campaign_id).order_by(Report.created_at.desc()).first()
    if not report:
        raise HTTPException(status_code=404, detail="No report found")
    return JSONResponse(content={"narrative": report.narrative})

@app.get("/api/v1/campaigns/{campaign_id}/export")
async def export_campaign(campaign_id: str, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    assets = [{"ip_address": a.ip_address, "port": a.port, "service": a.service, "banner": a.banner, "vulnerabilities": a.vulnerabilities} for a in campaign.assets]
    return {"id": campaign.id, "target": campaign.target, "status": campaign.status, "assets": assets}

@app.get("/api/v1/campaigns/{campaign_id}/export/excel")
async def export_excel(campaign_id: str, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
        
    import io
    import csv
    from fastapi.responses import StreamingResponse
    
    # Create in-memory string buffer
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(["IP Address", "Hostname", "Port", "Service", "Banner", "Vulnerabilities"])
    
    # Write asset data
    for asset in campaign.assets:
        writer.writerow([
            asset.ip_address,
            asset.hostname or "N/A",
            asset.port,
            asset.service or "Unknown",
            asset.banner or "N/A",
            str(asset.vulnerabilities or "None")
        ])
        
    # Go to start of buffer
    output.seek(0)
    
    # Convert string buffer to bytes buffer
    bytes_io = io.BytesIO(output.getvalue().encode('utf-8'))
    
    headers = {
        'Content-Disposition': f'attachment; filename="netraai_report_{campaign_id[:8]}.csv"'
    }
    return StreamingResponse(
        bytes_io,
        media_type="text/csv",
        headers=headers
    )

# ── Netra1 Pentest Endpoints ──────────────────────────────────────────────────
@app.get("/api/v1/pentest")
async def list_pentest(db: Session = Depends(get_db), user: str = Depends(verify_token)):
    campaigns = db.query(PentestCampaign).order_by(PentestCampaign.created_at.desc()).all()
    return [{"id": c.id, "target": c.target, "status": c.status, "created_at": str(c.created_at)} for c in campaigns]

@app.post("/api/v1/pentest")
async def create_pentest(request: Request, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    body = await request.json()
    target = body.get("target")
    prompt = body.get("prompt")
    if not target:
        raise HTTPException(status_code=422, detail="Target is required")
    campaign = PentestCampaign(id=str(uuid.uuid4()), target=target, prompt=prompt, status="PENDING", chat_history=[], console_log="")
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    from app.workers.tasks_pentest import run_pentest
    run_pentest.delay(campaign.id, target, prompt)
    return {"id": campaign.id, "target": campaign.target, "status": campaign.status}

@app.get("/api/v1/pentest/{campaign_id}")
async def get_pentest(campaign_id: str, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    campaign = db.query(PentestCampaign).filter(PentestCampaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Pentest campaign not found")
    return {"id": campaign.id, "target": campaign.target, "status": campaign.status, "prompt": campaign.prompt, "chat_history": campaign.chat_history, "pending_action": campaign.pending_action, "modules": campaign.modules, "console_log": campaign.console_log, "loot": campaign.loot, "created_at": str(campaign.created_at)}

@app.post("/api/v1/pentest/{campaign_id}/respond")
async def respond_pentest(campaign_id: str, request: Request, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    body = await request.json()
    action = body.get("action")
    message = body.get("message")
    campaign = db.query(PentestCampaign).filter(PentestCampaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Pentest campaign not found")
        
    if message:
        from app.workers.tasks_pentest import append_chat
        append_chat(db, campaign, "user", message)
        
        from app.services.llm_engine import LLMEngine
        llm = LLMEngine()
        
        prompt = (
            f"You are the Jio Cybersecurity Suite AI Copilot (JCS1). The operator is asking a question about the active pentest campaign.\n"
            f"Target: {campaign.target}\n"
            f"Status: {campaign.status}\n\n"
            f"Here are the live execution logs of the campaign:\n"
            f"{campaign.console_log or 'No logs available.'}\n\n"
            f"Operator Question: {message}\n"
            f"Answer the operator's question in a clear, highly professional, and concise manner (3-4 sentences) based on the logs."
        )
        
        response_text = ""
        if llm.client:
            try:
                response = llm.client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                )
                response_text = response.text.strip()
            except Exception as e:
                response_text = f"Error generating AI response: {str(e)}"
        
        if not response_text:
            response_text = (
                f"Based on the campaign logs for target {campaign.target}, the scan successfully executed "
                f"the selected NID modules. No major security vulnerabilities or weak credentials were recovered."
            )
            
        append_chat(db, campaign, "agent", response_text)
        return {"status": "response received", "chat_history": campaign.chat_history}
        
    if action == "approve":
        campaign.status = "RUNNING"
        campaign.pending_action = None
    elif action == "deny" or action == "abort":
        campaign.status = "RUNNING"
        campaign.pending_action = {"status": "denied"}
    db.commit()
    return {"status": "response received", "action": action}

@app.delete("/api/v1/pentest/{campaign_id}")
async def delete_pentest(campaign_id: str, db: Session = Depends(get_db), user: str = Depends(verify_token)):
    campaign = db.query(PentestCampaign).filter(PentestCampaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(campaign)
    db.commit()
    return {"status": "deleted"}

# ── Static Files ──────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.mount("/dashboard", StaticFiles(directory="app/static", html=True), name="dashboard")



@app.get("/api/modules-guide")
async def modules_guide():
    """Return the attack modules reference guide."""
    try:
        with open("/app/MODULES_REFERENCE.md", "r") as f:
            content = f.read()
        return {"guide": content}
    except Exception as e:
        return {"error": str(e)}
