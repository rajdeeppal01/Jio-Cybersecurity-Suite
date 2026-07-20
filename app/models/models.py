import datetime
from sqlalchemy import Column, String, Integer, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base

class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String, primary_key=True, index=True)
    target = Column(String, nullable=False)
    status = Column(String, default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    assets = relationship("Asset", back_populates="campaign", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="campaign", cascade="all, delete-orphan")

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(String, ForeignKey("campaigns.id"), nullable=False)
    ip_address = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    port = Column(Integer, nullable=False)
    service = Column(String, nullable=True)
    banner = Column(String, nullable=True)
    vulnerabilities = Column(JSON, nullable=True) # List of vulnerabilities detected on port
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    campaign = relationship("Campaign", back_populates="assets")

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(String, ForeignKey("campaigns.id"), nullable=False)
    topology_data = Column(JSON, nullable=False) # minified graph topological json
    narrative = Column(String, nullable=False) # LLM generated report
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    campaign = relationship("Campaign", back_populates="reports")


class PentestCampaign(Base):
    __tablename__ = "pentest_campaigns"

    id = Column(String, primary_key=True, index=True)
    target = Column(String, nullable=False)
    status = Column(String, default="PENDING")   # PENDING, RUNNING, WAITING_FOR_PERMISSION, COMPLETED, FAILED
    prompt = Column(String, nullable=True)        # Natural language prompt from user
    chat_history = Column(JSON, default=list)     # Conversational logs: [{"role": "user"/"agent", "text": "...", "timestamp": "..."}]
    pending_action = Column(JSON, nullable=True)   # Details of action waiting for approval: {"type": "exploit", "module": "...", "description": "..."}
    modules = Column(JSON, nullable=True)         # List of selected exploit modules
    console_log = Column(String, default="")      # Real-time streaming cyberpunk log
    loot = Column(JSON, nullable=True)            # JSON of harvested credentials/flags
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
