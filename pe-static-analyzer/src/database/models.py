from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Text,
    Boolean,
    ForeignKey,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class AnalysisRecord(Base):
    __tablename__ = "analyses"
    id = Column(Integer, primary_key=True)
    file_path = Column(String(512))
    file_name = Column(String(256))
    sha256 = Column(String(64))
    suspicion_score = Column(Float)
    risk_level = Column(String(20))
    packer_detected = Column(String(100))
    timestamp = Column(DateTime, default=datetime.now)
    analysis_duration = Column(Float)
    modules_used = Column(Text)
    sections = relationship("SectionRecord", back_populates="analysis", cascade="all, delete-orphan")


class SectionRecord(Base):
    __tablename__ = "sections"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"))
    name = Column(String(16))
    entropy = Column(Float)
    executable = Column(Boolean)
    writable = Column(Boolean)
    readable = Column(Boolean)
    analysis = relationship("AnalysisRecord", back_populates="sections")
