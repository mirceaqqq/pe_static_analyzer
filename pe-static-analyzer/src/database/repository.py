"""
PE Static Analyzer - Database & Reporting System
"""
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import json
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

from src.core.analyzer import AnalysisResult

Base = declarative_base()

class AnalysisRecord(Base):
    __tablename__ = 'analyses'
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
    __tablename__ = 'sections'
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey('analyses.id'))
    name = Column(String(16))
    entropy = Column(Float)
    executable = Column(Boolean)
    writable = Column(Boolean)
    readable = Column(Boolean)
    analysis = relationship("AnalysisRecord", back_populates="sections")

class AnalysisRepository:
    def __init__(self, db_path="pe_analyzer.db"):
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def save_analysis(self, result: AnalysisResult) -> int:
        record = AnalysisRecord(
            file_path=result.file_path,
            file_name=Path(result.file_path).name,
            sha256=result.file_hash.get("sha256"),
            suspicion_score=result.suspicion_score,
            risk_level=result.risk_level,
            packer_detected=result.packer_detected,
            analysis_duration=result.analysis_duration,
            modules_used=json.dumps(result.modules_used)
        )
        self.session.add(record)
        self.session.flush()
        for s in result.sections:
            sec = SectionRecord(
                analysis_id=record.id,
                name=s['name'],
                entropy=s['entropy'],
                executable=s['executable'],
                writable=s['writable'],
                readable=s['readable']
            )
            self.session.add(sec)
        self.session.commit()
        return record.id

class JSONReporter:
    @staticmethod
    def generate(result: AnalysisResult, path: str):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
