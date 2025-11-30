"""
PE Static Analyzer - Database & Reporting System
"""
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.analyzer import AnalysisResult
from src.database.models import Base, AnalysisRecord, SectionRecord

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
