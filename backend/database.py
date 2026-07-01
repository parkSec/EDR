import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    Text,
    Float,
)
from sqlalchemy.orm import declarative_base, sessionmaker


# EDR 프로젝트 최상위 폴더의 .env 파일 경로
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"

# .env 파일 불러오기
load_dotenv(dotenv_path=ENV_PATH)

# .env의 DATABASE_URL 읽기
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL을 찾을 수 없습니다. "
        "EDR 최상위 폴더의 .env 파일을 확인하세요."
    )


# Neon 온라인 PostgreSQL 연결
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()


class SysmonLog(Base):
    __tablename__ = "sysmon_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    recv_time = Column(DateTime, default=datetime.now)
    gen_time = Column(DateTime, nullable=True)

    host_ip = Column(String(50))
    os_name = Column(String(100))

    rule_level = Column(String(20))
    risk = Column(String(10))
    ai_risk = Column(String(10), nullable=True)

    detect_type = Column(String(20))

    tactic_id = Column(String(20))
    tactic_name = Column(String(100))
    technique_id = Column(String(20))
    technique_name = Column(String(100))

    action_desc = Column(Text)
    process_name = Column(String(200))
    event_id = Column(Integer)

    command_line = Column(Text, nullable=True)
    destination_ip = Column(String(50), nullable=True)
    destination_port = Column(String(10), nullable=True)
    query_name = Column(String(500), nullable=True)

    status = Column(String(20), default="신규")
    ai_score = Column(Float, nullable=True)


def init_db():
    """DB 테이블이 없으면 생성한다."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI 요청마다 DB 세션을 생성하고 종료한다."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()