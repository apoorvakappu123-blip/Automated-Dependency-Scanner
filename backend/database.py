import os
from pathlib import Path
from datetime import datetime, timezone

from dotenv import load_dotenv
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    JSON,
    text
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.engine import URL, make_url


# Load local environment variables
load_dotenv(Path(__file__).resolve().parent / ".env")


# PostgreSQL connection
render_database_url = os.getenv("DATABASE_URL")

if render_database_url:
    database_url = make_url(render_database_url).set(
        drivername="postgresql+psycopg"
    )
else:
    database_url = URL.create(
        drivername="postgresql+psycopg",
        username=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=os.getenv("DB_NAME")
    )


engine = create_engine(
    database_url,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)

Base = declarative_base()


# Scan history table
class ScanHistory(Base):

    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)

    project_name = Column(String(255), nullable=False)

    scan_type = Column(String(30), nullable=False)

    scanned_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    total_vulnerabilities = Column(Integer, default=0)

    critical = Column(Integer, default=0)
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)

    risk_score = Column(String(30))
    risk_level = Column(String(50))

    analysis = Column(JSON, nullable=False)


# Create database table
def init_db():

    Base.metadata.create_all(bind=engine)


# Test database connection
def test_db_connection():

    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))

    return True


# Save successful scan results to PostgreSQL
def save_scan_history(project_name, scan_type, analysis):

    session = SessionLocal()

    try:
        severity = analysis.get("severity_summary", {})

        scan_record = ScanHistory(
            project_name=str(project_name)[:255],
            scan_type=scan_type,
            total_vulnerabilities=int(
                analysis.get("total_vulnerabilities", 0) or 0
            ),
            critical=int(severity.get("CRITICAL", 0) or 0),
            high=int(severity.get("HIGH", 0) or 0),
            medium=int(severity.get("MEDIUM", 0) or 0),
            low=int(severity.get("LOW", 0) or 0),
            risk_score=str(analysis.get("risk_score", "N/A")),
            risk_level=str(analysis.get("risk_level", "UNKNOWN")),
            analysis=analysis
        )

        session.add(scan_record)
        session.commit()

        return scan_record.id

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()
