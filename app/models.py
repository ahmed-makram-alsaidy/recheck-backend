# models.py

import os
import bcrypt
import datetime
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.exc import OperationalError
import logging

# Configure logging for database operations
logging.basicConfig(level=logging.INFO)
db_logger = logging.getLogger('sqlalchemy.engine')

Base = declarative_base()

class Company(Base):
    __tablename__ = 'companies'
    id = Column(Integer, primary_key=True, autoincrement=False)
    name = Column(String(255), unique=True, nullable=False)
    employees = relationship('Employee', back_populates='company', cascade="all, delete-orphan")

class Employee(Base):
    __tablename__ = 'employees'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    username = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    password_plain = Column(String(255), nullable=True) # For display/recovery, not for production security
    role = Column(String(50), default='employee', nullable=False, index=True)
    company_id = Column(Integer, ForeignKey('companies.id'), nullable=True)
    company = relationship('Company', back_populates='employees')

    def set_password(self, password):
        self.password_plain = password
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except (ValueError, TypeError):
            return False

class Shipment(Base):
    __tablename__ = 'shipments'
    id = Column(Integer, primary_key=True, autoincrement=True)
    shipment_id = Column(String(255), nullable=False, index=True) # Indexed for faster lookups
    status = Column(String(50), nullable=False)
    checked = Column(Boolean, default=False, index=True)
    imported = Column(Boolean, default=False)
    inspected_date = Column(DateTime, nullable=True)
    
    employee_id = Column(Integer, ForeignKey('employees.id'), nullable=True)
    employee = relationship('Employee', foreign_keys=[employee_id], backref='shipments')

    inspected_by = Column(Integer, ForeignKey('employees.id'), nullable=True)
    inspector = relationship('Employee', foreign_keys=[inspected_by], backref='inspected_shipments')

class EmployeeActivity(Base):
    __tablename__ = 'employee_activities'
    id = Column(Integer, primary_key=True, autoincrement=True)
    employee_id = Column(Integer, ForeignKey('employees.id'), nullable=False)
    sheet_name = Column(String(255), nullable=False)
    shipment_count = Column(Integer, nullable=False)
    activity_date = Column(DateTime, default=datetime.datetime.now)
    employee = relationship('Employee', backref='activities')

class UnmatchedShipment(Base):
    __tablename__ = 'unmatched_shipments'
    id = Column(Integer, primary_key=True, autoincrement=True)
    shipment_id = Column(String(255), nullable=False)
    date = Column(DateTime, default=datetime.datetime.now)
    employee_id = Column(Integer, ForeignKey('employees.id'), nullable=False)
    employee = relationship('Employee', backref='unmatched_shipments')


# --- Database Connection ---
# IMPORTANT: Replace with your actual database credentials
DATABASE_URL = (
    "postgresql://shipments_owner:npg_LBrZfvsy1m6S@ep-mute-sun-a5v8rm1v-pooler.us-east-2.aws.neon.tech/shipments?sslmode=require"
)

try:
    # Use pool_recycle to prevent timeout issues with cloud databases
    engine = create_engine(DATABASE_URL, echo=False, pool_recycle=3600) 
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db_logger.info("Database engine created successfully.")
except OperationalError as e:
    db_logger.error("FATAL: Could not connect to the database: %s", e)
    raise

def create_tables():
    """Create all tables in the database if they don't exist."""
    try:
        Base.metadata.create_all(bind=engine)
        db_logger.info("Tables checked/created successfully.")
    except Exception as e:
        db_logger.error("Error creating database tables: %s", e)
        raise

if __name__ == "__main__":
    print("Creating database tables...")
    create_tables()
    print("Done.")