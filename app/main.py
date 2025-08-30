# D:\Checker V1.4\app\main.py

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import List


from .models import SessionLocal, Employee, Shipment, UnmatchedShipment, Company
# الاستيراد النسبي من نفس الحزمة

# --- إعدادات نظام المصادقة (JWT) ---
# هام: قم بتغيير هذا المفتاح إلى سلسلة عشوائية طويلة ومعقدة في بيئة الإنتاج
SECRET_KEY = "a_very_secret_key_that_should_be_long_and_random"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # صلاحية التوكن: 7 أيام

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- نماذج البيانات (Pydantic Models) ---
# تستخدم للتحقق من صحة البيانات الواردة والصادرة
class TokenData(BaseModel):
    username: str | None = None

class ShipmentScan(BaseModel):
    shipment_id: str
    
class ShipmentDetails(BaseModel):
    shipment_id: str
    status: str
    checked: bool
    inspected_date: datetime | None
    inspector_name: str | None

class EmployeePerformance(BaseModel):
    employee_id: int
    employee_name: str
    inspected_count: int

# --- إعداد تطبيق FastAPI ---
app = FastAPI(
    title="recheck API",
    description="الواجهة الخلفية لنظام فحص الشحنات (recheck)",
    version="1.0.0"
)

# إعداد CORS للسماح لتطبيق الواجهة الأمامية بالاتصال
origins = [
    "http://localhost:3000",  # لـ React Web (أثناء التطوير)
    "http://localhost:8081",
    https://recheck-eg.netlify.app,
# لـ React Native Metro Bundler
    # يمكنك إضافة عناوين أخرى هنا في المستقبل
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- دوال مساعدة لقاعدة البيانات والمصادقة ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(Employee).filter(Employee.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# --- نقاط النهاية (API Endpoints) ---

# --- قسم المصادقة (Authentication) ---
@app.post("/token", summary="إنشاء توكن الدخول للمستخدم")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(Employee).filter(Employee.username == form_data.username.lower()).first()
    if not user or not user.check_password(form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "user_role": user.role, 
        "user_name": user.name
    }

@app.get("/users/me", summary="الحصول على تفاصيل المستخدم الحالي")
async def read_users_me(current_user: Employee = Depends(get_current_user)):
    return {"username": current_user.username, "role": current_user.role, "name": current_user.name, "company_id": current_user.company_id}

# --- قسم الموظف (فحص الشحنات) ---
@app.post("/shipments/check-scan", summary="فحص شحنة عبر مسح الباركود")
def check_shipment_by_scan(scan_data: ShipmentScan, db: Session = Depends(get_db), current_user: Employee = Depends(get_current_user)):
    shipment_id = scan_data.shipment_id.strip().lower()
    shipment = db.query(Shipment).filter(Shipment.shipment_id == shipment_id).order_by(Shipment.id.desc()).first()

    if not shipment:
        unmatched = UnmatchedShipment(shipment_id=shipment_id, employee_id=current_user.id)
        db.add(unmatched)
        db.commit()
        return {"status": "Not Found", "type": None}

    if shipment.checked:
        return {"status": "Already Checked", "type": shipment.status}
        
    shipment.checked = True
    shipment.inspected_by = current_user.id
    shipment.inspected_date = datetime.utcnow()
    db.commit()

    return {"status": "Checked", "type": shipment.status}

# --- قسم المدير (متابعة الأداء والبحث) ---
@app.get("/manager/performance", response_model=List[EmployeePerformance], summary="عرض أداء جميع الموظفين في الشركة")
def get_employee_performance(db: Session = Depends(get_db), current_user: Employee = Depends(get_current_user)):
    if current_user.role not in ["manager", "owner"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    employees = db.query(Employee).filter(Employee.company_id == current_user.company_id, Employee.role == 'employee').all()
    
    performance_data = []
    for emp in employees:
        count = db.query(Shipment).filter(Shipment.inspected_by == emp.id).count()
        performance_data.append({
            "employee_id": emp.id,
            "employee_name": emp.name,
            "inspected_count": count
        })
    return performance_data

@app.get("/manager/search/{shipment_id}", response_model=ShipmentDetails, summary="البحث عن تفاصيل شحنة محددة")
def search_shipment_details(shipment_id: str, db: Session = Depends(get_db), current_user: Employee = Depends(get_current_user)):
    if current_user.role not in ["manager", "owner"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    shipment = db.query(Shipment).filter(Shipment.shipment_id == shipment_id.strip().lower()).order_by(Shipment.id.desc()).first()
    if not shipment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shipment not found")

    inspector_name = shipment.inspector.name if shipment.inspector else "غير محدد"
    
    return {
        "shipment_id": shipment.shipment_id,
        "status": shipment.status,
        "checked": shipment.checked,
        "inspected_date": shipment.inspected_date,
        "inspector_name": inspector_name
    }
class EmployeeCreate(BaseModel):
    name: str
    username: str
    password: str

@app.post("/manager/employees", summary="إضافة موظف جديد للشركة")
def create_employee(employee_data: EmployeeCreate, db: Session = Depends(get_db), current_user: Employee = Depends(get_current_user)):
    if current_user.role not in ["manager", "owner"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    # التحقق من أن الموظف الجديد سيكون في نفس شركة المدير
    if not current_user.company_id:
        raise HTTPException(status_code=400, detail="Manager is not associated with a company")

    existing_user = db.query(Employee).filter(Employee.username == employee_data.username.lower()).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    new_employee = Employee(
        name=employee_data.name,
        username=employee_data.username.lower(),
        role="employee",
        company_id=current_user.company_id # ربط الموظف بشركة المدير
    )
    new_employee.set_password(employee_data.password)
    db.add(new_employee)
    db.commit()
    return {"message": "Employee created successfully"}

@app.delete("/manager/employees/{employee_id}", summary="حذف موظف من الشركة")
def delete_employee(employee_id: int, db: Session = Depends(get_db), current_user: Employee = Depends(get_current_user)):
    if current_user.role not in ["manager", "owner"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    employee_to_delete = db.query(Employee).filter(Employee.id == employee_id).first()
    
    # التحقق من وجود الموظف وأنه في نفس شركة المدير
    if not employee_to_delete:
        raise HTTPException(status_code=404, detail="Employee not found")
        
    if employee_to_delete.company_id != current_user.company_id:
        raise HTTPException(status_code=403, detail="Cannot delete an employee from another company")
    
    db.delete(employee_to_delete)
    db.commit()

    return {"message": "Employee deleted successfully"}
class ManagerCreate(BaseModel):
    name: str
    username: str
    password: str
    company_id: int
    company_name: str | None = None # اختياري، فقط إذا كانت الشركة جديدة

class ManagerInfo(BaseModel):
    id: int
    name: str
    username: str
    company_id: int
    company_name: str

@app.post("/owner/managers", summary="إضافة مدير جديد و/أو شركة جديدة")
def create_manager(manager_data: ManagerCreate, db: Session = Depends(get_db), current_user: Employee = Depends(get_current_user)):
    if current_user.role != "owner":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this action")

    # التحقق من وجود اسم المستخدم
    existing_user = db.query(Employee).filter(Employee.username == manager_data.username.lower()).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # التحقق من الشركة
    company = db.query(Company).filter(Company.id == manager_data.company_id).first()
    if not company:
        if not manager_data.company_name:
            raise HTTPException(status_code=400, detail="Company does not exist and no new company name was provided")
        company = Company(id=manager_data.company_id, name=manager_data.company_name)
        db.add(company)
        db.commit()
        db.refresh(company)

    # إنشاء المدير الجديد
    new_manager = Employee(
        name=manager_data.name,
        username=manager_data.username.lower(),
        role="manager",
        company_id=company.id
    )
    new_manager.set_password(manager_data.password)
    db.add(new_manager)
    db.commit()
    
    return {"message": "Manager created successfully"}


@app.get("/owner/managers", response_model=List[ManagerInfo], summary="الحصول على قائمة بجميع المدراء")
def get_all_managers(db: Session = Depends(get_db), current_user: Employee = Depends(get_current_user)):
    if current_user.role != "owner":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
        
    managers = db.query(Employee).filter(Employee.role == 'manager').all()
    
    # تحضير البيانات للعرض
    result = []
    for mgr in managers:
        result.append({
            "id": mgr.id,
            "name": mgr.name,
            "username": mgr.username,
            "company_id": mgr.company_id,
            "company_name": mgr.company.name if mgr.company else "N/A"
        })
    return result
