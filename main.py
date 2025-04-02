from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import sqlite3
from jose import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi import Request, Depends

# Secret key for JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

# Mount static files for serving HTML
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize database
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Password Hashing
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Token Generation
def create_access_token(username: str):
    expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

# Serve Login Page
@app.get("/", response_class=HTMLResponse)
def get_login_page():
    with open("static/index.html", "r") as file:
        return HTMLResponse(content=file.read())

# Signup Route
@app.post("/signup")
async def signup(username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT username FROM users WHERE username=?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = hash_password(password)
    cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/", status_code=303)

# Login Route
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT hashed_password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row or not verify_password(password, row[0]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(username)
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="token", value=token, httponly=True)
    return response

def verify_token(request: Request): # verify that they have a valid token and cant just bypass logging in
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Unable - Please log in")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]  # Return username if valid
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired, please log in again")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard_page(username: str = Depends(verify_token)):
    with open("static/dashboard.html", "r") as file:
        return HTMLResponse(content=file.read())
