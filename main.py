from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Dict, Optional
import json
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
import asyncio
import uvicorn
import sqlite3
import aiosqlite
from contextlib import asynccontextmanager

# Configuration
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = "chat_app.db"

# Global variables
active_connections: Dict[str, WebSocket] = {}

# Database initialization
async def init_database():
    async with aiosqlite.connect(DATABASE_URL) as db:
        # Create users table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create messages table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                message_type TEXT DEFAULT 'message',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        """)
        
        await db.commit()

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_database()
    yield
    # Shutdown (cleanup if needed)
    pass

app = FastAPI(title="Secure Chat App", lifespan=lifespan)
security = HTTPBearer()
templates = Jinja2Templates(directory="templates")

# Models
class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Message(BaseModel):
    content: str
    timestamp: datetime
    username: str

# Database operations
class DatabaseManager:
    @staticmethod
    async def create_user(username: str, password: str) -> bool:
        try:
            password_hash = hash_password(password)
            async with aiosqlite.connect(DATABASE_URL) as db:
                await db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                await db.commit()
                return True
        except sqlite3.IntegrityError:
            return False
    
    @staticmethod
    async def verify_user(username: str, password: str) -> bool:
        async with aiosqlite.connect(DATABASE_URL) as db:
            cursor = await db.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,)
            )
            row = await cursor.fetchone()
            if row is None:
                return False
            return verify_password(password, row[0])
    
    @staticmethod
    async def user_exists(username: str) -> bool:
        async with aiosqlite.connect(DATABASE_URL) as db:
            cursor = await db.execute(
                "SELECT 1 FROM users WHERE username = ?",
                (username,)
            )
            row = await cursor.fetchone()
            return row is not None
    
    @staticmethod
    async def save_message(username: str, content: str, message_type: str = "message"):
        async with aiosqlite.connect(DATABASE_URL) as db:
            await db.execute(
                "INSERT INTO messages (username, content, message_type) VALUES (?, ?, ?)",
                (username, content, message_type)
            )
            await db.commit()
    
    @staticmethod
    async def get_recent_messages(limit: int = 50) -> List[Dict]:
        async with aiosqlite.connect(DATABASE_URL) as db:
            cursor = await db.execute("""
                SELECT username, content, message_type, 
                       datetime(timestamp, 'localtime') as timestamp 
                FROM messages 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            rows = await cursor.fetchall()
            
            messages = []
            for row in rows:
                messages.append({
                    "username": row[0],
                    "content": row[1],
                    "type": row[2],
                    "timestamp": row[3]
                })
            
            # Return messages in chronological order (oldest first)
            return list(reversed(messages))

# Utility functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except jwt.PyJWTError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    username = verify_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify user still exists in database
    if not await DatabaseManager.user_exists(username):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return username

# Routes
@app.get("/", response_class=HTMLResponse)
async def get_chat_page(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})

@app.post("/register")
async def register(user: UserCreate):
    # Validate input
    if len(user.username.strip()) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters long")
    
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")
    
    # Check if username contains only alphanumeric characters and underscores
    if not user.username.replace('_', '').isalnum():
        raise HTTPException(status_code=400, detail="Username can only contain letters, numbers, and underscores")
    
    success = await DatabaseManager.create_user(user.username.strip(), user.password)
    if not success:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    access_token = create_access_token(data={"sub": user.username.strip()})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/login")
async def login(user: UserLogin):
    if not await DatabaseManager.verify_user(user.username.strip(), user.password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    access_token = create_access_token(data={"sub": user.username.strip()})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/messages")
async def get_messages(current_user: str = Depends(get_current_user)):
    messages = await DatabaseManager.get_recent_messages()
    return {"messages": messages}

@app.get("/users/me")
async def get_current_user_info(current_user: str = Depends(get_current_user)):
    return {"username": current_user}

@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    username = verify_token(token)
    if username is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    # Verify user exists in database
    if not await DatabaseManager.user_exists(username):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    await websocket.accept()
    active_connections[username] = websocket
    
    # Send user joined notification
    join_message = {
        "type": "system",
        "content": f"{username} joined the chat",
        "timestamp": datetime.utcnow().isoformat(),
        "username": "System"
    }
    
    # Save system message to database
    await DatabaseManager.save_message("System", f"{username} joined the chat", "system")
    await broadcast_message(join_message)
    
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            # Validate message content
            content = message_data.get("content", "").strip()
            if not content or len(content) > 1000:  # Max message length
                continue
            
            # Create message object
            message = {
                "type": "message",
                "content": content,
                "timestamp": datetime.utcnow().isoformat(),
                "username": username
            }
            
            # Save message to database
            await DatabaseManager.save_message(username, content, "message")
            
            # Broadcast to all connected clients
            await broadcast_message(message)
            
    except WebSocketDisconnect:
        if username in active_connections:
            del active_connections[username]
        
        # Send user left notification
        leave_message = {
            "type": "system",
            "content": f"{username} left the chat",
            "timestamp": datetime.utcnow().isoformat(),
            "username": "System"
        }
        
        # Save system message to database
        await DatabaseManager.save_message("System", f"{username} left the chat", "system")
        await broadcast_message(leave_message)
    except Exception as e:
        print(f"WebSocket error for user {username}: {e}")
        if username in active_connections:
            del active_connections[username]

async def broadcast_message(message: dict):
    if active_connections:
        message_json = json.dumps(message)
        disconnected = []
        
        for username, connection in active_connections.items():
            try:
                await connection.send_text(message_json)
            except Exception as e:
                print(f"Failed to send message to {username}: {e}")
                disconnected.append(username)
        
        # Clean up disconnected clients
        for username in disconnected:
            if username in active_connections:
                del active_connections[username]

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "database": "connected"}

# Get chat statistics
@app.get("/stats")
async def get_stats(current_user: str = Depends(get_current_user)):
    async with aiosqlite.connect(DATABASE_URL) as db:
        # Get total users
        cursor = await db.execute("SELECT COUNT(*) FROM users")
        total_users = (await cursor.fetchone())[0]
        
        # Get total messages
        cursor = await db.execute("SELECT COUNT(*) FROM messages WHERE message_type = 'message'")
        total_messages = (await cursor.fetchone())[0]
        
        # Get online users
        online_users = len(active_connections)
        
        return {
            "total_users": total_users,
            "total_messages": total_messages,
            "online_users": online_users,
            "connected_users": list(active_connections.keys())
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)