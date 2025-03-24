import os
import logging
import jwt
from datetime import datetime, timedelta

from fastapi import FastAPI, Body, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from google.oauth2 import id_token
from google.auth.transport import requests
from dotenv import load_dotenv
import requests as http_requests

from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import User

# Load environment variables
load_dotenv()

# Logging setup
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")  # Use a secure key in production
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_DELTA = 24  # Token expiration in hours

# Google OAuth Config
WEB_CLIENT_ID = os.getenv("WEB_CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:3001")

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "FastAPI with Google Authentication and PostgreSQL"}

@app.post("/api/auth/google")
async def verify_token(data: dict = Body(...), db: Session = Depends(get_db)):
    auth_code = data.get("code")

    if not auth_code:
        raise HTTPException(status_code=400, detail="Authorization code is required")

    try:
        # Exchange authorization code for tokens
        token_endpoint = "https://oauth2.googleapis.com/token"
        token_data = {
            "code": auth_code,
            "client_id": WEB_CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code"
        }

        token_response = http_requests.post(token_endpoint, data=token_data)
        token_response.raise_for_status()
        token_json = token_response.json()

        # Extract the ID token
        id_token_str = token_json.get("id_token")
        if not id_token_str:
            raise HTTPException(status_code=400, detail="No ID token received")

        # Verify ID token
        idinfo = id_token.verify_oauth2_token(id_token_str, requests.Request(), WEB_CLIENT_ID)

        if idinfo["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            raise HTTPException(status_code=400, detail="Invalid token issuer")

        # Extract user info
        user_info = {
            "id": idinfo["sub"],
            "email": idinfo.get("email"),
            "name": idinfo.get("name"),
            "picture": idinfo.get("picture")
        }

        logger.info(f"Authenticated user: {user_info}")

        # Check if user exists in DB
        user = db.query(User).filter(User.email == user_info["email"]).first()
        if not user:
            user = User(name=user_info["name"], email=user_info["email"], picture=user_info["picture"])
            db.add(user)
            db.commit()
            db.refresh(user)

        # Generate auth token
        auth_token = token_generator(user_info)

        return {
            "authenticated": True,
            "authToken": auth_token,
            "user": user_info,
            "expiresIn": JWT_EXPIRATION_DELTA * 3600
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Token validation failed: {str(e)}")
    except http_requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Network error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication error: {str(e)}")

def token_generator(user_info):
    expiration = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_DELTA)
    payload = {
        "sub": user_info["id"],
        "email": user_info["email"],
        "name": user_info["name"],
        "exp": expiration,
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
