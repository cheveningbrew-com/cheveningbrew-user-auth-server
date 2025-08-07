import os
import logging
import jwt
from datetime import datetime, timedelta

from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
from google.oauth2 import id_token
from google.auth.transport import requests
from dotenv import load_dotenv
import requests as http_requests

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")  # Use a secure key in production
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_DELTA = 24  # Token expiration in hours


load_dotenv()

# Get allowed origins from environment variable, default to localhost for development
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3001")
allowed_origins_list = [origin.strip() for origin in ALLOWED_ORIGINS.split(",")]

app = FastAPI()

# Configure CORS with multiple allowed origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

WEB_CLIENT_ID = os.getenv("WEB_CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DOMAIN_NAME = os.getenv("DOMAIN_NAME")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:3001")

@app.post("/api/auth/google")
async def verify_token(data: dict = Body(...)):
    auth_code = data.get("code")  # The frontend is sending the auth code as idToken

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
        token_response.raise_for_status()  # Raise exception for 4XX/5XX responses
        token_json = token_response.json()

        # Extract the ID token from the response
        id_token_str = token_json.get("id_token")

        logger.debug(f"ID token: {id_token_str}")

        if not id_token_str:
            return {"authenticated": False, "error": "No ID token received"}

        # Verify the ID token
        idinfo = id_token.verify_oauth2_token(id_token_str, requests.Request(), WEB_CLIENT_ID)

        logger.debug(f"ID token info: {idinfo}")

        # Check that the token is valid for your app
        if idinfo["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            # Log the error
            logger.error(f"Invalid token issuer: {idinfo['iss']}")
            # Return error response to client
            return {"authenticated": False, "error": "Wrong issuer."}


        # Extract user info you want to return
        user_info = {
            "id": idinfo["sub"],
            "email": idinfo.get("email"),
            "name": idinfo.get("name"),
            "picture": idinfo.get("picture")
        }

        logger.info(f"User info: {user_info}")

        # Generate or retrieve an auth token for your app's session management
        auth_token = token_generator(user_info)

        return {
    "authenticated": True,
    "authToken": auth_token,
    "user": user_info,
    "expiresIn": JWT_EXPIRATION_DELTA * 3600  # Add expiration time in seconds
}

    except ValueError as e:
        return {"authenticated": False, "error": f"Token validation failed: {str(e)}"}
    except http_requests.RequestException as e:
        return {"authenticated": False, "error": f"Network error: {str(e)}"}
    except Exception as e:
        return {"authenticated": False, "error": f"Authentication error: {str(e)}"}

def token_generator(user_info):
    """Generate a JWT token with expiration"""
    # Set expiration time
    expiration = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_DELTA)

    # Create payload
    payload = {
        "sub": user_info["id"],
        "email": user_info["email"],
        "name": user_info["name"],
        "exp": expiration,
        "iat": datetime.utcnow()
    }

    # Create token
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return token

if __name__ == "__main__":
    pass