from passlib.context import CryptContext
import jwt
from dotenv import dotenv_values
from connection import  user_collection
from datetime import datetime, timedelta
from fastapi import HTTPException

ACCESS_TOKEN_EXPIRES_MINUTES = 60

config_credentials = dotenv_values(".env")

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def get_hashed_password(password):
    return pwd_context.hash(password)

async def verify_password(plain_password, hashed_password):
    verified = pwd_context.verify(plain_password, hashed_password)

    return verified


async def authenticate_user(email:str, password:str):
    user = user_collection.find_one({"email": email})
    if user is None:
        return False
    passwordhash = user["password"]
    verified = await verify_password(password, passwordhash)
    if user and verified:
        user = {**user, "_id": str(user["_id"])}
        return user
    return False

async def token_generator(email:str, password:str):
    user = await authenticate_user(email,password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token_data = {
        "id": user["id"],
        "email": user["email"],
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES),
    }
    del user["password"]
    token = jwt.encode(token_data, config_credentials["SECRET"])
    user["token"] = token
    return user
