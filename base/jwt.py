from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from jose import jwt, JWTError
from .exceptions import credentials_exception

SECRET_KEY = "f094faa6ca2563b88e8d3e56c818166b7a9564caa6cf09d25e3b93f7099f6f07"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1


class Token(BaseModel):
    access_token: str
    token_type: str


def create_token(login: str, expires_delta: Optional[timedelta] = None) -> Token:
    if expires_delta is None:
        expires_delta = ACCESS_TOKEN_EXPIRE_MINUTES
    expires = datetime.utcnow() + timedelta(minutes=expires_delta)
    to_encode = {"sub": login,
                 "exp": expires
                 }
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return Token(access_token=encoded_jwt, token_type="Bearer")


def decode_token(token) -> str:
    try:
        token_decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        login = token_decoded['sub']
        if not login:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return login
