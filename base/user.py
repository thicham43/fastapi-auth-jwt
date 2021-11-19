from pydantic import BaseModel
from typing import Optional
from passlib.context import CryptContext
from .jwt import decode_token
from .exceptions import login_pswd_exception, credentials_exception

USERS_DB = {"johndoe": {"full_name": "John Doe",
                        "login": "johndoe",
                        "password": "$2b$12$LACBh9K4u02C/hCBTFI6ne9KiueyYnBcOjsrD3foj1JYtCybdjsc6",
                        "email": "johndoe@example.com",
                        "active": True
                        }
            }

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(BaseModel):
    full_name: str
    login: str
    password: str
    email: Optional[str] = None
    active: Optional[bool] = None


def get_current_user(token: str) -> User:
    """
    decode the token to extract the login as the token subject.
    get user from db based on login
    :param token: a string jwt token
    :return: an instance of User
    """
    login = decode_token(token)
    user_dict = USERS_DB.get(login)
    if not user_dict:
        raise credentials_exception
    return User(**user_dict)


def get_password_hash(password) -> str:
    return pwd_context.hash(password)


def verify_password(password, db_password) -> bool:
    return pwd_context.verify(password, db_password)


def authenticate_user(login, password) -> str:
    """
    check if the login is found in DB
    if yes, hash given password and check it against password in DB
    if all ok, return the user
    :param login: --
    :param password: --
    :return: user's login
    """
    db_user = USERS_DB.get(login, False)
    if not db_user or not verify_password(password, db_user['password']):
        raise login_pswd_exception
    return db_user['login']
