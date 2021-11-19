from pydantic import BaseModel
from typing import Optional
from .jwt import decode_token
from .exceptions import login_pswd_exception, credentials_exception

USERS_DB = {"johndoe": {"full_name": "John Doe",
                        "login": "johndoe",
                        "password": "mysecret",
                        "email": "johndoe@example.com",
                        "active": False
                        }
            }


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
    if not db_user or db_user['password'] != password:
        raise login_pswd_exception
    return db_user['login']
