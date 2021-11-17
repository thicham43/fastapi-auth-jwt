from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
from jose import jwt, JWTError
from datetime import datetime, timedelta


SECRET_KEY = "f094faa6ca2563b88e8d3e56c818166b7a9564caa6cf09d25e3b93f7099f6f07"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1

USERS_DB = {"johndoe": {"full_name": "John Doe",
                        "login": "johndoe",
                        "password": "mysecret",
                        "email": "johndoe@example.com",
                        "active": False
                        }
            }

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="get-token")
app = FastAPI(title="OAuth2 and JWT demo")


class Token(BaseModel):
    access_token: str
    token_type: str


class User(BaseModel):
    full_name: str
    login: str
    password: str
    email: Optional[str] = None
    active: Optional[bool] = None


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    try to decode the token to extract the username as the token subject
    throw an jwtError exception if the username is None
    get user from db based on username
    :param token: a string corresponding to a generated jwt token
    :return: an instance of User
    """
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                          detail="Could not validate credentials",
                                          headers={"WWW-Authenticate": "Bearer"},
                                          )
    try:
        token_decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = token_decoded['sub']
        if not username:
            raise credentials_exception
        return USERS_DB.get(username)
    except JWTError:
        raise credentials_exception


@app.get("/my-favorites")
def get_favorite_books(current_user: User = Depends(get_current_user)):
    """
    this is supposed to be a secured endpoint. only logged in and active users are allowed
    :param current_user: the current user who's trying to access the endpoint
    :return: list of favorite books, else throws an exception (handled by the dependency)
    """
    return ["fav_book_1", "fav_book_2", "fav_book_3"]


def authenticate_user(db, username, password) -> User:
    """
    check if the username is found in DB
    if yes, hash given password and check it against password in DB
    if all ok, return the user
    :param db: the DB to which the user is going to log in
    :param username: --
    :param password: --
    :return: an instance of the User model
    """
    db_user = db.get(username, False)
    if not db_user or db_user['password'] != password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password",
                            headers={"WWW-Authenticate": "Bearer"},
                            )
    return db_user['login']


def create_jwt_token(username: str, expires_delta: Optional[timedelta] = None) -> Token:
    if not expires_delta:
        expires_delta = ACCESS_TOKEN_EXPIRE_MINUTES
    expires = datetime.utcnow() + timedelta(minutes=expires_delta)
    to_encode = {"sub": username,
                 "exp": expires
                 }
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return Token(access_token=encoded_jwt, token_type="Bearer")


@app.post("/get-token", response_model=Token)
def login_for_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """

    this is supposed to be called the first time for the user to log in
    future calls to the secured endpoint wont call this function unless the  token has expired

    - authenticate the user by checking if username/password exists in DB
    - create a new jwt token
    :param form_data: dict {'username': --, 'password': --}
    :return: a jwt access token {'access_token': --, 'token_type': 'Bearer'}
            throws exception if credentials not valid
    """
    login = authenticate_user(USERS_DB, form_data.username, form_data.password)
    token = create_jwt_token(login)
    return token
