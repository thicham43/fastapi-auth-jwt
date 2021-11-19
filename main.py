from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from base import User, get_current_user, authenticate_user,\
                 Token, create_token, inactive_user_exception

app = FastAPI(title="OAuth2 and JWT demo")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="get-token")


def get_active_user(token: str = Depends(oauth2_scheme)) -> User:
    user = get_current_user(token)
    if not user.active:
        raise inactive_user_exception
    return user


@app.get("/my-favorites")
def get_favorite_books(current_user: User = Depends(get_active_user)):
    """
    this is supposed to be a secured endpoint. only logged in and active users are allowed
    :param current_user: the current user who's trying to access the endpoint
    :return: list of favorite books, else throw an exception (handled by the dependency)
    """
    return [f"Email: {current_user.email}", "fav_book_1", "fav_book_2"]


@app.post("/get-token", response_model=Token)
def login_for_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    this is supposed to be called the first time for the user to log in.
    future calls to a secured endpoint wont call this function unless the token has expired
    - authenticate the user by checking if login/password exists in DB
    - create a new jwt token
    :param form_data: request form object with attrs 'username' and 'password'
    :return: a jwt access token {'access_token': --, 'token_type': 'Bearer'}
    """
    login = authenticate_user(form_data.username, form_data.password)
    token = create_token(login)
    return token
