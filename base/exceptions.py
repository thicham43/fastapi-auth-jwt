from fastapi import HTTPException, status

login_pswd_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                     detail="Incorrect login or password",
                                     headers={"WWW-Authenticate": "Bearer"},
                                     )
credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                      detail="Could not validate credentials",
                                      headers={"WWW-Authenticate": "Bearer"},
                                      )
inactive_user_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                        detail="Inactive user account",
                                        headers={"WWW-Authenticate": "Bearer"},
                                        )
