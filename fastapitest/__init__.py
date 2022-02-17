from http.client import HTTPException
from urllib.request import Request
from fastapi import FastAPI, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from pydantic import BaseModel

def create_app():
    

    from typing import Optional

    app = FastAPI()

    class User(BaseModel):
        username: str
        password: str

    class Settings(BaseModel):
        authjwt_secret_key: str = "secret"
        authjwt_token_location: set = {"cookies"}
        authjwt_token_location: set = {"cookies"}

    @AuthJWT.load_config
    def get_config():
        return Settings()

    @app.exception_handler(AuthJWTException)
    def authjwt_exception_handler(request: Request, exc: AuthJWTException):
        return JSONResponse(
            status_code=exc.status_code,
            content={'detail': exc.message}
        )

    @app.post('/login')
    def login(user: User, Authorize: AuthJWT = Depends()):
        if user.username != 'test' or user.password != 'test':
            raise HTTPException(status_code=401, detail="Bad credentials")

        access_token = Authorize.create_access_token(subject=user.username)
        refresh_token = Authorize.create_refresh_token(subject=user.username)

        Authorize.set_access_cookies(access_token)
        Authorize.set_refresh_cookies(refresh_token)
        
        return {'msg':'success'}

    @app.get("/")
    def read_root():
        return {"Hello": "World"}


    @app.get("/items/{item_id}")
    def read_item(item_id: int, q: Optional[str] = None):
        return {"item_id": item_id, "q": q}

    return app

