from http.client import HTTPException

from urllib import response
from urllib.request import Request

from typing import Optional

from fastapi import FastAPI, Depends, Request, Cookie
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
        authjwt_cookie_csrf_protect: bool = False

    @app.middleware("http")
    async def preproc(request: Request, call_next, cookie: Optional[str] = Cookie(None)):
        print(request.headers['cookie'])
        print(cookie)
        response = await call_next(request)
        return response

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

        access_token = Authorize.create_access_token(subject=user.username, fresh=True)
        refresh_token = Authorize.create_refresh_token(subject=user.username)

        Authorize.set_access_cookies(access_token)
        Authorize.set_refresh_cookies(refresh_token)
        
        return {'msg':'success'}

    @app.post('/refresh')
    def refresh(Authorize: AuthJWT = Depends()):
        Authorize.jwt_refresh_token_required()

        current_user = Authorize.get_jwt_subject()
        new_access_token = Authorize.create_access_token(subject=current_user, fresh=False)
        Authorize.set_access_cookies(new_access_token)

        return {'msg':'refreshed'}

    @app.delete('/logout')
    def logout(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()

        Authorize.unset_jwt_cookies()
        return {'msg' : 'logged out'}
    
    @app.get('/protected_fresh')
    def protected_fresh(Authorize: AuthJWT = Depends()):
        Authorize.fresh_jwt_required()

        return Authorize.get_jwt_subject()

    @app.get("/")
    def read_root():
        return {"Hello": "World"}


    @app.get("/items/{item_id}")
    def read_item(item_id: int, q: Optional[str] = None):
        return {"item_id": item_id, "q": q}

    return app

