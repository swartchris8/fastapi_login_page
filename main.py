from fastapi import FastAPI, Depends, status, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from fastapi_login import LoginManager  # Loginmanager Class
from fastapi_login.exceptions import InvalidCredentialsException  # Exception class
from fastapi.staticfiles import StaticFiles

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

SECRET = "secret-key"
# To obtain a suitable secret key you can run | import os; print(os.urandom(24).hex())

templates = Jinja2Templates(directory="templates")

class NotAuthenticatedException(Exception):
    pass

manager = LoginManager(SECRET, token_url="/auth/login", use_cookie=True, custom_exception=NotAuthenticatedException)
manager.cookie_name = "some-name"
manager.not_authenticated_exception = NotAuthenticatedException

# these two argument are mandatory
def exc_handler(request, exc):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "message": f"You are not authorised for {request.url} please login"}
    )

app.add_exception_handler(NotAuthenticatedException, exc_handler)

DB = {"username": {"password": "qwertyuiop"}}  # unhashed


@manager.user_loader
def load_user(username: str):
    user = DB.get(username)
    return user


@app.post("/auth/login")
def login(data: OAuth2PasswordRequestForm = Depends()):
    username = data.username
    password = data.password
    user = load_user(username)
    if not user:
        raise InvalidCredentialsException
    elif password != user['password']:
        raise InvalidCredentialsException
    access_token = manager.create_access_token(
        data={"sub": username}
    )
    resp = RedirectResponse(url="/private", status_code=status.HTTP_302_FOUND)
    manager.set_cookie(resp, access_token)
    return resp


@app.get("/private")
def getPrivateendpoint(_=Depends(manager)):
    return "You are an authentciated user"


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/logout", response_class=HTMLResponse)
def logout_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})