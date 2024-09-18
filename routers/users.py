from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse
from starlette import status
from starlette.responses import RedirectResponse
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import models
from database import SessionLocal, engine
from pydantic import BaseModel
from routers.auth import get_current_user, verify_password, get_password_hash
from fastapi.templating import Jinja2Templates

import sys
sys.path.append("..")

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}}
)


models.Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory="templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


class UserVerification(BaseModel):
    username: str
    password: str
    new_password: str


# Render the change password form
@router.get("/change-password", response_class=HTMLResponse)
async def change_password_form(request: Request):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse("change-password.html", {"request": request, "user": user})


# Handle the change password form submission
@router.post("/change-password", response_class=HTMLResponse)
async def change_password(request: Request, username: str = Form(...), current_password: str = Form(...),
                          new_password: str = Form(...), db: Session = Depends(get_db)):

    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    # Fetch the user from the database
    user_data = db.query(models.Users).filter(models.Users.username == username).first()

    msg = "Invalid username or password"

    if user_data is not None:
        # If user doesn't exist
        if username == user_data.username and verify_password(current_password, user_data.hashed_password):
            user_data.hashed_password = get_password_hash(new_password)
            db.add(user_data)
            db.commit()
            msg = 'Password updated'

        return templates.TemplateResponse('change-password.html', {"request": request, "user": user, "msg": msg})


