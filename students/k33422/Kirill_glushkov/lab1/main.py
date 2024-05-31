from typing import List
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
import uvicorn
from datetime import datetime, timedelta
from app.database import SessionLocal,  init_db, BudgetDB, ExpenseDB, UserDB, IncomeDB
from app.models import Income, Expense, Budget, User
from bcrypt import hashpw, gensalt
import jwt
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(swagger_ui_parameters={"syntaxHighlight.theme": "obsidian"})
router = APIRouter()

class Token(BaseModel):
    access_token: str
    token_type: str
def generate_token(username: str) -> str:
    expiration = datetime.now() + timedelta(minutes=30)
    token_data = {
        "sub": username,
        "exp": expiration
    }
    token = jwt.encode(token_data, "secret", algorithm="HS256")
    return token
@app.on_event("startup")
def startup():
    init_db()

@app.get("/")
async def root():
    return {"message": "Hello World"}


@router.get("/users")
async def get_users() -> List[User]:
    with SessionLocal() as db:
        users = db.query(UserDB).all()
        return users
    
@router.get("/users/{user_id}", response_model=User)
async def get_user(user_id: int):
    with SessionLocal() as db:
        user = db.query(UserDB).filter(UserDB.id == user_id).first()
        print(user, 'usr')
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    

@router.delete("/users/{user_id}")
async def delete_user(user_id: int):
    with SessionLocal() as db:
        db_user = db.query(UserDB).get(user_id)
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        db.delete(db_user)
        db.commit()
        return JSONResponse(status_code=204, content="User deleted")

@router.post("/users", response_model=User)
async def create_user(user: User):
    with SessionLocal() as db:
        salt = gensalt()
        user_data = user.model_dump(exclude={'password'})
        db_user = UserDB(**user_data, password=str(hashpw(user.password.encode(), salt)))
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

        return db_user
    
def verify_pwd(password: str, hashed_password: str) -> bool:
    salt = gensalt()
    return str(hashpw(password.encode(), salt)) == hashed_password


@router.post("/users/login")
async def login(user: User):
    with SessionLocal() as db:
        db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        if not verify_pwd(user.password, db_user.password):
            raise HTTPException(status_code=401, detail="Invalid password")
        token = generate_token(db_user.username)
        return {"access_token": token, "token_type": "bearer"}
    

@router.put("/users/{user_id}", response_model=User)
async def update_user(user_id: int, user: User):
    with SessionLocal() as db:
        db_user = db.query(UserDB).filter(UserDB.id == user_id).first()
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        for var, value in vars(user).items():
            setattr(db_user, var, value)
        db.commit()
        db.refresh(db_user)
        return db_user



app.include_router(router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=8000, reload=True, workers=1, log_level='debug', access_log=True)