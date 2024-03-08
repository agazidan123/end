from fastapi import FastAPI, HTTPException, status, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, MetaData, select, Table, Column, Integer, String, ForeignKey
from passlib.context import CryptContext
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from starlette.requests import Request
from typing import List, Optional
from datetime import timedelta, timezone, datetime
import jwt
import random
import asyncio
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from fastapi_session import Session

load_dotenv()

app = FastAPI()

SECRET_KEY = "d38b291ccebc18af95d4df97a0a98f9bb9eea3c820e771096fa1c5e3a58f3d53"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
from starlette.middleware.sessions import SessionMiddleware

app.add_middleware(SessionMiddleware, secret_key="8c87d814d4be0ddc08364247da359a61941957e84f62f3cd0e87eb5d853a4144")


DATABASE_URL = r"mssql+pyodbc://admin:12tourism#app34@tourism.cnqy0qogeve8.us-east-1.rds.amazonaws.com/TouristaDB?driver=ODBC+Driver+17+for+SQL+Server&Integrated_Security=True"
engine = create_engine(DATABASE_URL)
metadata = MetaData()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

users = Table(
    "users",
    metadata,
    Column("user_id", Integer, primary_key=True, index=True),
    Column("first_name", String(length=255)),
    Column("last_name", String(length=255)),
    Column("user_email", String),
    Column("user_password", String),
    Column("user_location", String),
)

metadata.create_all(bind=engine)


def query_database(country: str, governorate: str, category: str, name: str) -> List[str]:
    return []


class UserRegistration(BaseModel):
    first_name: str
    last_name: str
    user_password: str
    user_email: EmailStr
    user_location: Optional[str] = None

class UserLogin(BaseModel):
    user_email: EmailStr
    user_password: str


class UserUpdate(BaseModel):
    first_name: str
    last_name: str
    user_location: str

oauth = OAuth()
oauth.register(
    name='google',
    client_id='661608121084-ujv3v7ptoc1dtr1mp7hegarnrtfsceas.apps.googleusercontent.com',
    client_secret='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',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params={'scope': 'openid email profile'},
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    userinfo_url='https://openidconnect.googleapis.com/v1/userinfo',
    userinfo_params=None,
    client_kwargs={
        'token_endpoint_auth_method': 'client_secret_post',
        'prompt': 'consent',  # Adding prompt parameter
        'response_type': 'code id_token',  # Adding response_type parameter
        'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs'  # Adding jwks_uri parameter
    }
)



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return password_context.hash(password)


def verify_user_credentials(user_email: str, user_password: str):
    conn = engine.connect()
    query = select(users.c.user_email, users.c.user_password).where(users.c.user_email == user_email)
    result = conn.execute(query).fetchone()

    if result and password_context.verify(user_password, result[1]):
        return True
    return False


def register_user(user: UserRegistration):
    conn = engine.connect()
    conn.execute(users.insert().values(
        first_name=user.first_name,
        last_name=user.last_name,
        user_password=hash_password(user.user_password),
        user_email=user.user_email,
        user_location=user.user_location,
    ))
    conn.commit()


def delete_user(user_email: str):
    conn = engine.connect()
    conn.execute(users.delete().where(users.c.user_email == user_email))
    conn.commit()


def update_user(user_email: str, updated_user: UserUpdate):
    conn = engine.connect()
    conn.execute(users.update().where(users.c.user_email == user_email).values(
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        user_location=updated_user.user_location,
    ))
    conn.commit()


UTC = timezone.utc
def create_access_token(data: dict):
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



def get_user_from_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            return None
        return user_email
    except jwt.JWTError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return user_email
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")



@app.post("/register")
async def register(user: UserRegistration):
    conn = engine.connect()
    query = select(users.c.user_email).where(users.c.user_email == user.user_email)
    result = conn.execute(query).fetchone()
    conn.close()

    if result:
        raise HTTPException(status_code=400, detail="User with this email already registered")

    register_user(user)
    return {"message": "Registration successful"}

@app.post("/login")
async def login(user: UserLogin):
    user_email = user.user_email
    user_password = user.user_password

    if not verify_user_credentials(user_email, user_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user_email})
    return {"access_token": access_token, "token_type": "bearer", "message": "Login successful"}


@app.delete("/delete")
async def delete(current_user: str = Depends(get_current_user)):
    delete_user(current_user)
    return {"message": "User deleted successfully"}


@app.put("/update")
async def update(updated_user: UserUpdate, current_user: str = Depends(get_current_user)):
    update_user(current_user, updated_user)
    return {"message": "User updated successfully"}


@app.put("/reset_password")
async def reset_password(user_identifier: str, new_password: str, current_user: str = Depends(get_current_user)):
    conn = engine.connect()
    hashed_password = hash_password(new_password)
    if '@' in user_identifier:
        conn.execute(users.update().where(users.c.user_email == user_identifier).values(
            user_password=hashed_password
        ))
    else:
        conn.execute(users.update().where(users.c.user_id == int(user_identifier)).values(
            user_password=hashed_password
        ))
    conn.commit()
    return {"message": "Password reset successful"}

recent_searches = []


@app.post("/search")
async def search(country: str, governorate: str, category: str, name: str):
    # Your existing code...
    search_results = query_database(country, governorate, category, name)

    recent_searches.append((country, governorate, category, name))

    if len(recent_searches) > 10:
        recent_searches.pop(0)

    return {"results": search_results}


@app.put("/change_password")
async def change_password(current_password: str, new_password: str, current_user: str = Depends(get_current_user)):
    conn = engine.connect()
    query = select(users.c.user_password).where(users.c.user_email == current_user)
    result = conn.execute(query).fetchone()
    conn.close()

    if result:
        current_hashed_password = result[0]
        if password_context.verify(current_password, current_hashed_password):
            hashed_new_password = hash_password(new_password)
            conn = engine.connect()
            conn.execute(users.update().where(users.c.user_email == current_user).values(
                user_password=hashed_new_password
            ))
            conn.close()
            return {"message": "Password changed successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid current password"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


import secrets
@app.get("/login_google")
async def login_google(request: Request):
    state = secrets.token_urlsafe(16)
    request.session['state'] = state
    redirect_uri = request.url_for('google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri, state=state)


@app.get("/google_callback")
async def google_callback(request: Request):
    try:
        state = request.session.get('state')
        if state is None:
            raise HTTPException(status_code=400, detail="State parameter missing in session")
        token = await oauth.google.authorize_access_token(request)
        user_info = await oauth.google.parse_id_token(request, token)

        # Check if the state parameter in the callback matches the one in the session
        if 'state' not in token or token['state'] != state:
            raise HTTPException(status_code=400, detail="State parameter mismatch")

        return {"token": token, "user_info": user_info}
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Google OAuth callback error: {e}")
        raise HTTPException(status_code=400, detail="Google OAuth callback error")


@app.get("/recent_searches")
async def get_recent_searches(current_user: str = Depends(get_current_user)):
    return {"recent_searches": recent_searches}


items_of_interest = ["restaurants", "hotels", "tours", "archaeological tourism", "for fun", "museum",
                     "water places", "games", "religious tourism", "malls", "parks", "natural views"]
@app.get("/may liked it")
async def get_recommended_items(current_user: str = Depends(get_current_user)):
    # Your existing code...
    recommended_items = random.sample(items_of_interest, min(3, len(items_of_interest)))
    return {"user_id": current_user, "recommended_items": recommended_items}
@app.post("/logout")
async def logout(current_user: str = Depends(get_current_user)):
    """
ليه ياعم تخرج ما انت منورنا والله!!!!!
    """
    return {"message": "Logout successful"}

class Notification(BaseModel):
    user_email: str
    message: str

user_notifications = {}

def send_notification(notification: Notification):
    print(f"Sending notification to user {notification.user_email}: {notification.message}")
    if notification.user_email not in user_notifications:
        user_notifications[notification.user_email] = []
    user_notifications[notification.user_email].append(notification.message)

async def schedule_notifications():
    while True:

        await asyncio.sleep(24 * 3600)
        for user_email, message in user_notifications.items():
            notification = Notification(user_email=user_email, message=message)
            send_notification(notification)

@app.get("/send_notification")
async def send_notification_endpoint(user_email: str, background_tasks: BackgroundTasks):
    default_message = "Reminder: Don't forget to use our app!"
    notification = Notification(user_email=user_email, message=default_message)
    background_tasks.add_task(send_notification, notification)
    return {"detail": "Notification scheduled successfully"}

class Favorite(Base):
    __tablename__ = "favorites"

    fav_id = Column(Integer, primary_key=True, index=True)
    type = Column(String(10))
    name = Column(String(25))
    location = Column(String(25))


class UserFavorite(Base):
    __tablename__ = "user_fav"

    user_id = Column(Integer, ForeignKey('users.user_id'), primary_key=True, index=True)
    fav_id = Column(Integer, ForeignKey('favorites.fav_id'), primary_key=True, index=True)

class FavoriteCreate(BaseModel):
    type: str
    name: str
    location: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
@app.post("/favorites/")
async def create_favorite(favorite: FavoriteCreate, current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    # Your existing code...
    db_favorite = Favorite(**favorite.dict())
    db.add(db_favorite)
    db.commit()
    db.refresh(db_favorite)

    db_user_favorite = UserFavorite(user_id=favorite.user_id, fav_id=db_favorite.fav_id)
    print(db_user_favorite)
    db.add(db_user_favorite)
    db.commit()
    return db_favorite
class Plan(Base):
    __tablename__ = "plans"

    plan_id = Column(Integer, primary_key=True, index=True)
    destination = Column(String)
    duration = Column(Integer)
    budget = Column(Integer)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/plan_trip")
async def plan_trip(
    destination: str,
    duration: int,
    budget: int,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    selected_plans = db.query(Plan).filter(Plan.destination == destination, Plan.duration == duration, Plan.budget <= budget).all()

    return {
        "destination": destination,
        "duration": duration,
        "budget": budget,
        "selected_plans": [plan.id for plan in selected_plans]
    }

@app.get("/plan_history")
async def plan_history(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    # Your existing code...
    plans = db.query(Plan).all()
    return plans
# -------------------------------------------------------------------------
class SurveyResponse(BaseModel):
    user_id: int
    category: str

# SQLAlchemy models
class Survey(Base):
    __tablename__ = "surveys"
    survey_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)

class Option(Base):
    __tablename__ = "options"
    id = Column(Integer, primary_key=True, index=True)
    category = Column(String, index=True)
    survey_id = Column(Integer, ForeignKey("surveys.survey_id"))

@app.post("/survey/")
async def survey(survey_response: SurveyResponse, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        # Create survey entry
        survey = Survey(user_id=survey_response.user_id)
        db.add(survey)
        db.commit()
        db.refresh(survey)

        # Create option entry
        option = Option(category=survey_response.category, survey_id=survey.survey_id)
        db.add(option)
        db.commit()
        db.refresh(option)

        return {"message": "Survey submitted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    finally:
        db.close()


@app.get("/protected")
async def protected_endpoint(current_user: str = Depends(get_current_user)):
    return {"message": f"Hello, {current_user}. You are authenticated."}
@app.get("/unprotected")
async def unprotected_endpoint():
    return {"message": "This endpoint is accessible without authentication."}
