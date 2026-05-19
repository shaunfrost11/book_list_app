from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv

import requests
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta, timezone

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret_key")
ALGORITHM = "HS256"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print("Database connection failed:", e)
        return None

# --- AUTHENTICATION HELPERS ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    # Token expires in 7 days
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- PYDANTIC MODELS ---
class UserAuth(BaseModel):
    email: str
    password: str

from pydantic import BaseModel
class BookCreate(BaseModel):
    title: str
    author: str
    publish_year: str
    isbn: str = None
    cover_url: str = None

class StatusUpdate(BaseModel):
    status: str

# --- ROUTES ---

@app.get("/")
def health_check():
    return {"status": "Book Tracker API is running!"}

@app.post("/register")
def register_user(user: UserAuth):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    cursor = conn.cursor()
    try:
        # 1. Check if user already exists
        cursor.execute("SELECT user_id FROM users WHERE email = %s;", (user.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # 2. Hash the password and save
        hashed_password = get_password_hash(user.password)
        cursor.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING user_id;",
            (user.email, hashed_password)
        )
        new_user_id = cursor.fetchone()[0]
        conn.commit()
        
        return {"message": "User created successfully", "user_id": new_user_id}
        
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()

@app.post("/login")
def login_user(user: UserAuth):
    print(f"🔥 DEBUG: Reached /login endpoint for email: {user.email}") # Track 1
    
    conn = get_db_connection()
    if not conn:
        print("🔥 DEBUG: get_db_connection() returned None!") # Track 2
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    print("🔥 DEBUG: Database connected successfully!") # Track 3
    
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute("SELECT user_id, password_hash FROM users WHERE email = %s;", (user.email,))
        db_user = cursor.fetchone()
        
        print(f"🔥 DEBUG: Database lookup complete. User found? {bool(db_user)}") # Track 4
        
        if not db_user or not verify_password(user.password, db_user['password_hash']):
            print("🔥 DEBUG: Password verification failed!") # Track 5
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        access_token = create_access_token(data={"sub": str(db_user['user_id'])})
        print("🔥 DEBUG: Login fully successful, returning token!") # Track 6
        
        return {"access_token": access_token, "token_type": "bearer"}
        
    except Exception as e:
        print(f"🔥 DEBUG: FATAL CRASH inside try block: {str(e)}") # Track 7
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()
        
@app.get("/search")
def search_books(q: str):
    url = f"https://openlibrary.org/search.json?title={q}&limit=10"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        clean_results = []
        
        for doc in data.get("docs", []):
            # 1. Try to get the Cover ID first (most reliable for images)
            cover_id = doc.get("cover_i")
            
            # 2. Safely get the ISBN
            isbn_list = doc.get("isbn", [])
            primary_isbn = isbn_list[0] if isbn_list else None
            
            # 3. Assemble the cover URL
            # Priority: 1. Cover ID -> 2. ISBN -> 3. None
            cover_url = None
            if cover_id:
                cover_url = f"https://covers.openlibrary.org/b/id/{cover_id}-M.jpg"
            elif primary_isbn:
                cover_url = f"https://covers.openlibrary.org/b/isbn/{primary_isbn}-M.jpg"
                
            author_list = doc.get("author_name", [])
            primary_author = author_list[0] if author_list else "Unknown Author"
            
            clean_book = {
                "title": doc.get("title", "Unknown Title"),
                "author": primary_author,
                "publish_year": str(doc.get("first_publish_year", "N/A")),
                "isbn": primary_isbn,
                "cover_url": cover_url
            }
            
            clean_results.append(clean_book)
            
        return {"results": clean_results}
        
    except Exception as e:
        print(f"Search API Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch books")

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Use the same SECRET_KEY you used for login!
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        return {"id": user_id}
    except JWTError:
        raise credentials_exception

@app.post("/books")
def save_book(book: BookCreate, current_user: dict = Depends(get_current_user)):

    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    # --- THE DATA SCRUBBER ---
    # Ensure nothing hits the database as NULL or "undefined"
    safe_publish_year = book.publish_year if book.publish_year and book.publish_year not in ["undefined", "null"] else "Unknown Year"
    safe_isbn = book.isbn if book.isbn and book.isbn not in ["undefined", "null"] else "No ISBN"
    safe_author = book.author if book.author else "Unknown Author"
    
    cursor = conn.cursor()
    query = """
    INSERT INTO books (user_id, title, author, publish_year, isbn, cover_url)
    VALUES (%s, %s, %s, %s, %s, %s);
    """
    try:
        cursor.execute(query, (
            current_user["id"],
            book.title,
            safe_author,
            safe_publish_year,
            safe_isbn,
            book.cover_url
        ))
        conn.commit()
        return {"message": "Book saved successfully!"}
    except Exception as e:
        conn.rollback()
        print(f"Database Error: {e}")
        raise HTTPException(status_code=500, detail="Could not save book")
    finally:
        cursor.close()
        conn.close()

@app.get("/books")
def get_my_books(current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Added 'id' and 'status' to the SELECT query!
        cursor.execute(
            "SELECT id, title, author, publish_year, isbn, cover_url, status FROM books WHERE user_id = %s ORDER BY created_at DESC;",
            (current_user["id"],)
        )
        saved_books = cursor.fetchall()
        return {"books": saved_books}
    except Exception as e:
        print(f"Database Error: {e}")
        raise HTTPException(status_code=500, detail="Could not fetch books")
    finally:
        cursor.close()
        conn.close()

@app.put("/books/{book_id}/status")
def update_book_status(book_id: int, status_data: StatusUpdate, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    cursor = conn.cursor()
    try:
        # We check user_id too, so a hacker can't change someone else's book status!
        cursor.execute(
            "UPDATE books SET status = %s WHERE id = %s AND user_id = %s;",
            (status_data.status, book_id, current_user["id"])
        )
        conn.commit()
        return {"message": "Status updated"}
    except Exception as e:
        conn.rollback()
        print(f"Database Error: {e}")
        raise HTTPException(status_code=500, detail="Could not update status")
    finally:
        cursor.close()
        conn.close()

@app.delete("/books/{book_id}")
def delete_book(book_id: int, current_user: dict = Depends(get_current_user)):
    """
    Deletes a specific book from the user's library.
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    cursor = conn.cursor()
    try:
        # We include user_id in the WHERE clause so users can ONLY delete their own books
        cursor.execute(
            "DELETE FROM books WHERE id = %s AND user_id = %s RETURNING id;",
            (book_id, current_user["id"])
        )
        
        # If fetchone() is None, it means the book didn't exist or didn't belong to this user
        deleted_book = cursor.fetchone()
        if not deleted_book:
            raise HTTPException(status_code=404, detail="Book not found or unauthorized")
            
        conn.commit()
        return {"message": "Book deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        print(f"Database Error: {e}")
        raise HTTPException(status_code=500, detail="Could not delete book")
    finally:
        cursor.close()
        conn.close()