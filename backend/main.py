from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path
import jwt
from datetime import datetime, timedelta, timezone
import hashlib, secrets

from database import SessionLocal, User, Post, Comment

SECRET = "blog-secret-key-change-in-production"
ALGO = "HS256"

app = FastAPI(title="Blog Platform")

def hash_pw(password: str) -> str:
    salt = secrets.token_hex(16)
    return salt + ":" + hashlib.sha256((salt + password).encode()).hexdigest()

def verify_pw(password: str, hashed: str) -> bool:
    salt, h = hashed.split(":")
    return h == hashlib.sha256((salt + password).encode()).hexdigest()
auth_scheme = HTTPBearer()

static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(token: str = Depends(auth_scheme), db: Session = Depends(get_db)):
    try:
        data = jwt.decode(token.credentials, SECRET, algorithms=[ALGO])
        user = db.query(User).filter(User.id == data["user_id"]).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- Schemas ---
class RegisterReq(BaseModel):
    username: str
    password: str

class LoginReq(BaseModel):
    username: str
    password: str

class TokenRes(BaseModel):
    token: str
    username: str

class PostReq(BaseModel):
    title: str
    content: str

class PostRes(BaseModel):
    id: int
    title: str
    content: str
    created_at: str
    author: str
    comment_count: int

class CommentReq(BaseModel):
    content: str

class CommentRes(BaseModel):
    id: int
    content: str
    created_at: str
    author: str

class UserRes(BaseModel):
    id: int
    username: str

# --- Auth Routes ---
@app.post("/api/register", response_model=TokenRes)
def register(req: RegisterReq, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username taken")
    user = User(username=req.username, password=hash_pw(req.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    token = jwt.encode({"user_id": user.id, "exp": datetime.now(timezone.utc) + timedelta(days=7)}, SECRET, algorithm=ALGO)
    return TokenRes(token=token, username=user.username)

@app.post("/api/login", response_model=TokenRes)
def login(req: LoginReq, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_pw(req.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = jwt.encode({"user_id": user.id, "exp": datetime.now(timezone.utc) + timedelta(days=7)}, SECRET, algorithm=ALGO)
    return TokenRes(token=token, username=user.username)

@app.get("/api/me", response_model=UserRes)
def me(user: User = Depends(get_user)):
    return user

# --- Post Routes ---
@app.get("/api/posts", response_model=List[PostRes])
def list_posts(db: Session = Depends(get_db)):
    posts = db.query(Post).order_by(Post.created_at.desc()).all()
    return [
        PostRes(
            id=p.id, title=p.title, content=p.content,
            created_at=p.created_at.isoformat(),
            author=p.author.username,
            comment_count=len(p.comments)
        ) for p in posts
    ]

@app.get("/api/posts/{post_id}", response_model=PostRes)
def get_post(post_id: int, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return PostRes(
        id=post.id, title=post.title, content=post.content,
        created_at=post.created_at.isoformat(),
        author=post.author.username,
        comment_count=len(post.comments)
    )

@app.post("/api/posts", response_model=PostRes, status_code=201)
def create_post(req: PostReq, user: User = Depends(get_user), db: Session = Depends(get_db)):
    post = Post(title=req.title, content=req.content, user_id=user.id)
    db.add(post)
    db.commit()
    db.refresh(post)
    return PostRes(
        id=post.id, title=post.title, content=post.content,
        created_at=post.created_at.isoformat(),
        author=post.author.username, comment_count=0
    )

@app.put("/api/posts/{post_id}", response_model=PostRes)
def update_post(post_id: int, req: PostReq, user: User = Depends(get_user), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not your post")
    post.title = req.title
    post.content = req.content
    db.commit()
    db.refresh(post)
    return PostRes(
        id=post.id, title=post.title, content=post.content,
        created_at=post.created_at.isoformat(),
        author=post.author.username, comment_count=len(post.comments)
    )

@app.delete("/api/posts/{post_id}", status_code=204)
def delete_post(post_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not your post")
    db.delete(post)
    db.commit()

# --- Comment Routes ---
@app.get("/api/posts/{post_id}/comments", response_model=List[CommentRes])
def list_comments(post_id: int, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    comments = db.query(Comment).filter(Comment.post_id == post_id).order_by(Comment.created_at.asc()).all()
    return [
        CommentRes(id=c.id, content=c.content, created_at=c.created_at.isoformat(), author=c.author.username)
        for c in comments
    ]

@app.post("/api/posts/{post_id}/comments", response_model=CommentRes, status_code=201)
def create_comment(post_id: int, req: CommentReq, user: User = Depends(get_user), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    comment = Comment(content=req.content, user_id=user.id, post_id=post_id)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return CommentRes(id=comment.id, content=comment.content, created_at=comment.created_at.isoformat(), author=comment.author.username)

@app.delete("/api/comments/{comment_id}", status_code=204)
def delete_comment(comment_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    if comment.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not your comment")
    db.delete(comment)
    db.commit()

# --- Frontend ---
@app.get("/", response_class=HTMLResponse)
def serve():
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
