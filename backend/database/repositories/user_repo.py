from typing import Optional, List
from sqlalchemy.orm import Session
from backend.models.user import User

class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_user(self, username: str, email: str, password_hash: str, role: str = "user") -> User:
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            role=role
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def get_by_id(self, user_id: int) -> Optional[User]:
        return self.db.query(User).filter(User.id == user_id, User.is_active == 1).first()

    def get_by_username(self, username: str) -> Optional[User]:
        return self.db.query(User).filter(User.username == username, User.is_active == 1).first()

    def get_by_email(self, email: str) -> Optional[User]:
        return self.db.query(User).filter(User.email == email, User.is_active == 1).first()

    def search_users(self, query: str, exclude_user_id: int, limit: int = 10) -> List[User]:
        if not query or len(query.strip()) < 1:
            return []
        term = f"%{query.strip().lower()}%"
        return self.db.query(User).filter(
            User.is_active == 1,
            User.id != exclude_user_id,
            (User.username.ilike(term) | User.email.ilike(term))
        ).limit(limit).all()

    def update_last_login(self, user_id: int, timestamp_iso: str):
        user = self.get_by_id(user_id)
        if user:
            user.last_login_at = timestamp_iso
            self.db.commit()

    def update_password(self, user_id: int, new_password_hash: str):
        user = self.get_by_id(user_id)
        if user:
            user.password_hash = new_password_hash
            self.db.commit()
