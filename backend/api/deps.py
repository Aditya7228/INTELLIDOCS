from datetime import datetime, timezone
from typing import Generator
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.user_repo import UserRepository
from backend.models.user import User
from backend.models.session_token import Session as SessionModel
from backend.security.jwt_handler import JWTHandler
from backend.algorithms.lsh import MinHashLSH
from backend.algorithms.inverted_index import InvertedIndex
from backend.algorithms.trie import Trie
from backend.algorithms.graph import DocumentGraph
from backend.ai.embedding_engine import EmbeddingEngine
from backend.ai.vector_store import VectorStore
from backend.core.search_service import SearchService
from backend.core.duplicate_service import DuplicateService
from backend.core.document_service import DocumentService
from backend.security.path_guard import PathGuard

security = HTTPBearer(auto_error=False)

# Global singleton instances for stateful DSA & AI models across server lifespan
lsh_instance = MinHashLSH()
inverted_index_instance = InvertedIndex()
trie_instance = Trie()
document_graph_instance = DocumentGraph()
embedding_engine_instance = EmbeddingEngine()
vector_store_instance = VectorStore()
path_guard = PathGuard()

search_service_instance = SearchService(
    inverted_index_instance,
    trie_instance,
    document_graph_instance,
    embedding_engine_instance,
    vector_store_instance
)

duplicate_service_instance = DuplicateService(
    lsh_instance,
    embedding_engine_instance,
    vector_store_instance
)

document_service_instance = DocumentService(
    search_service_instance,
    duplicate_service_instance,
    embedding_engine_instance,
    vector_store_instance
)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = JWTHandler.decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user_id = int(payload.get("sub"))
    jti = payload.get("jti")

    if jti:
        session = db.query(SessionModel).filter(SessionModel.jti == jti).first()
        if session:
            if session.revoked == 1:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session has been revoked",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            if session.expires_at:
                try:
                    exp_dt = datetime.fromisoformat(session.expires_at)
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) >= exp_dt:
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Session expired",
                            headers={"WWW-Authenticate": "Bearer"}
                        )
                except ValueError:
                    pass

    user_repo = UserRepository(db)
    user = user_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer active",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return user


def require_role(required_role: str):
    def role_checker(user: User = Depends(get_current_user)):
        if user.role != required_role and user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permission to perform this action"
            )
        return user
    return role_checker
