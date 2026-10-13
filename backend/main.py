from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import settings
from backend.database.connection import engine, Base, SessionLocal
import backend.models  # Ensures all SQLAlchemy models are registered
from backend.database.migrations import run_migrations
from backend.api import (
    auth, documents, search, tags, duplicates,
    suggestions, folders, categories, trash, notifications, explorer,
    shares, groups, access_lock, support
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables (new ones), then run safe column migrations
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
    # INTELLIDOCS_STARTUP_SEARCH_INDEX_RECOVERY_V1: restore in-memory search structures after every process start.
    from backend.api.deps import search_service_instance
    db = SessionLocal()
    try:
        rebuilt_count = search_service_instance.rebuild_index(db)
        import logging
        logging.getLogger(__name__).info(
            "Rebuilt keyword/autocomplete indexes for %d document(s)", rebuilt_count
        )
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Search-index recovery failed during startup")
        raise
    finally:
        db.close()
    # INTELLIDOCS_STARTUP_VECTOR_INDEX_RECOVERY_V1: rebuild semantic vectors and FAISS-to-document-ID mappings from persisted text.
    import logging
    logger = logging.getLogger(__name__)
    vector_store = None
    try:
        from backend.api.deps import embedding_engine_instance, vector_store_instance
        from backend.core.vector_index_recovery import rebuild_vector_index
        vector_store = vector_store_instance
        if settings.ENABLE_SEMANTIC_SEARCH and embedding_engine_instance.is_available() and vector_store.is_available():
            vector_db = SessionLocal()
            try:
                semantic_count = rebuild_vector_index(
                    vector_db, embedding_engine_instance, vector_store, batch_size=32
                )
            finally:
                vector_db.close()
            logger.info("Rebuilt semantic vector index for %d document(s)", semantic_count)
        else:
            logger.warning(
                "Semantic vector recovery skipped: semantic search or model/FAISS is unavailable"
            )
    except Exception:
        # Keep the app and keyword search available if optional semantic recovery fails.
        if vector_store is not None:
            try:
                vector_store.reset()
            except Exception:
                pass
        logger.exception("Semantic vector recovery failed; continuing without semantic ANN")
    yield

app = FastAPI(
    title="IntelliDocs API",
    description="IntelliDocs Smart Document Processing API V4",
    version="4.0.0",
    lifespan=lifespan
)

origins = [origin.strip() for origin in settings.ALLOWED_ORIGINS.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(auth.router)
app.include_router(documents.router)
app.include_router(shares.router)
app.include_router(groups.router)
app.include_router(access_lock.router)
app.include_router(search.router)
app.include_router(tags.router)
app.include_router(duplicates.router)
app.include_router(suggestions.router)
app.include_router(folders.router)
app.include_router(categories.router)
app.include_router(trash.router)
app.include_router(notifications.router)
app.include_router(explorer.router)
app.include_router(support.router)

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "app": "IntelliDocs API",
        "version": "4.0.0"
    }

from fastapi.staticfiles import StaticFiles
import os

frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)

