from types import SimpleNamespace

from backend.api.duplicates import _fallback_pair_classification


def test_strong_near_duplicate_text_is_actionable_without_candidate_index():
    text_a = (
        "IntelliDocs Smart Document Management System provides offline AI document "
        "classification, hybrid full-text search, multi-level security scanning, "
        "and duplicate detection algorithms across all local workspace repositories."
    )
    text_b = (
        "IntelliDocs Smart Document Management System provides offline AI document "
        "classification, hybrid full-text search, multi-level security scanning, "
        "and duplicate detection algorithms across local workspace repositories."
    )
    a = SimpleNamespace(
        id=1, extracted_text=text_a, sha256_hash="sha-a",
        perceptual_hash=None, has_ocr=0,
    )
    b = SimpleNamespace(
        id=2, extracted_text=text_b, sha256_hash="sha-b",
        perceptual_hash=None, has_ocr=0,
    )

    result = _fallback_pair_classification(a, b)

    assert result is not None
    assert result["relation_type"] == "exact_duplicate"
    assert result["confidence"] >= 0.90
    assert "normalized_content_sim" in result["scores"]


def test_unrelated_text_does_not_create_fallback_alert():
    a = SimpleNamespace(
        id=1, extracted_text="The astronomy club meets on Friday.",
        sha256_hash="sha-a", perceptual_hash=None, has_ocr=0,
    )
    b = SimpleNamespace(
        id=2, extracted_text="The department budget proposal is due Monday.",
        sha256_hash="sha-b", perceptual_hash=None, has_ocr=0,
    )

    assert _fallback_pair_classification(a, b) is None


def test_newest_pair_is_returned_when_older_alerts_exceed_cap(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import backend.models  # register all models before create_all
    from backend.database.connection import Base
    from backend.models.document import DocumentModel
    from backend.models.user import User
    from backend.api import duplicates as duplicates_api

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    LocalSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = LocalSession()
    original_analyze = duplicates_api.duplicate_service_instance.analyze_all_candidates
    try:
        user = User(
            username="duplicate-alert-cap-test",
            email="duplicate-alert-cap-test@example.com",
            password_hash="not-used-in-this-test",
            role="user",
            is_active=1,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        common_text = (
            "Archived duplicate alert seed text. This older document is intentionally "
            "identical so the alert response exceeds its 100-row display cap."
        )
        for index in range(102):
            db.add(DocumentModel(
                uuid=f"old-doc-{index:03d}",
                original_name=f"old-{index:03d}.txt",
                stored_name=f"old-{index:03d}.txt",
                file_path=f"uploads/old-{index:03d}.txt",
                file_type="txt",
                mime_type="text/plain",
                size_bytes=len(common_text),
                sha256_hash="old-seed-hash",
                extracted_text=common_text,
                owner_id=user.id,
                processing_status="done",
            ))
        text_a = (
            "IntelliDocs Smart Document Management System provides offline AI document "
            "classification, hybrid full-text search, multi-level security scanning, "
            "and duplicate detection algorithms across all local workspace repositories."
        )
        text_b = (
            "IntelliDocs Smart Document Management System provides offline AI document "
            "classification, hybrid full-text search, multi-level security scanning, "
            "and duplicate detection algorithms across local workspace repositories."
        )
        db.add_all([
            DocumentModel(
                uuid="fresh-doc-a", original_name="fresh-a.docx",
                stored_name="fresh-a.docx", file_path="uploads/fresh-a.docx",
                file_type="docx", mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                size_bytes=len(text_a), sha256_hash="fresh-sha-a", extracted_text=text_a,
                owner_id=user.id, processing_status="done",
            ),
            DocumentModel(
                uuid="fresh-doc-b", original_name="fresh-b.docx",
                stored_name="fresh-b.docx", file_path="uploads/fresh-b.docx",
                file_type="docx", mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                size_bytes=len(text_b), sha256_hash="fresh-sha-b", extracted_text=text_b,
                owner_id=user.id, processing_status="done",
            ),
        ])
        db.commit()

        # Simulate the case where the candidate index emits no pairs; the strict
        # fallback and latest-first response ordering must still surface this pair.
        monkeypatch.setattr(
            duplicates_api.duplicate_service_instance,
            "analyze_all_candidates",
            lambda _db, _doc, _owner_id, **_kwargs: [],
        )
        result = duplicates_api.get_duplicate_alerts(current_user=user, db=db)
        assert result["alert_count"] > 100
        assert any(
            {alert["document_uuid"], alert["candidate_uuid"]}
            == {"fresh-doc-a", "fresh-doc-b"}
            for alert in result["alerts"]
        )
    finally:
        duplicates_api.duplicate_service_instance.analyze_all_candidates = original_analyze
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
