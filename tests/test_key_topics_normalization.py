import json
from backend.schemas.document_schema import DocumentOut

def test_normalize_key_topics_legacy_string():
    # Valid JSON string representing a list
    doc = DocumentOut(
        id=1,
        uuid="abc",
        original_name="test.txt",
        file_type="txt",
        mime_type="text/plain",
        size_bytes=100,
        sha256_hash="hash",
        sensitivity="General",
        has_ocr=0,
        processing_status="DONE",
        owner_id=1,
        uploaded_at="2023-01-01T00:00:00Z",
        key_topics='["Clg Fee"]'
    )
    assert doc.key_topics == ["Clg Fee"]

    # Already correct list
    doc2 = DocumentOut(
        id=2,
        uuid="def",
        original_name="test2.txt",
        file_type="txt",
        mime_type="text/plain",
        size_bytes=100,
        sha256_hash="hash",
        sensitivity="General",
        has_ocr=0,
        processing_status="DONE",
        owner_id=1,
        uploaded_at="2023-01-01T00:00:00Z",
        key_topics=["Already", "List"]
    )
    assert doc2.key_topics == ["Already", "List"]

    # Malformed string
    doc3 = DocumentOut(
        id=3,
        uuid="ghi",
        original_name="test3.txt",
        file_type="txt",
        mime_type="text/plain",
        size_bytes=100,
        sha256_hash="hash",
        sensitivity="General",
        has_ocr=0,
        processing_status="DONE",
        owner_id=1,
        uploaded_at="2023-01-01T00:00:00Z",
        key_topics='["Bad Json"'
    )
    assert doc3.key_topics == []

    # None value
    doc4 = DocumentOut(
        id=4,
        uuid="jkl",
        original_name="test4.txt",
        file_type="txt",
        mime_type="text/plain",
        size_bytes=100,
        sha256_hash="hash",
        sensitivity="General",
        has_ocr=0,
        processing_status="DONE",
        owner_id=1,
        uploaded_at="2023-01-01T00:00:00Z",
        key_topics=None
    )
    assert doc4.key_topics == []
