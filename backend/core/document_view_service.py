"""Recipient-safe document presentation helpers."""
from backend.models.user_document_preference import UserDocumentPreference
from backend.models.tag import Tag, document_tags


def get_preference(db, user_id: int, document_id: int):
    if db is None or not user_id or not document_id:
        return None
    return db.query(UserDocumentPreference).filter(
        UserDocumentPreference.user_id == user_id,
        UserDocumentPreference.document_id == document_id,
    ).first()


def effective_fields(db, doc, user_id: int):
    """Return only values that this user is allowed to see for the given document."""
    if not doc:
        return {}
    if user_id == doc.owner_id:
        tags = list(getattr(doc, "tags", []) or [])
        return {
            "display_name": getattr(doc, "display_name", None) or doc.original_name,
            "category": getattr(doc, "category", None),
            "folder_id": getattr(doc, "folder_id", None),
            "tags": tags,
        }

    pref = get_preference(db, user_id, doc.id)
    # Do not expose the owner's folder path or tag assignments in the recipient's view.
    recipient_tags = db.query(Tag).join(
        document_tags, document_tags.c.tag_id == Tag.id
    ).filter(
        document_tags.c.document_id == doc.id,
        document_tags.c.assigned_by == user_id,
    ).all()
    return {
        "display_name": (pref.display_name if pref and pref.display_name else None) or getattr(doc, "display_name", None) or doc.original_name,
        "category": (pref.category if pref and pref.category else None) or getattr(doc, "category", None),
        "folder_id": pref.folder_id if pref else None,
        "tags": recipient_tags,
    }
