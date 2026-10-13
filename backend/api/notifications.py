from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.notification_repo import NotificationRepository
from backend.schemas.document_schema import NotificationOut
from backend.schemas.settings_schema import NotificationSettingsOut, NotificationSettingsUpdate
from backend.models.user_notification_settings import UserNotificationSettings
from backend.models.user import User
from backend.api.deps import get_current_user

router = APIRouter(prefix="/notifications", tags=["Notifications"])

@router.get("", response_model=List[NotificationOut])
def list_notifications(
    unread_only: bool = False,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from backend.database.repositories.document_repo import DocumentRepository
    repo = NotificationRepository(db)
    doc_repo = DocumentRepository(db)
    raw_notifs = repo.list_for_user(user_id=current_user.id, unread_only=unread_only, limit=limit)

    res = []
    for n in raw_notifs:
        n_out = NotificationOut.model_validate(n)
        if n.document_id:
            doc = doc_repo.get_by_id(n.document_id)
            if doc and not doc.is_deleted:
                n_out.document_uuid = doc.uuid
            else:
                n_out.document_uuid = None
        res.append(n_out)
    return res


@router.post("/{notification_id}/read", status_code=status.HTTP_200_OK)
def mark_notification_read(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = NotificationRepository(db)
    ok = repo.mark_read(notification_id=notification_id, user_id=current_user.id)
    if not ok:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"detail": "Marked read"}

@router.post("/read-all", status_code=status.HTTP_200_OK)
def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = NotificationRepository(db)
    repo.mark_all_read(user_id=current_user.id)
    return {"detail": "All notifications marked read"}

@router.get("/settings", response_model=NotificationSettingsOut)
def get_notification_settings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    settings_rec = db.query(UserNotificationSettings).filter(UserNotificationSettings.user_id == current_user.id).first()
    if not settings_rec:
        settings_rec = UserNotificationSettings(user_id=current_user.id)
        db.add(settings_rec)
        db.commit()
        db.refresh(settings_rec)

    return NotificationSettingsOut(
        email_notifications=bool(settings_rec.email_notifications),
        in_app_notifications=bool(settings_rec.in_app_notifications),
        suggestion_alerts=bool(settings_rec.suggestion_alerts),
        duplicate_alerts=bool(settings_rec.duplicate_alerts),
        security_alerts=bool(settings_rec.security_alerts)
    )

@router.put("/settings", response_model=NotificationSettingsOut)
@router.post("/settings", response_model=NotificationSettingsOut)
def update_notification_settings(
    data: NotificationSettingsUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    settings_rec = db.query(UserNotificationSettings).filter(UserNotificationSettings.user_id == current_user.id).first()
    if not settings_rec:
        settings_rec = UserNotificationSettings(user_id=current_user.id)
        db.add(settings_rec)

    if data.email_notifications is not None:
        settings_rec.email_notifications = 1 if data.email_notifications else 0
    if data.in_app_notifications is not None:
        settings_rec.in_app_notifications = 1 if data.in_app_notifications else 0
    if data.suggestion_alerts is not None:
        settings_rec.suggestion_alerts = 1 if data.suggestion_alerts else 0
    if data.duplicate_alerts is not None:
        settings_rec.duplicate_alerts = 1 if data.duplicate_alerts else 0
    if data.security_alerts is not None:
        settings_rec.security_alerts = 1 if data.security_alerts else 0

    db.commit()
    db.refresh(settings_rec)

    return NotificationSettingsOut(
        email_notifications=bool(settings_rec.email_notifications),
        in_app_notifications=bool(settings_rec.in_app_notifications),
        suggestion_alerts=bool(settings_rec.suggestion_alerts),
        duplicate_alerts=bool(settings_rec.duplicate_alerts),
        security_alerts=bool(settings_rec.security_alerts)
    )
