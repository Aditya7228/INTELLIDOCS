import os
import smtplib
from email.mime.text import MIMEText
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field, field_validator, ConfigDict
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.models.user import User
from backend.models.support_ticket import SupportTicket
from backend.models.document import DocumentModel
from backend.api.deps import get_current_user
from backend.core.permission_service import PermissionService
from backend.core.audit_service import AuditService

router = APIRouter(prefix="/support", tags=["Support"])

ALLOWED_ISSUE_TYPES = {
    "general", "upload", "ai_suggestions", "search", "duplicates",
    "sharing", "access_lock", "explorer", "security", "bug", "account", "other"
}

class SupportTicketCreate(BaseModel):
    issue_type: str
    subject: str = Field(..., min_length=3, max_length=200)
    message: str = Field(..., min_length=10, max_length=3000)
    document_uuid: Optional[str] = None

    @field_validator("issue_type")
    @classmethod
    def validate_issue_type(cls, val: str) -> str:
        v = (val or "").strip().lower()
        if v not in ALLOWED_ISSUE_TYPES:
            raise ValueError(f"Invalid issue type. Allowed: {', '.join(sorted(ALLOWED_ISSUE_TYPES))}")
        return v

    @field_validator("subject", "message")
    @classmethod
    def strip_whitespace(cls, val: str) -> str:
        v = (val or "").strip()
        if not v:
            raise ValueError("Field cannot be empty or whitespace only")
        return v


class SupportTicketOut(BaseModel):
    id: int
    user_id: int
    issue_type: str
    subject: str
    message: str
    document_uuid: Optional[str] = None
    status: str
    email_sent: int
    created_at: str

    model_config = ConfigDict(from_attributes=True)


@router.post("/tickets", response_model=SupportTicketOut, status_code=status.HTTP_201_CREATED)
def submit_support_ticket(
    data: SupportTicketCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Validate optional document context reference
    doc_uuid = None
    if data.document_uuid and data.document_uuid.strip():
        doc_uuid = data.document_uuid.strip()
        doc = db.query(DocumentModel).filter(DocumentModel.uuid == doc_uuid, DocumentModel.is_deleted == 0).first()
        if not doc or not PermissionService.can_read(db, current_user, doc):
            raise HTTPException(status_code=404, detail="Referenced document not found or access denied")

    # Persist support request to DB (primary store)
    ticket = SupportTicket(
        user_id=current_user.id,
        issue_type=data.issue_type,
        subject=data.subject,
        message=data.message,
        document_uuid=doc_uuid,
        status="open",
        email_sent=0
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    # Optional email notification to support/admin if configured via env
    admin_email = os.getenv("SUPPORT_ADMIN_EMAIL")
    smtp_host = os.getenv("SUPPORT_SMTP_HOST")
    if admin_email and smtp_host:
        try:
            smtp_port = int(os.getenv("SUPPORT_SMTP_PORT", "587"))
            smtp_user = os.getenv("SUPPORT_SMTP_USER", "")
            smtp_pass = os.getenv("SUPPORT_SMTP_PASS", "")

            msg_body = f"Support Ticket #{ticket.id}\nUser: {current_user.username} ({current_user.email})\nCategory: {ticket.issue_type}\nSubject: {ticket.subject}\n\nMessage:\n{ticket.message}\n"
            msg = MIMEText(msg_body)
            msg["Subject"] = f"[IntelliDocs Support #{ticket.id}] {ticket.subject}"
            msg["From"] = smtp_user or "support@intellidocs.local"
            msg["To"] = admin_email

            with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as server:
                if smtp_user and smtp_pass:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                server.send_message(msg)

            ticket.email_sent = 1
            db.commit()
            db.refresh(ticket)
        except Exception:
            # Failure to email does not lose the persisted ticket
            pass

    AuditService.log(
        db,
        action="SUPPORT_TICKET_CREATE",
        user_id=current_user.id,
        resource_type="support_ticket",
        resource_id=str(ticket.id),
        ip_address=request.client.host if request.client else None
    )

    return ticket


@router.get("/tickets", response_model=List[SupportTicketOut])
def list_user_support_tickets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns authenticated user's own support tickets strictly enforcing user isolation."""
    tickets = db.query(SupportTicket).filter(
        SupportTicket.user_id == current_user.id
    ).order_by(SupportTicket.created_at.desc()).all()
    return tickets
