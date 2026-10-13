"""INTELLIDOCS_SHARING_HUB_FOLLOWUP_REGRESSION_TESTS_V1"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
CSS = (ROOT / "frontend" / "styles.css").read_text(encoding="utf-8")


def test_email_invitation_note_removed_from_sharing_hub():
    assert "Email invitations to people without an account are not configured" not in HTML
    assert "shared-invite-note" not in HTML


def test_sent_shares_can_be_revoked_without_deleting_document():
    assert "function revokeSharedDocument(" in APP
    assert "method: 'DELETE'" in APP
    assert "The document will remain in your library; only shared access will be removed." in APP
    assert "Share revoked. The original document was not deleted." in APP


def test_shared_document_list_has_search_and_pagination():
    assert 'id="shared-documents-search"' in HTML
    assert 'id="shared-documents-pagination"' in HTML
    assert "function handleSharedDocumentsSearch(" in APP
    assert "function changeSharedDocumentsPage(" in APP
    assert "SHARED_DOCUMENTS_PAGE_SIZE = 4" in APP


def test_received_locked_document_uses_existing_unlock_route():
    assert "function openSharedReceivedDocument(" in APP
    assert "openDocumentDetail(documentUuid);" in APP
    assert "access-lock/unlock" in APP
    assert "modal-access-lock-unlock" in HTML


def test_group_cards_have_document_picker_and_use_existing_group_share_api():
    assert 'onclick="openGroupDocumentPicker(${g.id})"' in APP
    assert 'id="modal-group-share-document"' in HTML
    assert "function submitGroupDocumentPicker(event)" in APP
    assert "`/groups/${groupId}/shares`" in APP
    assert "Number(d.owner_id) === Number(currentUser.id)" in APP


def test_received_share_key_verification_continues_into_lock_and_security_review_flow():
    assert "beginReceivedShareActivation(" in APP
    assert "continueReceivedShareActivation()" in APP
    assert "await showReceivedShareSecurityReport();" in APP
    assert "access-lock/unlock" in APP
    assert 'id="modal-share-security-review"' in HTML
    assert "submitReceivedShareActivation()" in APP
    assert "const lockQuery = lockToken ? `?lock_token=${encodeURIComponent(lockToken)}` : '';" in APP
    assert "security-report${lockQuery}" in APP
    assert "activate${lockQuery}" in APP


def test_compact_toolbar_css_is_scoped():
    assert ".shared-documents-toolbar" in CSS
    assert ".shared-documents-pagination" in CSS
