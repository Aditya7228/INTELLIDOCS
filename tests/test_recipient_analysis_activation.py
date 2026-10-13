from pathlib import Path


def test_received_share_activation_runs_recipient_analysis_pipeline():
    root = Path(__file__).resolve().parents[1]
    source = (root / "frontend" / "app.js").read_text(encoding="utf-8")
    start = source.index("async function submitReceivedShareActivation()")
    end = source.index("function cancelReceivedShareActivation()", start)
    activation = source[start:end]
    assert "/suggestions/analyze?document_id=" in activation
    assert "intellidocs_suggestion_focus_document_id" in activation
    assert "/suggestions/analyze-groups" in activation
    assert "loadRelatedDocuments()" in activation
    assert "navigateTo('suggestions')" in activation


def test_recipient_group_evidence_matches_current_suggestions_renderer():
    root = Path(__file__).resolve().parents[1]
    org = (root / "backend" / "core" / "organization_service.py").read_text(encoding="utf-8")
    assert '"v14_strong_group": True' in org
    assert '"document_ids": ids_signature' in org


def test_recipient_pipeline_test_fixture_runs_additive_migrations():
    root = Path(__file__).resolve().parents[1]
    test = (root / "tests" / "test_recipient_pipeline_scope.py").read_text(encoding="utf-8")
    assert "from backend.database.migrations import run_migrations" in test
    assert "run_migrations(engine)" in test



def test_suggestions_and_duplicate_review_include_activated_received_documents():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    source = (root / "frontend" / "app.js").read_text(encoding="utf-8")
    suggestions_start = source.rfind("window.loadSuggestions = async function()")
    suggestions_end = source.index("window.triggerAnalyzeLibrarySuggestions", suggestions_start)
    suggestions = source[suggestions_start:suggestions_end]
    assert 'apiFetch("/shares/received")' in suggestions
    assert "access_activated" in suggestions
    assert "lockTokens[focusedUuid]" in suggestions
    assert 'apiFetch("/suggestions/analyze-groups"' in suggestions
    duplicate_start = source.index("async function initDuplicatesPage()")
    duplicate_end = source.index("async function inspectSelectedDuplicates()", duplicate_start)
    duplicates = source[duplicate_start:duplicate_end]
    assert 'apiFetch("/shares/received")' in duplicates
    assert "intellidocsReceivedSharedDocumentUuids" in duplicates
