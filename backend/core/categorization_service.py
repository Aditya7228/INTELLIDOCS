from typing import Tuple, List, Optional, Dict, Any
from backend.ai.classifier import DocumentClassifier

class CategorizationService:
    def __init__(self, embedding_engine=None):
        self.classifier = DocumentClassifier(embedding_engine=embedding_engine)

    def categorize(self, text: str):
        return self.classifier.classify(text)

    def categorize_multi_signal(
        self,
        text: str = "",
        filename: str = "",
        file_type: str = "",
        pii_types: Optional[List[str]] = None,
        ocr_confidence: Optional[float] = None
    ) -> Tuple[str, float, str, Dict[str, Any]]:
        return self.classifier.classify_multi_signal(
            text=text,
            filename=filename,
            file_type=file_type,
            pii_types=pii_types,
            ocr_confidence=ocr_confidence
        )
