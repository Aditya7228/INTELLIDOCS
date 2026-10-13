from backend.ai.pii_detector import PIIDetector

class SensitivityService:
    def __init__(self):
        self.detector = PIIDetector()

    def analyze(self, text: str):
        return self.detector.detect_pii(text)
