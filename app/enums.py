import enum


class AlertStatus(str, enum.Enum):
    SUPPRESSED = "suppressed"
    ESCALATED = "escalated"
    ERROR = "error"
    # FP verdict below REVIEW_CONFIDENCE_THRESHOLD: not escalated, but not silently dropped either
    NEEDS_REVIEW = "needs_review"


class GroundTruth(str, enum.Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
