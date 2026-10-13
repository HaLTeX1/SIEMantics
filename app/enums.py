import enum


class AlertStatus(str, enum.Enum):
    SUPPRESSED = "suppressed"
    ESCALATED = "escalated"
    ERROR = "error"
    # Alacsony confidence-u FP itelet: nem eszkalalt, de nem is elnyomott.
    NEEDS_REVIEW = "needs_review"
    # Webhookrol erkezett, a hatter workerre var (app/pipeline.py).
    QUEUED = "queued"


class GroundTruth(str, enum.Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
