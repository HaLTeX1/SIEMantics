import enum


class AlertStatus(str, enum.Enum):
    SUPPRESSED = "suppressed"
    ESCALATED = "escalated"
    ERROR = "error"


class GroundTruth(str, enum.Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
