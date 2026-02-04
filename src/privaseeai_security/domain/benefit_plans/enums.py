"""Enumerations for benefit plan types and network types."""

from enum import Enum


class BenefitPlanType(str, Enum):
    """Types of insurance benefit plans."""

    PPO = "PPO"
    HMO = "HMO"
    EPO = "EPO"
    POS = "POS"
    INDEMNITY = "Indemnity"
    MEDICARE = "Medicare"
    MEDICAID = "Medicaid"
    OTHER = "Other"


class NetworkType(str, Enum):
    """Network coverage types for benefit plans."""

    IN_NETWORK = "In-Network"
    OUT_OF_NETWORK = "Out-of-Network"
    BOTH = "Both"
