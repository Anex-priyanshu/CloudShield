"""Registry of all security checks."""
from app.checks.iam_checks import ALL_IAM_CHECKS
from app.checks.s3_checks import ALL_S3_CHECKS
from app.checks.other_checks import (
    ALL_NETWORK_CHECKS, ALL_LOGGING_CHECKS, ALL_ENCRYPTION_CHECKS, ALL_BACKUP_CHECKS
)

ALL_CHECKS = (
    ALL_IAM_CHECKS
    + ALL_S3_CHECKS
    + ALL_NETWORK_CHECKS
    + ALL_LOGGING_CHECKS
    + ALL_ENCRYPTION_CHECKS
    + ALL_BACKUP_CHECKS
)

CHECK_CATEGORIES = {
    "IAM": ALL_IAM_CHECKS,
    "Storage": ALL_S3_CHECKS,
    "Network": ALL_NETWORK_CHECKS,
    "Logging": ALL_LOGGING_CHECKS,
    "Encryption": ALL_ENCRYPTION_CHECKS,
    "Backup": ALL_BACKUP_CHECKS,
}

__all__ = ["ALL_CHECKS", "CHECK_CATEGORIES"]
