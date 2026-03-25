"""
Abstract base class for all forensic collectors.
One subclass per platform (AWS, GCP, Stripe, etc.).
"""

from abc import ABC, abstractmethod
from datetime import datetime

from normalizer.schema import ForensicEvent


class BaseCollector(ABC):
    """All collectors implement this interface."""

    @abstractmethod
    def collect(
        self,
        access_key_id: str,
        exposure_start: datetime,
        exposure_end: datetime,
    ) -> list[ForensicEvent]:
        """
        Query the platform's audit log for events during the exposure window.
        Returns normalised ForensicEvent objects.
        """
        ...
