from abc import ABC, abstractmethod
from datetime import datetime

from normalizer.schema import ForensicEvent


class BaseCollector(ABC):
    """Abstract base class for all platform forensic collectors."""

    platform: str = ""

    @abstractmethod
    def collect(
        self,
        credential: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[ForensicEvent]:
        """
        Query the platform audit log API for activity during [start_time, end_time].
        Returns a list of normalised ForensicEvent objects.
        """
        ...
