from datetime import datetime

import boto3

from collectors.base import BaseCollector
from normalizer.schema import ForensicEvent


class AWSCloudTrailCollector(BaseCollector):
    """
    Collects AWS CloudTrail events for a given access key ID during an exposure window.
    TODO (Ritwik/Day 3): implement full pagination and event mapping.
    """

    platform = "aws"

    def collect(
        self,
        credential: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[ForensicEvent]:
        raise NotImplementedError("CloudTrail collector — implement on Day 3")
