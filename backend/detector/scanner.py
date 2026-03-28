from detector.patterns import CredentialMatch, find_aws_credentials


def scan_diff(diff_text: str) -> list[CredentialMatch]:
    """
    Scan a commit diff string for credential patterns.
    Returns a list of CredentialMatch objects found.
    TODO (Yash/Day 2): add line-number tracking, multi-credential support.
    """
    return find_aws_credentials(diff_text)
