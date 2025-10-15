"""
Utility functions for enhancer providers.

This module provides shared utility functions to avoid code duplication.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict


def create_http_session(
    user_agent: str,
    timeout: int = 30,
    max_retries: int = 3,
    auth_token: Optional[str] = None,
    additional_headers: Optional[Dict[str, str]] = None
) -> requests.Session:
    """
    Create a configured HTTP session with retry logic and standard headers.

    Args:
        user_agent: User-Agent string for the session
        timeout: Default timeout in seconds for requests
        max_retries: Maximum number of retries on failed requests
        auth_token: Optional authentication token (for Authorization header)
        additional_headers: Optional additional headers to add to the session

    Returns:
        Configured requests.Session instance
    """
    session = requests.Session()

    # Configure retry strategy for network resilience
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST"],
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Set timeout as default for all requests
    session.timeout = timeout

    # Set standard headers
    headers = {"User-Agent": user_agent}

    # Add authentication if provided
    if auth_token:
        headers["Authorization"] = f"token {auth_token}"

    # Add additional headers if provided
    if additional_headers:
        headers.update(additional_headers)

    session.headers.update(headers)

    return session
