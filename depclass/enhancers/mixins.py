"""
Shared mixins for enhancer providers.

This module provides reusable mixins to avoid code duplication across providers.
"""

import logging
from typing import Any, Dict, Optional

from ..db.vulnerability import VulnerabilityCache

logger = logging.getLogger(__name__)


class CacheableMixin:
    """
    Mixin providing caching functionality for enhancer providers.

    This mixin requires the following attributes on the implementing class:
    - self.cache: Optional[VulnerabilityCache]
    - self.config: Dict with caching configuration
    """

    # Type hints for attributes expected from implementing classes
    cache: Optional[VulnerabilityCache]
    config: Dict[str, Any]

    def _is_cache_available(self) -> bool:
        """
        Check if caching is available and enabled.

        Returns:
            True if cache is available and enabled, False otherwise
        """
        if not hasattr(self, 'cache') or self.cache is None:
            return False

        # Check if caching is enabled in config
        if hasattr(self, 'config') and not self.config.get("caching", {}).get("enabled", False):
            return False

        return True

    def _get_cached_data(self, cache_key: str, ttl_hours: int) -> Optional[Dict]:
        """
        Get cached data if available.

        Args:
            cache_key: Unique key for the cached data
            ttl_hours: Time-to-live in hours for the cached data (must be positive)

        Returns:
            Cached data dictionary if available and not expired, None otherwise

        Raises:
            ValueError: If ttl_hours is not positive
        """
        if ttl_hours <= 0:
            raise ValueError(f"TTL must be positive, got {ttl_hours}")

        if not self._is_cache_available():
            return None

        try:
            return self.cache.get_cached_data(cache_key, ttl_hours)
        except Exception as e:
            logger.warning(f"Failed to retrieve cached data for key '{cache_key}': {e}")
            return None

    def _cache_data(self, cache_key: str, data: Any) -> bool:
        """
        Cache data for future use.

        Args:
            cache_key: Unique key for storing the data
            data: Data to cache (must be JSON-serializable)

        Returns:
            True if data was successfully cached, False otherwise
        """
        if not self._is_cache_available():
            return False

        try:
            return self.cache.cache_data(cache_key, data)
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to cache data for key '{cache_key}': {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error caching data for key '{cache_key}': {e}")
            return False
