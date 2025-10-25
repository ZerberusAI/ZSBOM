"""
GitHub integration module for ZSBOM.

This module provides functionality for generating rich PR comments
with vulnerability data for GitHub Actions workflows.
"""

from depclass.github.pr_comment_generator import PRCommentGenerator

__all__ = ["PRCommentGenerator"]
