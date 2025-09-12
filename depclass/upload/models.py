"""
Data Models for Trace-AI Upload Workflow

Pydantic-based models for type safety and validation throughout
the upload process.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class UploadStatus(Enum):
    """Upload status enumeration"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class TraceAIConfig:
    """Configuration for Trace-AI upload operations"""
    api_url: str
    license_key: str
    upload_timeout: int = 300
    max_retries: int = 3
    parallel_uploads: int = 3
    chunk_size: int = 8192
    
    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests"""
        return {
            "X-Zerberus-License-Key": self.license_key,
            "Content-Type": "application/json"
        }


@dataclass
class RepositoryMetadata:
    """Repository information for scan metadata"""
    name: str
    scm_platform: str
    scm_namespace: str
    scm_repository: str
    scm_url: str
    default_branch: str = "main"


@dataclass
class ScanMetadata:
    """Scan execution metadata"""
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    trigger_type: str = "manual"
    started_at: Optional[datetime] = None
    environment: Optional[Dict[str, Any]] = None
    local_execution: bool = True


@dataclass
class ScanInitiationRequest:
    """Request model for scan initiation"""
    repository_metadata: RepositoryMetadata
    scan_metadata: ScanMetadata


@dataclass
class ThresholdConfig:
    """Threshold configuration from API"""
    enabled: bool
    high_severity_weight: int
    medium_severity_weight: int
    low_severity_weight: int
    max_score_threshold: int
    fail_on_critical: bool


@dataclass
class ScanInitiationResponse:
    """Response model for scan initiation"""
    scan_id: str
    project_id: str
    status: str
    message: str
    created_at: datetime
    threshold_config: Optional['ThresholdConfig'] = None


@dataclass
class UploadUrlsRequest:
    """Request model for upload URLs"""
    files: List[str]


@dataclass
class PresignedURL:
    """Presigned S3 URL information"""
    url: str
    expires_at: datetime
    fields: Optional[Dict[str, str]] = None


@dataclass
class UploadUrlsResponse:
    """Response model for upload URLs"""
    scan_id: str
    upload_urls: Dict[str, PresignedURL]
    upload_deadline: datetime


@dataclass
class UploadSummary:
    """Summary of upload operation"""
    total_files: int
    successful_uploads: int
    failed_uploads: int
    total_size_bytes: int


@dataclass
class CompletionRequest:
    """Request model for upload completion"""
    upload_status: UploadStatus
    uploaded_files: List[str]
    failed_files: List[str]
    completed_at: datetime
    upload_summary: UploadSummary


@dataclass
class CompletionResponse:
    """Response model for upload completion"""
    scan_id: str
    status: str
    report_url: str
    message: str
    processing_status: str
    estimated_processing_time: str


@dataclass
class FileUploadResult:
    """Result of individual file upload"""
    file_path: str
    success: bool
    error_message: Optional[str] = None
    size_bytes: Optional[int] = None
    upload_time_seconds: Optional[float] = None


@dataclass
class ThresholdResult:
    """Result of threshold validation"""
    threshold_exceeded: bool
    should_fail_build: bool
    calculated_score: int
    max_threshold: int
    failure_reason: Optional[str] = None


@dataclass
class UploadResult:
    """Overall upload operation result"""
    success: bool
    scan_id: Optional[str] = None
    report_url: Optional[str] = None
    error: Optional[str] = None
    skip_reason: Optional[str] = None
    file_results: Optional[List[FileUploadResult]] = None
    total_time_seconds: Optional[float] = None
    threshold_result: Optional[ThresholdResult] = None


@dataclass
class ValidationResult:
    """File validation result"""
    is_valid: bool
    error_message: Optional[str] = None
    file_path: Optional[str] = None
    validation_type: Optional[str] = None