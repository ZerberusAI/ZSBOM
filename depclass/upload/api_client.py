"""
Zerberus API Client for Trace-AI Upload

Handles all API interactions with the Zerberus server following the 3-phase
upload workflow: initiate, upload URLs, and completion acknowledgment.
"""

import json
import time
import asyncio
import aiohttp
import aiofiles
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests
import backoff

from .models import (
    TraceAIConfig,
    ScanInitiationRequest,
    ScanInitiationResponse, 
    UploadUrlsRequest,
    UploadUrlsResponse,
    CompletionRequest,
    CompletionResponse,
    PresignedURL,
    FileUploadResult
)
from .exceptions import (
    APIConnectionError,
    AuthenticationError,
    UploadError,
    ScanStateError
)


class ZerberusAPIClient:
    """Handles all API interactions with Zerberus server"""
    
    def __init__(self, config: TraceAIConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(config.get_headers())
        
        # Set reasonable timeouts
        self.session.timeout = config.upload_timeout
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()
    
    @backoff.on_exception(
        backoff.expo,
        (requests.exceptions.RequestException, APIConnectionError),
        max_tries=3,
        base=1,
        max_value=60
    )
    def initiate_scan(self, request: ScanInitiationRequest) -> ScanInitiationResponse:
        """POST /trace-ai/scans/initiate"""
        endpoint = "trace-ai/scans/initiate"
        url = urljoin(self.config.api_url, endpoint)
        
        # Convert request to dict
        payload = {
            "repository_metadata": {
                "name": request.repository_metadata.name,
                "scm_platform": request.repository_metadata.scm_platform,
                "scm_namespace": request.repository_metadata.scm_namespace,
                "scm_repository": request.repository_metadata.scm_repository,
                "scm_url": request.repository_metadata.scm_url,
                "default_branch": request.repository_metadata.default_branch
            },
            "scan_metadata": {
                "branch": request.scan_metadata.branch,
                "commit_sha": request.scan_metadata.commit_sha,
                "trigger_type": request.scan_metadata.trigger_type,
                "started_at": request.scan_metadata.started_at.isoformat() if request.scan_metadata.started_at else None,
                "environment": request.scan_metadata.environment or {},
                "local_execution": request.scan_metadata.local_execution
            }
        }
        
        try:
            response = self.session.post(url, json=payload)
            self._handle_response_errors(response, endpoint)
            
            data = response.json()
            return ScanInitiationResponse(
                scan_id=data["scan_id"],
                project_id=data["project_id"],
                status=data["status"],
                message=data["message"],
                created_at=datetime.fromisoformat(data["created_at"].replace('Z', '+00:00'))
            )
            
        except requests.exceptions.RequestException as e:
            raise APIConnectionError(f"Failed to initiate scan: {str(e)}", endpoint=endpoint)
    
    @backoff.on_exception(
        backoff.expo,
        (requests.exceptions.RequestException, APIConnectionError),
        max_tries=3,
        base=1,
        max_value=60
    )
    def get_upload_urls(self, scan_id: str, files: List[str]) -> UploadUrlsResponse:
        """POST /trace-ai/scans/{scan_id}/upload-urls"""
        endpoint = f"trace-ai/scans/{scan_id}/upload-urls"
        url = urljoin(self.config.api_url, endpoint)
        
        payload = {"files": files}
        
        try:
            response = self.session.post(url, json=payload)
            self._handle_response_errors(response, endpoint)
            
            data = response.json()
            
            # Parse upload URLs
            upload_urls = {}
            for filename, url_data in data["upload_urls"].items():
                upload_urls[filename] = PresignedURL(
                    url=url_data["url"],
                    expires_at=datetime.fromisoformat(url_data["expires_at"].replace('Z', '+00:00')),
                    fields=url_data.get("fields", {})
                )
            
            return UploadUrlsResponse(
                scan_id=data["scan_id"],
                upload_urls=upload_urls,
                upload_deadline=datetime.fromisoformat(data["upload_deadline"].replace('Z', '+00:00'))
            )
            
        except requests.exceptions.RequestException as e:
            raise APIConnectionError(f"Failed to get upload URLs: {str(e)}", endpoint=endpoint)
    
    @backoff.on_exception(
        backoff.expo,
        (requests.exceptions.RequestException, APIConnectionError),
        max_tries=3,
        base=1,
        max_value=60
    )
    def acknowledge_completion(self, scan_id: str, request: CompletionRequest) -> CompletionResponse:
        """POST /trace-ai/scans/{scan_id}/complete"""
        endpoint = f"trace-ai/scans/{scan_id}/complete"
        url = urljoin(self.config.api_url, endpoint)
        
        payload = {
            "upload_status": request.upload_status.value,
            "uploaded_files": request.uploaded_files,
            "failed_files": request.failed_files,
            "completed_at": request.completed_at.isoformat(),
            "upload_summary": {
                "total_files": request.upload_summary.total_files,
                "successful_uploads": request.upload_summary.successful_uploads,
                "failed_uploads": request.upload_summary.failed_uploads,
                "total_size_bytes": request.upload_summary.total_size_bytes
            }
        }
        
        try:
            response = self.session.post(url, json=payload)
            self._handle_response_errors(response, endpoint)
            
            data = response.json()
            return CompletionResponse(
                scan_id=data["scan_id"],
                status=data["status"],
                report_url=data["report_url"],
                message=data["message"],
                processing_status=data["processing_status"],
                estimated_processing_time=data["estimated_processing_time"]
            )
            
        except requests.exceptions.RequestException as e:
            raise APIConnectionError(f"Failed to acknowledge completion: {str(e)}", endpoint=endpoint)
    
    async def upload_to_s3(self, file_path: str, presigned_url: PresignedURL) -> FileUploadResult:
        """Upload file to S3 using presigned URL"""
        start_time = time.time()
        
        try:
            # Get file size
            import os
            file_size = os.path.getsize(file_path)
            
            # Prepare upload
            connector = aiohttp.TCPConnector(limit=10)
            timeout = aiohttp.ClientTimeout(total=self.config.upload_timeout)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with aiofiles.open(file_path, 'rb') as f:
                    file_data = await f.read()
                
                # Prepare form data if fields are provided
                data = aiohttp.FormData()
                for key, value in presigned_url.fields.items():
                    data.add_field(key, value)
                data.add_field('file', file_data, filename=os.path.basename(file_path))
                
                # Upload to S3
                async with session.post(presigned_url.url, data=data) as response:
                    if response.status not in [200, 201, 204]:
                        error_text = await response.text()
                        raise UploadError(
                            f"S3 upload failed with status {response.status}: {error_text}",
                            file_path=file_path
                        )
            
            upload_time = time.time() - start_time
            
            return FileUploadResult(
                file_path=file_path,
                success=True,
                size_bytes=file_size,
                upload_time_seconds=upload_time
            )
            
        except Exception as e:
            upload_time = time.time() - start_time
            
            if isinstance(e, (UploadError, aiohttp.ClientError)):
                error_msg = str(e)
            else:
                error_msg = f"Unexpected upload error: {str(e)}"
            
            return FileUploadResult(
                file_path=file_path,
                success=False,
                error_message=error_msg,
                upload_time_seconds=upload_time
            )
    
    async def upload_files_parallel(self, upload_urls: Dict[str, PresignedURL], file_paths: Dict[str, str]) -> List[FileUploadResult]:
        """Upload multiple files in parallel with semaphore control"""
        semaphore = asyncio.Semaphore(self.config.parallel_uploads)
        
        async def upload_single_file(upload_name: str) -> FileUploadResult:
            async with semaphore:
                file_path = file_paths[upload_name]
                presigned_url = upload_urls[upload_name]
                return await self.upload_to_s3(file_path, presigned_url)
        
        # Create upload tasks
        tasks = [upload_single_file(upload_name) for upload_name in upload_urls.keys()]
        
        # Execute with progress tracking
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                upload_name = list(upload_urls.keys())[i]
                file_path = file_paths[upload_name]
                processed_results.append(FileUploadResult(
                    file_path=file_path,
                    success=False,
                    error_message=str(result)
                ))
            else:
                processed_results.append(result)
        
        return processed_results
    
    def _handle_response_errors(self, response: requests.Response, endpoint: str):
        """Handle common API response errors"""
        if response.status_code == 401:
            raise AuthenticationError(
                "Invalid Zerberus license key. Please check ZERBERUS_LICENSE_KEY"
            )
        elif response.status_code == 403:
            raise AuthenticationError(
                "Access forbidden. Your license key may not have permission for this project"
            )
        elif response.status_code == 404:
            raise APIConnectionError(
                f"API endpoint not found: {endpoint}",
                status_code=response.status_code,
                endpoint=endpoint
            )
        elif response.status_code == 409:
            error_msg = "Conflict error"
            try:
                error_data = response.json()
                error_msg = error_data.get("message", error_msg)
            except:
                pass
            raise ScanStateError(error_msg)
        elif response.status_code >= 400:
            error_msg = f"API error {response.status_code}"
            try:
                error_data = response.json()
                error_msg = error_data.get("message", error_msg)
            except:
                error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
            
            raise APIConnectionError(
                error_msg,
                status_code=response.status_code,
                endpoint=endpoint
            )