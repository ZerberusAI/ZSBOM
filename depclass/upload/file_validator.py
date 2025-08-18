"""
File Validator for Trace-AI Upload

Validates files before upload to ensure compliance with size limits,
format requirements, and basic structure validation.
"""

import json
import os
from pathlib import Path
from typing import List, Dict

from .models import ValidationResult
from .exceptions import FileValidationError


class FileValidator:
    """Validates files before upload to ensure compliance"""
    
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_EXTENSIONS = [".json"]
    
    def validate_file_size(self, file_path: str) -> ValidationResult:
        """Ensure file size is within limits"""
        try:
            if not os.path.exists(file_path):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"File not found: {file_path}",
                    file_path=file_path,
                    validation_type="existence"
                )
            
            file_size = os.path.getsize(file_path)
            
            if file_size > self.MAX_FILE_SIZE:
                size_mb = file_size / (1024 * 1024)
                max_mb = self.MAX_FILE_SIZE / (1024 * 1024)
                return ValidationResult(
                    is_valid=False,
                    error_message=f"File size {size_mb:.2f}MB exceeds maximum {max_mb}MB",
                    file_path=file_path,
                    validation_type="size"
                )
            
            return ValidationResult(is_valid=True)
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Error checking file size: {str(e)}",
                file_path=file_path,
                validation_type="size"
            )
    
    def validate_file_format(self, file_path: str) -> ValidationResult:
        """Verify file extension and basic format"""
        try:
            file_path_obj = Path(file_path)
            
            if file_path_obj.suffix.lower() not in self.ALLOWED_EXTENSIONS:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Invalid file extension. Allowed: {', '.join(self.ALLOWED_EXTENSIONS)}",
                    file_path=file_path,
                    validation_type="format"
                )
            
            return ValidationResult(is_valid=True)
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Error checking file format: {str(e)}",
                file_path=file_path,
                validation_type="format"
            )
    
    def validate_json_structure(self, file_path: str) -> ValidationResult:
        """Validate JSON syntax and basic structure"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if file is empty
            if not content.strip():
                return ValidationResult(
                    is_valid=False,
                    error_message="File is empty",
                    file_path=file_path,
                    validation_type="json_structure"
                )
            
            # Parse JSON to validate syntax
            try:
                json_data = json.loads(content)
            except json.JSONDecodeError as e:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Invalid JSON syntax: {str(e)}",
                    file_path=file_path,
                    validation_type="json_structure"
                )
            
            # Basic structure validation - ensure it's not just a primitive value
            if not isinstance(json_data, (dict, list)):
                return ValidationResult(
                    is_valid=False,
                    error_message="JSON must be an object or array",
                    file_path=file_path,
                    validation_type="json_structure"
                )
            
            return ValidationResult(is_valid=True)
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Error validating JSON structure: {str(e)}",
                file_path=file_path,
                validation_type="json_structure"
            )
    
    def validate_single_file(self, file_path: str) -> ValidationResult:
        """Comprehensive validation of a single file"""
        # Check file existence and size
        size_result = self.validate_file_size(file_path)
        if not size_result.is_valid:
            return size_result
        
        # Check file format
        format_result = self.validate_file_format(file_path)
        if not format_result.is_valid:
            return format_result
        
        # Check JSON structure for .json files
        if file_path.lower().endswith('.json'):
            json_result = self.validate_json_structure(file_path)
            if not json_result.is_valid:
                return json_result
        
        return ValidationResult(is_valid=True)
    
    def validate_all_files(self, files: Dict[str, str]) -> ValidationResult:
        """Pre-upload validation of all files"""
        errors = []
        valid_files = {}
        
        for upload_name, file_path in files.items():
            result = self.validate_single_file(file_path)
            
            if result.is_valid:
                valid_files[upload_name] = file_path
            else:
                errors.append(f"{upload_name}: {result.error_message}")
        
        if errors:
            return ValidationResult(
                is_valid=False,
                error_message=f"File validation failed: {'; '.join(errors)}",
                validation_type="batch_validation"
            )
        
        if not valid_files:
            return ValidationResult(
                is_valid=False,
                error_message="No valid files found for upload",
                validation_type="batch_validation"
            )
        
        return ValidationResult(is_valid=True)
    
    def get_file_summary(self, file_path: str) -> Dict:
        """Get summary information about a file"""
        try:
            if not os.path.exists(file_path):
                return {
                    "exists": False,
                    "error": "File not found"
                }
            
            stat = os.stat(file_path)
            file_path_obj = Path(file_path)
            
            summary = {
                "exists": True,
                "size_bytes": stat.st_size,
                "size_mb": stat.st_size / (1024 * 1024),
                "extension": file_path_obj.suffix,
                "name": file_path_obj.name,
                "modified_time": stat.st_mtime,
                "is_valid_size": stat.st_size <= self.MAX_FILE_SIZE,
                "is_valid_format": file_path_obj.suffix.lower() in self.ALLOWED_EXTENSIONS
            }
            
            # Add JSON validation info for JSON files
            if file_path_obj.suffix.lower() == '.json':
                json_result = self.validate_json_structure(file_path)
                summary["is_valid_json"] = json_result.is_valid
                if not json_result.is_valid:
                    summary["json_error"] = json_result.error_message
            
            return summary
            
        except Exception as e:
            return {
                "exists": False,
                "error": f"Error reading file: {str(e)}"
            }
    
    def filter_valid_files(self, files: Dict[str, str]) -> Dict[str, str]:
        """Filter and return only valid files"""
        valid_files = {}
        
        for upload_name, file_path in files.items():
            result = self.validate_single_file(file_path)
            if result.is_valid:
                valid_files[upload_name] = file_path
        
        return valid_files