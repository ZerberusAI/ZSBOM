"""
Tests for File Validator

Tests file validation functionality including size checks, format validation,
and JSON structure validation for upload files.
"""

import json
import os
import tempfile
import pytest
from pathlib import Path

from depclass.upload.file_validator import FileValidator


class TestFileValidator:
    """Test cases for file validation"""
    
    def setup_method(self):
        """Setup for each test"""
        self.validator = FileValidator()
    
    def test_validate_file_size_valid(self):
        """Test validation of file within size limits"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            f.write(b'{"test": "data"}')
            f.flush()
            
            try:
                result = self.validator.validate_file_size(f.name)
                assert result.is_valid == True
                assert result.error_message is None
            finally:
                os.unlink(f.name)
    
    def test_validate_file_size_too_large(self):
        """Test validation of oversized file"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            # Write 6MB of data (exceeds 5MB limit)
            large_data = b'x' * (6 * 1024 * 1024)
            f.write(large_data)
            f.flush()
            
            try:
                result = self.validator.validate_file_size(f.name)
                assert result.is_valid == False
                assert "exceeds maximum" in result.error_message
                assert "6.00MB" in result.error_message
            finally:
                os.unlink(f.name)
    
    def test_validate_file_size_not_found(self):
        """Test validation of non-existent file"""
        result = self.validator.validate_file_size("/non/existent/file.json")
        assert result.is_valid == False
        assert "File not found" in result.error_message
    
    def test_validate_file_format_valid_json(self):
        """Test validation of valid JSON file format"""
        with tempfile.NamedTemporaryFile(suffix='.json') as f:
            result = self.validator.validate_file_format(f.name)
            assert result.is_valid == True
    
    def test_validate_file_format_invalid_extension(self):
        """Test validation of invalid file extension"""
        with tempfile.NamedTemporaryFile(suffix='.txt') as f:
            result = self.validator.validate_file_format(f.name)
            assert result.is_valid == False
            assert "Invalid file extension" in result.error_message
            assert ".json" in result.error_message
    
    def test_validate_json_structure_valid(self):
        """Test validation of valid JSON structure"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"test": "data", "array": [1, 2, 3]}, f)
            f.flush()
            
            try:
                result = self.validator.validate_json_structure(f.name)
                assert result.is_valid == True
            finally:
                os.unlink(f.name)
    
    def test_validate_json_structure_empty_file(self):
        """Test validation of empty JSON file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("")
            f.flush()
            
            try:
                result = self.validator.validate_json_structure(f.name)
                assert result.is_valid == False
                assert "File is empty" in result.error_message
            finally:
                os.unlink(f.name)
    
    def test_validate_json_structure_invalid_syntax(self):
        """Test validation of invalid JSON syntax"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"invalid": json syntax}')
            f.flush()
            
            try:
                result = self.validator.validate_json_structure(f.name)
                assert result.is_valid == False
                assert "Invalid JSON syntax" in result.error_message
            finally:
                os.unlink(f.name)
    
    def test_validate_json_structure_primitive_value(self):
        """Test validation of JSON file with primitive value"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('"just a string"')
            f.flush()
            
            try:
                result = self.validator.validate_json_structure(f.name)
                assert result.is_valid == False
                assert "JSON must be an object or array" in result.error_message
            finally:
                os.unlink(f.name)
    
    def test_validate_single_file_comprehensive(self):
        """Test comprehensive validation of a single file"""
        # Create a valid test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"test": "data"}, f)
            f.flush()
            
            try:
                result = self.validator.validate_single_file(f.name)
                assert result.is_valid == True
            finally:
                os.unlink(f.name)
    
    def test_validate_single_file_multiple_issues(self):
        """Test validation of file with multiple issues"""
        # Create an oversized file with invalid extension
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            large_data = b'x' * (6 * 1024 * 1024)
            f.write(large_data)
            f.flush()
            
            try:
                result = self.validator.validate_single_file(f.name)
                assert result.is_valid == False
                # Should fail on first check (size), not get to format check
                assert "exceeds maximum" in result.error_message
            finally:
                os.unlink(f.name)
    
    def test_validate_all_files_success(self):
        """Test validation of multiple valid files"""
        files = {}
        temp_files = []
        
        try:
            # Create multiple valid test files
            for i, name in enumerate(['file1.json', 'file2.json']):
                f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
                json.dump({"test": f"data{i}"}, f)
                f.flush()
                files[name] = f.name
                temp_files.append(f.name)
            
            result = self.validator.validate_all_files(files)
            assert result.is_valid == True
            
        finally:
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except:
                    pass
    
    def test_validate_all_files_mixed_results(self):
        """Test validation with some valid and some invalid files"""
        files = {}
        temp_files = []
        
        try:
            # Create one valid file
            f1 = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump({"test": "data"}, f1)
            f1.flush()
            files['valid.json'] = f1.name
            temp_files.append(f1.name)
            
            # Create one invalid file (wrong extension)
            f2 = tempfile.NamedTemporaryFile(suffix='.txt', delete=False)
            f2.write(b'test data')
            f2.flush()
            files['invalid.json'] = f2.name
            temp_files.append(f2.name)
            
            result = self.validator.validate_all_files(files)
            assert result.is_valid == False
            assert "File validation failed" in result.error_message
            
        finally:
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except:
                    pass
    
    def test_validate_all_files_empty(self):
        """Test validation with no files"""
        result = self.validator.validate_all_files({})
        assert result.is_valid == False
        assert "No valid files found" in result.error_message
    
    def test_get_file_summary_valid(self):
        """Test file summary generation for valid file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"test": "data"}, f)
            f.flush()
            
            try:
                summary = self.validator.get_file_summary(f.name)
                
                assert summary["exists"] == True
                assert summary["size_bytes"] > 0
                assert summary["extension"] == ".json"
                assert summary["is_valid_size"] == True
                assert summary["is_valid_format"] == True
                assert summary["is_valid_json"] == True
                
            finally:
                os.unlink(f.name)
    
    def test_get_file_summary_not_found(self):
        """Test file summary for non-existent file"""
        summary = self.validator.get_file_summary("/non/existent/file.json")
        assert summary["exists"] == False
        assert "File not found" in summary["error"]
    
    def test_get_file_summary_invalid_json(self):
        """Test file summary for invalid JSON"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('invalid json')
            f.flush()
            
            try:
                summary = self.validator.get_file_summary(f.name)
                
                assert summary["exists"] == True
                assert summary["is_valid_json"] == False
                assert "json_error" in summary
                
            finally:
                os.unlink(f.name)
    
    def test_filter_valid_files(self):
        """Test filtering of valid files from mixed set"""
        files = {}
        temp_files = []
        
        try:
            # Create one valid file
            f1 = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump({"test": "data"}, f1)
            f1.flush()
            files['valid.json'] = f1.name
            temp_files.append(f1.name)
            
            # Create one invalid file
            f2 = tempfile.NamedTemporaryFile(suffix='.txt', delete=False)
            f2.write(b'test data')
            f2.flush()
            files['invalid.json'] = f2.name
            temp_files.append(f2.name)
            
            # Add non-existent file
            files['missing.json'] = '/non/existent/file.json'
            
            valid_files = self.validator.filter_valid_files(files)
            
            # Should only return the valid file
            assert len(valid_files) == 1
            assert 'valid.json' in valid_files
            assert 'invalid.json' not in valid_files
            assert 'missing.json' not in valid_files
            
        finally:
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except:
                    pass