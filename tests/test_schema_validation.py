"""
Schema validation tests for scan_metadata.json compliance with Phase 3 specification.

This module validates that generated metadata files conform to the exact schema
defined in the Phase 3 design document.
"""

import json
import tempfile
import os
from datetime import datetime
from pathlib import Path
import pytest

from depclass.metadata import MetadataCollector


class TestSchemaValidation:
    """Test suite for validating scan_metadata.json schema compliance."""
    
    def test_complete_schema_structure(self):
        """Test that metadata contains all required top-level keys."""
        config = {
            "output": {
                "sbom_file": "sbom.json",
                "risk_file": "risk_report.json",
                "dependencies_file": "dependencies.json",
                "report_file": "validation_report.json"
            }
        }
        
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Simulate minimal pipeline
        collector.track_stage_start("dependency_extraction")
        collector.track_stage_end("dependency_extraction", success=True)
        
        metadata = collector.finalize_metadata(exit_code=0)
        
        # Validate top-level structure matches Phase 3 schema
        required_keys = [
            "scan_id", "execution", "environment", "repository",
            "performance", "configuration", "outputs", "errors", "statistics"
        ]
        
        for key in required_keys:
            assert key in metadata, f"Missing required top-level key: {key}"
    
    def test_execution_section_schema(self):
        """Test execution section schema compliance."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        metadata = collector.finalize_metadata(exit_code=0)
        
        execution = metadata["execution"]
        required_execution_fields = [
            "started_at", "completed_at", "duration_seconds", "status", "exit_code"
        ]
        
        for field in required_execution_fields:
            assert field in execution, f"Missing execution field: {field}"
        
        # Validate field types and values
        assert isinstance(execution["started_at"], str)
        assert isinstance(execution["completed_at"], str)
        assert isinstance(execution["duration_seconds"], (int, float))
        assert execution["status"] in ["completed", "failed", "terminated"]
        assert isinstance(execution["exit_code"], int)
        
        # Validate ISO 8601 timestamp format
        try:
            datetime.fromisoformat(execution["started_at"].replace('Z', '+00:00'))
            datetime.fromisoformat(execution["completed_at"].replace('Z', '+00:00'))
        except ValueError:
            pytest.fail("Timestamps must be in ISO 8601 format")
    
    def test_environment_section_schema(self):
        """Test environment section schema compliance."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        metadata = collector.finalize_metadata(exit_code=0)
        
        environment = metadata["environment"]
        
        # Check for common environment fields
        expected_fields = ["os", "architecture", "python_version", "zsbom_version", "working_directory"]
        for field in expected_fields:
            assert field in environment, f"Missing environment field: {field}"
        
        # Validate field types
        assert isinstance(environment["os"], str)
        assert isinstance(environment["architecture"], str)
        assert isinstance(environment["python_version"], str)
        assert isinstance(environment["working_directory"], str)
    
    def test_repository_section_schema(self):
        """Test repository section schema compliance."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        metadata = collector.finalize_metadata(exit_code=0)
        
        repository = metadata["repository"]
        
        # Check for required repository fields
        expected_fields = ["detected_scm", "ci_environment"]
        for field in expected_fields:
            assert field in repository, f"Missing repository field: {field}"
        
        # Validate SCM detection
        scm = repository["detected_scm"]
        assert scm is None or isinstance(scm, str)
        
        # Validate CI environment
        ci_env = repository["ci_environment"]
        assert isinstance(ci_env, str)
    
    def test_performance_section_schema(self):
        """Test performance section schema compliance."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Simulate pipeline stages
        stages = ["dependency_extraction", "validation", "risk_assessment", "sbom_generation"]
        for stage in stages:
            collector.track_stage_start(stage)
            collector.track_stage_end(stage, success=True)
        
        metadata = collector.finalize_metadata(exit_code=0)
        performance = metadata["performance"]
        
        # Check for stage timing fields
        for stage in stages:
            timing_field = f"{stage}_seconds"
            if timing_field in performance:
                assert isinstance(performance[timing_field], (int, float))
                assert performance[timing_field] >= 0
        
        # Check for additional performance fields
        if "files_analyzed" in performance:
            assert isinstance(performance["files_analyzed"], list)
        
        if "total_packages_processed" in performance:
            assert isinstance(performance["total_packages_processed"], int)
    
    def test_configuration_section_schema(self):
        """Test configuration section schema compliance."""
        config = {
            "output": {"sbom_file": "test.json"},
            "ecosystem": "python",
            "ignore_conflicts": False,
            "validation_rules": {"enable_cve_check": True}
        }
        
        collector = MetadataCollector(config)
        collector.start_collection()
        metadata = collector.finalize_metadata(exit_code=0)
        
        configuration = metadata["configuration"]
        
        # Check for required configuration fields
        expected_fields = ["config_source", "ecosystem", "ignore_conflicts"]
        for field in expected_fields:
            assert field in configuration, f"Missing configuration field: {field}"
        
        # Validate field types and values
        assert configuration["config_source"] in ["user_provided", "auto_discovered", "default", "unknown"]
        assert isinstance(configuration["ecosystem"], str)
        assert isinstance(configuration["ignore_conflicts"], bool)
    
    def test_outputs_section_schema(self):
        """Test outputs section schema compliance."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Add some generated files
        collector.add_generated_file("test1.json")
        collector.add_generated_file("test2.json")
        
        metadata = collector.finalize_metadata(exit_code=0)
        outputs = metadata["outputs"]
        
        # Check for required output fields
        required_fields = ["generated_files", "file_sizes"]
        for field in required_fields:
            assert field in outputs, f"Missing outputs field: {field}"
        
        # Validate field types
        assert isinstance(outputs["generated_files"], list)
        assert isinstance(outputs["file_sizes"], dict)
        
        # Validate file list contains added files
        assert "test1.json" in outputs["generated_files"]
        assert "test2.json" in outputs["generated_files"]
    
    def test_errors_section_schema(self):
        """Test errors section schema compliance."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Add some errors
        collector.capture_error(ValueError("Test error"), "test_stage")
        collector.capture_message("Test warning", "test_stage")
        
        metadata = collector.finalize_metadata(exit_code=0)
        errors = metadata["errors"]
        
        # Validate errors is a list
        assert isinstance(errors, list)
        
        # Validate error record structure
        if errors:
            error = errors[0]
            required_error_fields = [
                "timestamp", "level", "stage", "category", "message"
            ]
            
            for field in required_error_fields:
                assert field in error, f"Missing error field: {field}"
            
            # Validate field types
            assert isinstance(error["timestamp"], str)
            assert error["level"] in ["critical", "error", "warning", "info"]
            assert isinstance(error["stage"], str)
            assert isinstance(error["message"], str)
            
            # Validate timestamp format
            try:
                datetime.fromisoformat(error["timestamp"].replace('Z', '+00:00'))
            except ValueError:
                pytest.fail("Error timestamp must be in ISO 8601 format")
    
    def test_statistics_section_schema(self):
        """Test statistics section schema compliance."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Add statistics
        collector.update_statistics({
            "total_dependencies": 100,
            "direct_dependencies": 25,
            "transitive_dependencies": 75,
            "vulnerabilities_found": 10,
            "critical_vulnerabilities": 2,
            "high_vulnerabilities": 3
        })
        
        metadata = collector.finalize_metadata(exit_code=0)
        statistics = metadata["statistics"]
        
        # Validate statistics is a dictionary
        assert isinstance(statistics, dict)
        
        # Check for common statistics fields
        common_fields = [
            "total_dependencies", "direct_dependencies", "transitive_dependencies",
            "vulnerabilities_found"
        ]
        
        for field in common_fields:
            if field in statistics:
                assert isinstance(statistics[field], int)
                assert statistics[field] >= 0
    
    def test_scan_id_format(self):
        """Test scan_id follows UUID format."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        metadata = collector.finalize_metadata(exit_code=0)
        
        scan_id = metadata["scan_id"]
        
        # Validate UUID format (36 characters with hyphens)
        assert isinstance(scan_id, str)
        assert len(scan_id) == 36
        assert scan_id.count('-') == 4
        
        # Validate UUID4 format pattern
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        import re
        assert re.match(uuid_pattern, scan_id), "scan_id must be a valid UUID4"
    
    def test_json_serializable(self):
        """Test that all metadata is JSON serializable."""
        config = {
            "output": {"sbom_file": "test.json"},
            "ecosystem": "python"
        }
        
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Add complex data
        collector.track_stage_start("test_stage")
        collector.track_stage_end("test_stage", success=True)
        collector.capture_error(Exception("Test"), "stage")
        collector.update_statistics({"test_stat": 42})
        
        metadata = collector.finalize_metadata(exit_code=0)
        
        # Test JSON serialization
        try:
            json_str = json.dumps(metadata, indent=2)
            # Test deserialization
            parsed_metadata = json.loads(json_str)
            assert parsed_metadata["scan_id"] == metadata["scan_id"]
        except (TypeError, ValueError) as e:
            pytest.fail(f"Metadata is not JSON serializable: {e}")
    
    def test_file_generation_and_content(self):
        """Test actual metadata file generation and content validation."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Simulate complete pipeline
        collector.track_stage_start("dependency_extraction")
        collector.track_stage_end("dependency_extraction", success=True)
        
        metadata = collector.finalize_metadata(exit_code=0)
        
        # Test file saving
        with tempfile.TemporaryDirectory() as temp_dir:
            metadata_file = os.path.join(temp_dir, "test_scan_metadata.json")
            collector.save_metadata_file(metadata, metadata_file)
            
            # Validate file exists and is readable
            assert os.path.exists(metadata_file)
            
            # Validate file content
            with open(metadata_file, 'r') as f:
                file_content = f.read()
                loaded_metadata = json.loads(file_content)
            
            # Validate content matches original metadata
            assert loaded_metadata["scan_id"] == metadata["scan_id"]
            assert loaded_metadata["execution"]["status"] == metadata["execution"]["status"]
            
            # Validate file is properly formatted JSON
            assert file_content.strip().startswith('{')
            assert file_content.strip().endswith('}')


class TestSchemaComplianceEdgeCases:
    """Test edge cases for schema compliance."""
    
    def test_metadata_with_minimal_data(self):
        """Test metadata generation with minimal data."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        
        # Don't start collection - test fallback
        metadata = collector.finalize_metadata(exit_code=1)
        
        # Should still have required structure
        required_keys = ["scan_id", "execution", "environment", "repository", 
                        "performance", "configuration", "outputs", "errors", "statistics"]
        
        for key in required_keys:
            assert key in metadata, f"Missing key in minimal metadata: {key}"
    
    def test_metadata_with_maximum_errors(self):
        """Test metadata with many errors (should be limited)."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Add many errors (more than the limit)
        for i in range(150):  # More than METADATA_CONFIG["max_error_records"]
            collector.capture_message(f"Error {i}", "test_stage")
        
        metadata = collector.finalize_metadata(exit_code=0)
        errors = metadata["errors"]
        
        # Should be limited to max_error_records (100)
        assert len(errors) <= 100
    
    def test_unicode_and_special_characters(self):
        """Test metadata with unicode and special characters."""
        config = {"output": {}}
        collector = MetadataCollector(config)
        collector.start_collection()
        
        # Add unicode content
        collector.capture_message("Unicode test: 🔥 ✅ 🚀 测试", "test_stage")
        collector.update_statistics({"special_chars": "Special chars: <>\"'&"})
        
        metadata = collector.finalize_metadata(exit_code=0)
        
        # Test JSON serialization with unicode
        try:
            json_str = json.dumps(metadata, ensure_ascii=False, indent=2)
            parsed = json.loads(json_str)
            assert "Unicode test: 🔥 ✅ 🚀 测试" in str(parsed)
        except Exception as e:
            pytest.fail(f"Unicode handling failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])