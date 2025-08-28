"""
Performance Tracking Module for ZSBOM Metadata Collection

This module provides comprehensive performance monitoring and timing for ZSBOM pipeline stages,
following SOLID principles with extensible architecture.

Classes:
    PerformanceTracker: Main performance tracking orchestrator
    StageTimer: Individual stage timing management
    ResourceMonitor: System resource monitoring during execution
    PerformanceMetrics: Performance data aggregation and analysis
"""

import time
import psutil
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum


class StageStatus(Enum):
    """Enumeration of possible stage statuses."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class StageMetrics:
    """Data class for individual stage performance metrics."""
    name: str
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    status: StageStatus = StageStatus.NOT_STARTED
    memory_usage_mb: Optional[float] = None
    cpu_percent: Optional[float] = None
    error_message: Optional[str] = None
    custom_metrics: Dict[str, Any] = field(default_factory=dict)
    
    def mark_started(self):
        """Mark stage as started."""
        self.started_at = datetime.now(timezone.utc)
        self.status = StageStatus.IN_PROGRESS
    
    def mark_completed(self, duration: float):
        """Mark stage as completed."""
        self.ended_at = datetime.now(timezone.utc)
        self.duration_seconds = duration
        self.status = StageStatus.COMPLETED
    
    def mark_failed(self, duration: float, error: str):
        """Mark stage as failed."""
        self.ended_at = datetime.now(timezone.utc) 
        self.duration_seconds = duration
        self.status = StageStatus.FAILED
        self.error_message = error
    
    def mark_skipped(self):
        """Mark stage as skipped."""
        self.status = StageStatus.SKIPPED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "status": self.status.value,
            "memory_usage_mb": self.memory_usage_mb,
            "cpu_percent": self.cpu_percent,
            "error_message": self.error_message,
            "custom_metrics": self.custom_metrics
        }


class BaseResourceMonitor(ABC):
    """Abstract base class for resource monitoring."""
    
    @abstractmethod
    def start_monitoring(self):
        """Start resource monitoring."""
        pass
    
    @abstractmethod
    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return metrics."""
        pass
    
    @abstractmethod
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current resource metrics."""
        pass


class SystemResourceMonitor(BaseResourceMonitor):
    """System resource monitoring implementation."""
    
    def __init__(self, sample_interval: float = 1.0):
        self.sample_interval = sample_interval
        self.monitoring = False
        self.metrics_history = []
        self.monitor_thread = None
        self._lock = threading.Lock()
    
    def start_monitoring(self):
        """Start system resource monitoring."""
        with self._lock:
            if not self.monitoring:
                self.monitoring = True
                self.metrics_history = []
                self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
                self.monitor_thread.start()
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return aggregated metrics."""
        with self._lock:
            self.monitoring = False
            
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
        
        return self._aggregate_metrics()
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current system resource metrics."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            return {
                "memory_mb": memory_info.rss / 1024 / 1024,
                "memory_percent": process.memory_percent(),
                "cpu_percent": process.cpu_percent(),
                "num_threads": process.num_threads(),
                "timestamp": time.time()
            }
        except Exception as e:
            return {
                "error": str(e),
                "timestamp": time.time()
            }
    
    def _monitor_loop(self):
        """Background monitoring loop."""
        while self.monitoring:
            try:
                metrics = self.get_current_metrics()
                with self._lock:
                    self.metrics_history.append(metrics)
                time.sleep(self.sample_interval)
            except Exception:
                # Continue monitoring even if individual samples fail
                time.sleep(self.sample_interval)
    
    def _aggregate_metrics(self) -> Dict[str, Any]:
        """Aggregate collected metrics."""
        if not self.metrics_history:
            return {}
        
        try:
            valid_metrics = [m for m in self.metrics_history if "error" not in m]
            if not valid_metrics:
                return {"error": "No valid metrics collected"}
            
            memory_values = [m["memory_mb"] for m in valid_metrics]
            cpu_values = [m["cpu_percent"] for m in valid_metrics if m["cpu_percent"] is not None]
            
            return {
                "samples_collected": len(valid_metrics),
                "memory_mb": {
                    "avg": sum(memory_values) / len(memory_values),
                    "max": max(memory_values),
                    "min": min(memory_values)
                },
                "cpu_percent": {
                    "avg": sum(cpu_values) / len(cpu_values) if cpu_values else 0,
                    "max": max(cpu_values) if cpu_values else 0,
                    "min": min(cpu_values) if cpu_values else 0
                }
            }
        except Exception as e:
            return {"aggregation_error": str(e)}


class StageTimer:
    """Individual stage timing management."""
    
    def __init__(self, stage_name: str, resource_monitor: Optional[BaseResourceMonitor] = None):
        self.stage_name = stage_name
        self.resource_monitor = resource_monitor
        self.start_time = None
        self.end_time = None
        self._is_running = False
    
    def start(self):
        """Start timing the stage."""
        if self._is_running:
            raise RuntimeError(f"Stage '{self.stage_name}' timing already started")
        
        self.start_time = time.perf_counter()
        self._is_running = True
        
        if self.resource_monitor:
            self.resource_monitor.start_monitoring()
    
    def stop(self) -> float:
        """Stop timing and return duration in seconds."""
        if not self._is_running:
            raise RuntimeError(f"Stage '{self.stage_name}' timing not started")
        
        self.end_time = time.perf_counter()
        self._is_running = False
        duration = self.end_time - self.start_time
        
        if self.resource_monitor:
            self.resource_monitor.stop_monitoring()
        
        return duration
    
    def get_duration(self) -> Optional[float]:
        """Get current or final duration."""
        if self.start_time is None:
            return None
        
        end_time = self.end_time if self.end_time else time.perf_counter()
        return end_time - self.start_time
    
    def is_running(self) -> bool:
        """Check if timing is currently running."""
        return self._is_running


class PerformanceTracker:
    """Main performance tracking orchestrator following SOLID principles."""
    
    def __init__(self, enable_resource_monitoring: bool = True):
        self.enable_resource_monitoring = enable_resource_monitoring
        self.stages: Dict[str, StageMetrics] = {}
        self.active_timers: Dict[str, StageTimer] = {}
        self.overall_start_time = None
        self.overall_end_time = None
        self.resource_monitor = SystemResourceMonitor() if enable_resource_monitoring else None
    
    def start_overall_timing(self):
        """Start overall execution timing."""
        self.overall_start_time = time.perf_counter()
    
    def end_overall_timing(self):
        """End overall execution timing."""
        self.overall_end_time = time.perf_counter()
    
    def start_stage(self, stage_name: str, custom_metrics: Optional[Dict[str, Any]] = None):
        """Start timing a pipeline stage."""
        if stage_name in self.active_timers:
            raise RuntimeError(f"Stage '{stage_name}' is already being timed")
        
        # Create stage metrics
        stage_metrics = StageMetrics(
            name=stage_name,
            custom_metrics=custom_metrics or {}
        )
        stage_metrics.mark_started()
        self.stages[stage_name] = stage_metrics
        
        # Create and start timer
        monitor = SystemResourceMonitor() if self.enable_resource_monitoring else None
        timer = StageTimer(stage_name, monitor)
        timer.start()
        self.active_timers[stage_name] = timer
    
    def end_stage(self, stage_name: str, success: bool = True, error_message: Optional[str] = None):
        """End timing a pipeline stage."""
        if stage_name not in self.active_timers:
            raise RuntimeError(f"Stage '{stage_name}' timing was not started")
        
        timer = self.active_timers[stage_name]
        duration = timer.stop()
        
        # Update stage metrics
        stage_metrics = self.stages[stage_name]
        if success:
            stage_metrics.mark_completed(duration)
        else:
            stage_metrics.mark_failed(duration, error_message or "Unknown error")
        
        # Add resource metrics if available
        if timer.resource_monitor:
            resource_metrics = timer.resource_monitor.stop_monitoring()
            if "memory_mb" in resource_metrics:
                stage_metrics.memory_usage_mb = resource_metrics["memory_mb"].get("avg")
            if "cpu_percent" in resource_metrics:
                stage_metrics.cpu_percent = resource_metrics["cpu_percent"].get("avg")
        
        # Remove from active timers
        del self.active_timers[stage_name]
    
    def skip_stage(self, stage_name: str, reason: Optional[str] = None):
        """Mark a stage as skipped."""
        stage_metrics = StageMetrics(
            name=stage_name,
            custom_metrics={"skip_reason": reason} if reason else {}
        )
        stage_metrics.mark_skipped()
        self.stages[stage_name] = stage_metrics
    
    def get_stage_duration(self, stage_name: str) -> Optional[float]:
        """Get duration for a specific stage."""
        if stage_name in self.stages:
            return self.stages[stage_name].duration_seconds
        elif stage_name in self.active_timers:
            return self.active_timers[stage_name].get_duration()
        return None
    
    def get_overall_duration(self) -> Optional[float]:
        """Get overall execution duration."""
        if self.overall_start_time is None:
            return None
        
        end_time = self.overall_end_time if self.overall_end_time else time.perf_counter()
        return end_time - self.overall_start_time
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        summary = {
            "overall_duration_seconds": self.get_overall_duration(),
            "stages": {},
            "total_stages": len(self.stages),
            "completed_stages": len([s for s in self.stages.values() if s.status == StageStatus.COMPLETED]),
            "failed_stages": len([s for s in self.stages.values() if s.status == StageStatus.FAILED]),
            "skipped_stages": len([s for s in self.stages.values() if s.status == StageStatus.SKIPPED])
        }
        
        # Add individual stage metrics
        for stage_name, stage_metrics in self.stages.items():
            summary["stages"][stage_name] = stage_metrics.to_dict()
        
        # Add currently running stages
        for stage_name, timer in self.active_timers.items():
            summary["stages"][stage_name]["current_duration"] = timer.get_duration()
            summary["stages"][stage_name]["status"] = "in_progress"
        
        return summary
    
    def get_stage_metrics(self, stage_name: str) -> Optional[StageMetrics]:
        """Get metrics for a specific stage."""
        return self.stages.get(stage_name)
    
    def add_custom_metric(self, stage_name: str, metric_name: str, value: Any):
        """Add custom metric to a stage."""
        if stage_name in self.stages:
            self.stages[stage_name].custom_metrics[metric_name] = value
        elif stage_name in self.active_timers:
            # Add to metrics when stage is completed
            timer = self.active_timers[stage_name]
            if hasattr(timer, '_pending_custom_metrics'):
                timer._pending_custom_metrics[metric_name] = value
            else:
                timer._pending_custom_metrics = {metric_name: value}
    
    def cleanup_active_timers(self):
        """Clean up any active timers (for error scenarios)."""
        for stage_name in list(self.active_timers.keys()):
            try:
                self.end_stage(stage_name, success=False, error_message="Cleanup due to error")
            except Exception:
                # Force cleanup even if normal end fails
                del self.active_timers[stage_name]