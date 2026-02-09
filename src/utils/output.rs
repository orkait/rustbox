/// Output Boundaries and Collector Robustness
/// Implements P1-IO-001: Output Boundaries and Collector Robustness
/// Implements P1-IO-002: Output Integrity Classification
/// Per plan.md Section 12: Output, FD, and Environment Hygiene

use crate::config::types::{Result, OutputIntegrity};
use std::io::{Read, BufReader};
use std::process::{ChildStdout, ChildStderr};
use std::sync::mpsc::{channel, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

/// Output limits configuration
#[derive(Debug, Clone)]
pub struct OutputLimits {
    /// Combined stdout+stderr limit (bytes)
    pub combined_limit: usize,
    /// Per-stream stdout limit (bytes)
    pub stdout_limit: usize,
    /// Per-stream stderr limit (bytes)
    pub stderr_limit: usize,
    /// Collection timeout (milliseconds)
    pub collection_timeout_ms: u64,
}

impl Default for OutputLimits {
    fn default() -> Self {
        OutputLimits {
            combined_limit: 10 * 1024 * 1024, // 10 MB combined
            stdout_limit: 8 * 1024 * 1024,    // 8 MB stdout
            stderr_limit: 2 * 1024 * 1024,    // 2 MB stderr
            collection_timeout_ms: 5000,       // 5 seconds
        }
    }
}

/// Output collection result
#[derive(Debug, Clone)]
pub struct OutputResult {
    /// Collected stdout
    pub stdout: Vec<u8>,
    /// Collected stderr
    pub stderr: Vec<u8>,
    /// Stdout integrity state
    pub stdout_integrity: OutputIntegrity,
    /// Stderr integrity state
    pub stderr_integrity: OutputIntegrity,
    /// Combined integrity state
    pub combined_integrity: OutputIntegrity,
    /// Total bytes collected
    pub total_bytes: usize,
}

/// Output collector with bounded collection
pub struct OutputCollector {
    limits: OutputLimits,
}

impl OutputCollector {
    /// Create new output collector with limits
    pub fn new(limits: OutputLimits) -> Self {
        OutputCollector { limits }
    }
    
    /// Collect output from child process with bounded limits
    /// Returns (stdout, stderr, integrity_state)
    pub fn collect(
        &self,
        stdout: Option<ChildStdout>,
        stderr: Option<ChildStderr>,
    ) -> Result<OutputResult> {
        let (stdout_tx, stdout_rx) = channel();
        let (stderr_tx, stderr_rx) = channel();
        
        let stdout_limit = self.limits.stdout_limit;
        let stderr_limit = self.limits.stderr_limit;
        let combined_limit = self.limits.combined_limit;
        
        // Spawn stdout collector thread
        let stdout_handle = if let Some(stdout) = stdout {
            Some(thread::spawn(move || {
                collect_stream(stdout, stdout_limit, stdout_tx)
            }))
        } else {
            None
        };
        
        // Spawn stderr collector thread
        let stderr_handle = if let Some(stderr) = stderr {
            Some(thread::spawn(move || {
                collect_stream(stderr, stderr_limit, stderr_tx)
            }))
        } else {
            None
        };
        
        // Collect with timeout
        let timeout = Duration::from_millis(self.limits.collection_timeout_ms);
        let start = Instant::now();
        
        let mut stdout_data = Vec::new();
        let mut stderr_data = Vec::new();
        let mut stdout_integrity = OutputIntegrity::Complete;
        let mut stderr_integrity = OutputIntegrity::Complete;
        let mut combined_truncated = false;
        
        // Wait for collectors with timeout
        loop {
            if start.elapsed() > timeout {
                stdout_integrity = OutputIntegrity::TruncatedByJudgeLimit;
                stderr_integrity = OutputIntegrity::TruncatedByJudgeLimit;
                break;
            }
            
            // Try to receive from stdout
            match stdout_rx.try_recv() {
                Ok((data, integrity)) => {
                    stdout_data = data;
                    stdout_integrity = integrity;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {}
            }
            
            // Try to receive from stderr
            match stderr_rx.try_recv() {
                Ok((data, integrity)) => {
                    stderr_data = data;
                    stderr_integrity = integrity;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {}
            }
            
            // Check if both collectors finished
            let stdout_done = stdout_handle.is_none() || 
                matches!(stdout_integrity, OutputIntegrity::Complete | 
                         OutputIntegrity::TruncatedByJudgeLimit |
                         OutputIntegrity::TruncatedByProgramClose |
                         OutputIntegrity::CrashMidWrite |
                         OutputIntegrity::WriteError);
            
            let stderr_done = stderr_handle.is_none() || 
                matches!(stderr_integrity, OutputIntegrity::Complete | 
                         OutputIntegrity::TruncatedByJudgeLimit |
                         OutputIntegrity::TruncatedByProgramClose |
                         OutputIntegrity::CrashMidWrite |
                         OutputIntegrity::WriteError);
            
            if stdout_done && stderr_done {
                break;
            }
            
            thread::sleep(Duration::from_millis(10));
        }
        
        // Join threads
        if let Some(handle) = stdout_handle {
            let _ = handle.join();
        }
        if let Some(handle) = stderr_handle {
            let _ = handle.join();
        }
        
        // Check combined limit
        let total_bytes = stdout_data.len() + stderr_data.len();
        if total_bytes > combined_limit {
            combined_truncated = true;
            
            // Truncate to combined limit (prefer stdout)
            if stdout_data.len() > combined_limit {
                stdout_data.truncate(combined_limit);
                stderr_data.clear();
                stdout_integrity = OutputIntegrity::TruncatedByJudgeLimit;
                stderr_integrity = OutputIntegrity::TruncatedByJudgeLimit;
            } else {
                let remaining = combined_limit - stdout_data.len();
                stderr_data.truncate(remaining);
                stderr_integrity = OutputIntegrity::TruncatedByJudgeLimit;
            }
        }
        
        // Determine combined integrity
        let combined_integrity = if combined_truncated {
            OutputIntegrity::TruncatedByJudgeLimit
        } else if matches!(stdout_integrity, OutputIntegrity::CrashMidWrite) ||
                  matches!(stderr_integrity, OutputIntegrity::CrashMidWrite) {
            OutputIntegrity::CrashMidWrite
        } else if matches!(stdout_integrity, OutputIntegrity::WriteError) ||
                  matches!(stderr_integrity, OutputIntegrity::WriteError) {
            OutputIntegrity::WriteError
        } else if matches!(stdout_integrity, OutputIntegrity::TruncatedByJudgeLimit) ||
                  matches!(stderr_integrity, OutputIntegrity::TruncatedByJudgeLimit) {
            OutputIntegrity::TruncatedByJudgeLimit
        } else if matches!(stdout_integrity, OutputIntegrity::TruncatedByProgramClose) ||
                  matches!(stderr_integrity, OutputIntegrity::TruncatedByProgramClose) {
            OutputIntegrity::TruncatedByProgramClose
        } else {
            OutputIntegrity::Complete
        };
        
        Ok(OutputResult {
            stdout: stdout_data,
            stderr: stderr_data,
            stdout_integrity,
            stderr_integrity,
            combined_integrity,
            total_bytes,
        })
    }
}

/// Collect from a single stream with limit
fn collect_stream<R: Read + Send + 'static>(
    stream: R,
    limit: usize,
    tx: Sender<(Vec<u8>, OutputIntegrity)>,
) {
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut integrity = OutputIntegrity::Complete;
    
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => {
                // EOF - normal completion
                break;
            }
            Ok(n) => {
                if buffer.len() + n > limit {
                    // Hit limit - truncate
                    let remaining = limit - buffer.len();
                    buffer.extend_from_slice(&chunk[..remaining]);
                    integrity = OutputIntegrity::TruncatedByJudgeLimit;
                    break;
                } else {
                    buffer.extend_from_slice(&chunk[..n]);
                }
            }
            Err(e) => {
                // Read error
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    integrity = OutputIntegrity::TruncatedByProgramClose;
                } else {
                    integrity = OutputIntegrity::WriteError;
                }
                break;
            }
        }
    }
    
    let _ = tx.send((buffer, integrity));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_limits_default() {
        let limits = OutputLimits::default();
        assert_eq!(limits.combined_limit, 10 * 1024 * 1024);
        assert_eq!(limits.stdout_limit, 8 * 1024 * 1024);
        assert_eq!(limits.stderr_limit, 2 * 1024 * 1024);
    }

    #[test]
    fn test_output_collector_creation() {
        let limits = OutputLimits::default();
        let collector = OutputCollector::new(limits);
        assert_eq!(collector.limits.combined_limit, 10 * 1024 * 1024);
    }

    #[test]
    fn test_output_collector_small_output() {
        let limits = OutputLimits {
            combined_limit: 1024,
            stdout_limit: 512,
            stderr_limit: 512,
            collection_timeout_ms: 100, // Short timeout for test
        };
        
        let collector = OutputCollector::new(limits);
        
        // Test with no output (None streams)
        let result = collector.collect(None, None).expect("Failed to collect output");
        
        // Should complete successfully with empty output
        assert_eq!(result.stdout.len(), 0);
        assert_eq!(result.stderr.len(), 0);
        assert_eq!(result.combined_integrity, OutputIntegrity::Complete);
    }

    #[test]
    fn test_output_integrity_display() {
        assert_eq!(format!("{}", OutputIntegrity::Complete), "complete");
        assert_eq!(format!("{}", OutputIntegrity::TruncatedByJudgeLimit), "truncated_by_judge_limit");
        assert_eq!(format!("{}", OutputIntegrity::TruncatedByProgramClose), "truncated_by_program_close");
        assert_eq!(format!("{}", OutputIntegrity::CrashMidWrite), "crash_mid_write");
        assert_eq!(format!("{}", OutputIntegrity::WriteError), "write_error");
    }
}
