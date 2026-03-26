use crate::config::types::{OutputIntegrity, Result};
use std::io::{BufReader, Read};
use std::process::{ChildStderr, ChildStdout};
use std::sync::mpsc::{channel, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct OutputLimits {
    pub combined_limit: usize,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub collection_timeout_ms: u64,
}

impl Default for OutputLimits {
    fn default() -> Self {
        OutputLimits {
            combined_limit: 10 * 1024 * 1024,
            stdout_limit: 8 * 1024 * 1024,
            stderr_limit: 2 * 1024 * 1024,
            collection_timeout_ms: 5000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutputResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_integrity: OutputIntegrity,
    pub stderr_integrity: OutputIntegrity,
    pub combined_integrity: OutputIntegrity,
    pub total_bytes: usize,
}

pub struct OutputCollector {
    limits: OutputLimits,
}

impl OutputCollector {
    pub fn new(limits: OutputLimits) -> Self {
        OutputCollector { limits }
    }

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

        let stdout_handle = stdout
            .map(|stdout| thread::spawn(move || collect_stream(stdout, stdout_limit, stdout_tx)));

        let stderr_handle = stderr
            .map(|stderr| thread::spawn(move || collect_stream(stderr, stderr_limit, stderr_tx)));

        let timeout = Duration::from_millis(self.limits.collection_timeout_ms);
        let start = Instant::now();

        let mut stdout_data = Vec::new();
        let mut stderr_data = Vec::new();
        let mut stdout_integrity = OutputIntegrity::Complete;
        let mut stderr_integrity = OutputIntegrity::Complete;
        let mut combined_truncated = false;
        let mut stdout_received = stdout_handle.is_none();
        let mut stderr_received = stderr_handle.is_none();

        loop {
            if start.elapsed() > timeout {
                stdout_integrity = OutputIntegrity::TruncatedByJudgeLimit;
                stderr_integrity = OutputIntegrity::TruncatedByJudgeLimit;
                break;
            }

            match stdout_rx.try_recv() {
                Ok((data, integrity)) => {
                    stdout_data = data;
                    stdout_integrity = integrity;
                    stdout_received = true;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    stdout_received = true;
                }
            }

            match stderr_rx.try_recv() {
                Ok((data, integrity)) => {
                    stderr_data = data;
                    stderr_integrity = integrity;
                    stderr_received = true;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    stderr_received = true;
                }
            }

            if stdout_received && stderr_received {
                break;
            }

            thread::sleep(Duration::from_millis(10));
        }

        if let Some(handle) = stdout_handle {
            let _ = handle.join();
        }
        if let Some(handle) = stderr_handle {
            let _ = handle.join();
        }

        let total_bytes = stdout_data.len() + stderr_data.len();
        if total_bytes > combined_limit {
            combined_truncated = true;

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

        let combined_integrity = if combined_truncated {
            OutputIntegrity::TruncatedByJudgeLimit
        } else {
            OutputIntegrity::resolve_combined(&stdout_integrity, &stderr_integrity)
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
                break;
            }
            Ok(n) => {
                if buffer.len() + n > limit {
                    let remaining = limit - buffer.len();
                    buffer.extend_from_slice(&chunk[..remaining]);
                    integrity = OutputIntegrity::TruncatedByJudgeLimit;
                    break;
                } else {
                    buffer.extend_from_slice(&chunk[..n]);
                }
            }
            Err(e) => {
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
            collection_timeout_ms: 100,
        };

        let collector = OutputCollector::new(limits);

        let result = collector
            .collect(None, None)
            .expect("Failed to collect output");

        assert_eq!(result.stdout.len(), 0);
        assert_eq!(result.stderr.len(), 0);
        assert_eq!(result.combined_integrity, OutputIntegrity::Complete);
    }

    #[test]
    fn test_output_integrity_display() {
        assert_eq!(format!("{}", OutputIntegrity::Complete), "complete");
        assert_eq!(
            format!("{}", OutputIntegrity::TruncatedByJudgeLimit),
            "truncated_by_judge_limit"
        );
        assert_eq!(
            format!("{}", OutputIntegrity::TruncatedByProgramClose),
            "truncated_by_program_close"
        );
        assert_eq!(
            format!("{}", OutputIntegrity::CrashMidWrite),
            "crash_mid_write"
        );
        assert_eq!(format!("{}", OutputIntegrity::WriteError), "write_error");
    }
}
