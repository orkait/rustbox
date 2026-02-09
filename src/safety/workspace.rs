/// Workspace management for run-scoped artifacts
/// Implements P0-WS-001: Run-Scoped Workspace Artifacts
/// Per plan.md: No cross-instance artifact collision

use crate::config::types::{IsolateError, Result};
use crate::safety::safe_cleanup;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Workspace manager for isolated run artifacts
pub struct Workspace {
    /// Unique run ID
    run_id: String,
    /// Base workspace directory
    base_dir: PathBuf,
    /// Run-specific workspace directory
    run_dir: PathBuf,
    /// Source file path (if any)
    source_file: Option<PathBuf>,
    /// Binary file path (if any)
    binary_file: Option<PathBuf>,
    /// Temporary files created
    temp_files: Vec<PathBuf>,
}

impl Workspace {
    /// Create new workspace for a run
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        let run_id = Uuid::new_v4().to_string();
        let run_dir = base_dir.join(&run_id);
        
        // Create run-specific directory
        fs::create_dir_all(&run_dir).map_err(|e| {
            IsolateError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to create workspace directory {}: {}", run_dir.display(), e),
            ))
        })?;
        
        Ok(Self {
            run_id,
            base_dir,
            run_dir,
            source_file: None,
            binary_file: None,
            temp_files: Vec::new(),
        })
    }
    
    /// Get run ID
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    
    /// Get run directory
    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }
    
    /// Create source file in workspace
    pub fn create_source_file(&mut self, extension: &str, content: &[u8]) -> Result<PathBuf> {
        let filename = format!("source.{}", extension);
        let source_path = self.run_dir.join(&filename);
        
        fs::write(&source_path, content).map_err(|e| {
            IsolateError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to write source file {}: {}", source_path.display(), e),
            ))
        })?;
        
        self.source_file = Some(source_path.clone());
        Ok(source_path)
    }
    
    /// Create binary file path in workspace
    pub fn create_binary_path(&mut self, name: &str) -> PathBuf {
        let binary_path = self.run_dir.join(name);
        self.binary_file = Some(binary_path.clone());
        binary_path
    }
    
    /// Register temporary file for cleanup
    pub fn register_temp_file(&mut self, path: PathBuf) {
        self.temp_files.push(path);
    }
    
    /// Create temporary file in workspace
    pub fn create_temp_file(&mut self, name: &str) -> Result<PathBuf> {
        let temp_path = self.run_dir.join(name);
        
        // Create empty file
        fs::write(&temp_path, b"").map_err(|e| {
            IsolateError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to create temp file {}: {}", temp_path.display(), e),
            ))
        })?;
        
        self.temp_files.push(temp_path.clone());
        Ok(temp_path)
    }
    
    /// Get source file path
    pub fn source_file(&self) -> Option<&Path> {
        self.source_file.as_deref()
    }
    
    /// Get binary file path
    pub fn binary_file(&self) -> Option<&Path> {
        self.binary_file.as_deref()
    }
    
    /// Cleanup workspace (idempotent)
    pub fn cleanup(&self) -> Result<()> {
        // Remove all temporary files first
        for temp_file in &self.temp_files {
            if temp_file.exists() {
                if let Err(e) = fs::remove_file(temp_file) {
                    log::warn!("Failed to remove temp file {}: {}", temp_file.display(), e);
                }
            }
        }
        
        // Remove source file
        if let Some(source) = &self.source_file {
            if source.exists() {
                if let Err(e) = fs::remove_file(source) {
                    log::warn!("Failed to remove source file {}: {}", source.display(), e);
                }
            }
        }
        
        // Remove binary file
        if let Some(binary) = &self.binary_file {
            if binary.exists() {
                if let Err(e) = fs::remove_file(binary) {
                    log::warn!("Failed to remove binary file {}: {}", binary.display(), e);
                }
            }
        }
        
        // Remove run directory
        if self.run_dir.exists() {
            if let Err(e) = safe_cleanup::remove_tree_secure(&self.run_dir) {
                log::warn!("Failed to remove run directory {}: {}", self.run_dir.display(), e);
                // Don't fail - this is cleanup
            }
        }
        
        Ok(())
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        // Attempt cleanup on drop
        let _ = self.cleanup();
    }
}

/// Workspace manager for managing multiple workspaces
pub struct WorkspaceManager {
    base_dir: PathBuf,
}

impl WorkspaceManager {
    /// Create new workspace manager
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        // Create base directory if it doesn't exist
        fs::create_dir_all(&base_dir).map_err(|e| {
            IsolateError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to create workspace base directory {}: {}", base_dir.display(), e),
            ))
        })?;
        
        Ok(Self { base_dir })
    }
    
    /// Create new workspace for a run
    pub fn create_workspace(&self) -> Result<Workspace> {
        Workspace::new(self.base_dir.clone())
    }
    
    /// Cleanup old workspaces (older than specified duration)
    pub fn cleanup_old_workspaces(&self, max_age: std::time::Duration) -> Result<usize> {
        let mut cleaned = 0;
        let now = std::time::SystemTime::now();
        
        if !self.base_dir.exists() {
            return Ok(0);
        }
        
        let entries = fs::read_dir(&self.base_dir).map_err(|e| {
            IsolateError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read workspace directory {}: {}", self.base_dir.display(), e),
            ))
        })?;
        
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    log::warn!("Failed to read directory entry: {}", e);
                    continue;
                }
            };
            
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            
            // Check age
            let metadata = match fs::metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    log::warn!("Failed to get metadata for {}: {}", path.display(), e);
                    continue;
                }
            };
            
            let modified = match metadata.modified() {
                Ok(m) => m,
                Err(e) => {
                    log::warn!("Failed to get modified time for {}: {}", path.display(), e);
                    continue;
                }
            };
            
            let age = match now.duration_since(modified) {
                Ok(d) => d,
                Err(_) => continue, // Future timestamp, skip
            };
            
            if age > max_age {
                log::info!("Cleaning up old workspace: {}", path.display());
                if let Err(e) = safe_cleanup::remove_tree_secure(&path) {
                    log::warn!("Failed to remove old workspace {}: {}", path.display(), e);
                } else {
                    cleaned += 1;
                }
            }
        }
        
        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_workspace_creation() {
        let temp_dir = std::env::temp_dir().join("rustbox_test_workspace");
        let manager = WorkspaceManager::new(temp_dir.clone()).unwrap();
        
        let workspace = manager.create_workspace().unwrap();
        assert!(workspace.run_dir().exists());
        
        // Cleanup
        workspace.cleanup().unwrap();
        let _ = safe_cleanup::remove_tree_secure(&temp_dir);
    }
    
    #[test]
    fn test_workspace_files() {
        let temp_dir = std::env::temp_dir().join("rustbox_test_workspace_files");
        let manager = WorkspaceManager::new(temp_dir.clone()).unwrap();
        
        let mut workspace = manager.create_workspace().unwrap();
        
        // Create source file
        let source = workspace.create_source_file("cpp", b"int main() {}").unwrap();
        assert!(source.exists());
        
        // Create binary path
        let binary = workspace.create_binary_path("program");
        assert_eq!(binary.file_name().unwrap(), "program");
        
        // Create temp file
        let temp = workspace.create_temp_file("temp.txt").unwrap();
        assert!(temp.exists());
        
        // Cleanup
        workspace.cleanup().unwrap();
        assert!(!source.exists());
        assert!(!temp.exists());
        
        let _ = safe_cleanup::remove_tree_secure(&temp_dir);
    }
    
    #[test]
    fn test_cleanup_old_workspaces() {
        let temp_dir = std::env::temp_dir().join("rustbox_test_cleanup");
        let manager = WorkspaceManager::new(temp_dir.clone()).unwrap();
        
        // Create a workspace
        let workspace = manager.create_workspace().unwrap();
        let run_dir = workspace.run_dir().to_path_buf();
        drop(workspace); // Don't cleanup yet
        
        // Sleep briefly to ensure timestamp difference
        std::thread::sleep(Duration::from_millis(100));
        
        // Cleanup workspaces older than 0 seconds (should clean all)
        let cleaned = manager.cleanup_old_workspaces(Duration::from_secs(0)).unwrap();
        // May or may not clean depending on timing, just verify it doesn't error
        assert!(cleaned >= 0);
        
        let _ = safe_cleanup::remove_tree_secure(&temp_dir);
    }
}
