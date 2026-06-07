use std::fs::OpenOptions;
use std::io::Write;
use std::time::SystemTime;

/// Gets a timezone-local formatted timestamp string using libc localtime_r
pub fn get_timestamp_string() -> String {
    unsafe {
        let mut time_val: libc::time_t = libc::time(std::ptr::null_mut());
        if time_val == -1 {
            // Fallback to simple duration string if libc::time fails
            if let Ok(d) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                return format!("Epoch Secs: {}", d.as_secs());
            }
            return "unknown".to_string();
        }
        let mut tm_struct = std::mem::zeroed::<libc::tm>();
        if libc::localtime_r(&time_val, &mut tm_struct).is_null() {
            return "unknown".to_string();
        }
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            tm_struct.tm_year + 1900,
            tm_struct.tm_mon + 1,
            tm_struct.tm_mday,
            tm_struct.tm_hour,
            tm_struct.tm_min,
            tm_struct.tm_sec
        )
    }
}

/// Identifies the executing user, inspecting SUDO_USER and DOAS_USER env variables first,
/// then falling back to libc getpwuid for the real UID.
pub fn get_current_user() -> String {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() {
            return sudo_user;
        }
    }
    if let Ok(doas_user) = std::env::var("DOAS_USER") {
        if !doas_user.is_empty() {
            return doas_user;
        }
    }
    unsafe {
        let uid = libc::getuid();
        let pwd = libc::getpwuid(uid);
        if !pwd.is_null() {
            let c_str = std::ffi::CStr::from_ptr((*pwd).pw_name);
            if let Ok(name) = c_str.to_str() {
                return name.to_string();
            }
        }
    }
    "root".to_string()
}

pub struct Logger {
    log_path: String,
}

impl Logger {
    pub fn new(path: &str) -> Self {
        Self {
            log_path: path.to_string(),
        }
    }

    pub fn log_action(&self, backend: &str, action: &str, details: &str) -> Result<(), std::io::Error> {
        let timestamp = get_timestamp_string();
        let user = get_current_user();
        let log_line = format!(
            "[{}] [USER: {}] [BACKEND: {}] [ACTION: {}] {}\n",
            timestamp, user, backend, action, details
        );
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        file.write_all(log_line.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::thread;

    #[test]
    fn test_timestamp_not_empty() {
        let ts = get_timestamp_string();
        assert!(!ts.is_empty());
    }

    #[test]
    fn test_concurrent_logging() {
        let test_log = "./test_concurrent_nsmam.log";
        // Clean up any previous run
        let _ = fs::remove_file(test_log);
        
        let logger = std::sync::Arc::new(Logger::new(test_log));
        let mut handles = vec![];

        for i in 0..10 {
            let logger_clone = logger.clone();
            let handle = thread::spawn(move || {
                for j in 0..5 {
                    assert!(logger_clone.log_action("mock", "test_action", &format!("thread {} msg {}", i, j)).is_ok());
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let content = fs::read_to_string(test_log).unwrap();
        let lines: Vec<&str> = content.trim().split('\n').collect();
        assert_eq!(lines.len(), 50);

        let _ = fs::remove_file(test_log);
    }
}
