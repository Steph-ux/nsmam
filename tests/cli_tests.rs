use std::process::Command;

#[test]
fn test_non_root_exit_code() {
    #[cfg(unix)]
    {
        // Cargo automatically populates CARGO_BIN_EXE_<name> with the path to the compiled binary
        let bin_path = env!("CARGO_BIN_EXE_nsmam");
        
        let output = Command::new(bin_path)
            .output()
            .expect("Failed to execute nsmam binary");
        
        unsafe {
            if libc::geteuid() != 0 {
                assert_eq!(output.status.code(), Some(1));
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(stderr.contains("nsmam must be run as root/sudo"));
            }
        }
    }
}
