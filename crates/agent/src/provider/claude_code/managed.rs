//! Managed-settings posture for Claude Code containment.

use agentdesktop_core::model::ManagedSettingsSource;
use std::io;

/// Sources for managed settings (file tier and HKLM).
#[derive(Debug, Default)]
pub struct ManagedSources {
    pub hklm: Option<io::Result<String>>,
    pub file: Option<io::Result<String>>,
    pub drop_ins: Vec<(String, io::Result<String>)>,
}

/// Managed-settings posture snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManagedSettingsPosture {
    pub source: Option<ManagedSettingsSource>,
    pub hooks_locked: bool,
    pub mcp_locked: bool,
    pub error: Option<String>,
}

/// Models Windows: HKLM and the managed-settings file tier, Claude Code 2.1.273+.
/// Never reports a lock Claude Code does not apply; may report a lock as off where Claude Code fails closed.
pub fn managed_settings_state(_sources: &ManagedSources) -> ManagedSettingsPosture {
    todo!("managed_settings_state not yet implemented")
}

/// Read managed sources from the real file system and registry.
pub fn managed_sources_now() -> ManagedSources {
    todo!("managed_sources_now not yet implemented")
}

/// Read and compute the current managed-settings posture.
pub fn managed_posture_now() -> ManagedSettingsPosture {
    managed_settings_state(&managed_sources_now())
}

fn read_managed_sources(
    _root: Option<&std::path::Path>,
    _hklm: impl FnOnce() -> Option<io::Result<String>>,
) -> ManagedSources {
    todo!("read_managed_sources not yet implemented")
}

#[cfg(windows)]
fn read_hklm_settings(
    _hive: windows_sys::Win32::System::Registry::HKEY,
    _subkey: &str,
) -> Option<io::Result<String>> {
    todo!("read_hklm_settings not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure function tests for managed_settings_state (cases 1-15)

    #[test]
    fn test_managed_settings_state_none() {
        let sources = ManagedSources::default();
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, None);
        assert!(!posture.hooks_locked);
        assert!(!posture.mcp_locked);
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_file_only_with_both_locks() {
        let sources = ManagedSources {
            hklm: None,
            file: Some(Ok(r#"{"allowManagedHooksOnly":true,"allowManagedMcpServersOnly":true,"allowedMcpServers":[]}"#.to_owned())),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::File));
        assert!(posture.hooks_locked);
        assert!(posture.mcp_locked);
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_hklm_only_with_both_locks() {
        let sources = ManagedSources {
            hklm: Some(Ok(r#"{"allowManagedHooksOnly":true,"allowManagedMcpServersOnly":true,"allowedMcpServers":[]}"#.to_owned())),
            file: None,
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::Hklm));
        assert!(posture.hooks_locked);
        assert!(posture.mcp_locked);
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_both_present_first_wins_selects_hklm() {
        let sources = ManagedSources {
            hklm: Some(Ok(r#"{"model":"claude-3-5-sonnet"}"#.to_owned())),
            file: Some(Ok(r#"{"allowManagedHooksOnly":true}"#.to_owned())),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::Hklm));
        assert!(!posture.hooks_locked); // HKLM selected, doesn't have hooks lock
        assert!(!posture.mcp_locked);
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_file_with_locks_hklm_without_locks() {
        let sources = ManagedSources {
            hklm: Some(Ok(r#"{"model":"claude-3-5-sonnet"}"#.to_owned())),
            file: Some(Ok(r#"{"allowManagedHooksOnly":true,"allowManagedMcpServersOnly":true,"allowedMcpServers":[]}"#.to_owned())),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::Hklm));
        assert!(!posture.hooks_locked); // from selected source (HKLM), which doesn't have the lock
        assert!(posture.mcp_locked); // cross-source: flag and list from file
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_merge_mode_with_locks_in_both() {
        let sources = ManagedSources {
            hklm: Some(Ok(
                r#"{"managedSourcesBehavior":"merge","allowManagedHooksOnly":true}"#.to_owned(),
            )),
            file: Some(Ok(
                r#"{"allowManagedMcpServersOnly":true,"allowedMcpServers":[]}"#.to_owned(),
            )),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::Hklm));
        assert!(posture.hooks_locked); // strictest under merge
        assert!(posture.mcp_locked); // cross-source
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_one_lock_only() {
        let sources = ManagedSources {
            hklm: None,
            file: Some(Ok(r#"{"allowManagedMcpServersOnly":true}"#.to_owned())),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::File));
        assert!(!posture.hooks_locked);
        assert!(!posture.mcp_locked); // flag present but no allowedMcpServers list
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_policy_helper_present() {
        let sources = ManagedSources {
            hklm: None,
            file: Some(Ok(r#"{"policyHelper":"/usr/bin/helper","allowManagedHooksOnly":true,"allowManagedMcpServersOnly":true,"allowedMcpServers":[]}"#.to_owned())),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::File));
        assert!(!posture.hooks_locked); // policyHelper present, so both locks false
        assert!(!posture.mcp_locked);
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_allowed_mcp_servers_empty_array() {
        let sources = ManagedSources {
            hklm: None,
            file: Some(Ok(
                r#"{"allowManagedMcpServersOnly":true,"allowedMcpServers":[]}"#.to_owned(),
            )),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::File));
        assert!(!posture.hooks_locked);
        assert!(posture.mcp_locked); // empty array still counts as having the list
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_hklm_control_keys_only() {
        let sources = ManagedSources {
            hklm: Some(Ok(r#"{"managedSourcesBehavior":"merge"}"#.to_owned())),
            file: Some(Ok(r#"{"allowManagedHooksOnly":true}"#.to_owned())),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::File)); // HKLM has no policy keys
        assert!(posture.hooks_locked);
        assert!(!posture.mcp_locked);
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_null_policy_key_ignored() {
        let sources = ManagedSources {
            hklm: Some(Ok(r#"{"model":null}"#.to_owned())),
            file: Some(Ok(r#"{"allowManagedHooksOnly":true}"#.to_owned())),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::File)); // HKLM model:null is not a policy key
        assert!(posture.hooks_locked);
        assert!(!posture.mcp_locked);
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_broken_hklm() {
        let sources = ManagedSources {
            hklm: Some(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "access denied",
            ))),
            file: Some(Ok(r#"{"allowManagedHooksOnly":true}"#.to_owned())),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, None); // broken admin document
        assert!(!posture.hooks_locked);
        assert!(!posture.mcp_locked);
        assert!(posture.error.is_some()); // error names the source
        assert!(
            posture.error.as_ref().unwrap().contains("HKLM")
                || posture.error.as_ref().unwrap().contains("hklm")
        );
    }

    #[test]
    fn test_managed_settings_state_empty_file() {
        let sources = ManagedSources {
            hklm: None,
            file: Some(Ok("  \n  ".to_owned())), // whitespace-only
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, None); // empty file = {}, no policy keys
        assert!(!posture.hooks_locked);
        assert!(!posture.mcp_locked);
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_first_wins_with_flag_in_hklm_and_list_in_file() {
        let sources = ManagedSources {
            hklm: Some(Ok(r#"{"allowManagedMcpServersOnly":true}"#.to_owned())),
            file: Some(Ok(
                r#"{"allowedMcpServers":[{"serverUrl":"https://mcp.example.com/*"}]}"#.to_owned(),
            )),
            drop_ins: Vec::new(),
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::Hklm));
        assert!(!posture.hooks_locked);
        assert!(posture.mcp_locked); // cross-source: flag from HKLM, list from file
        assert_eq!(posture.error, None);
    }

    #[test]
    fn test_managed_settings_state_later_dropin_setting_overrides_earlier() {
        let sources = ManagedSources {
            hklm: None,
            file: None,
            drop_ins: vec![
                (
                    "50-first.json".to_owned(),
                    Ok(r#"{"allowManagedHooksOnly":true}"#.to_owned()),
                ),
                (
                    "60-second.json".to_owned(),
                    Ok(r#"{"allowManagedHooksOnly":false}"#.to_owned()),
                ),
            ],
        };
        let posture = managed_settings_state(&sources);
        assert_eq!(posture.source, Some(ManagedSettingsSource::File)); // drop-ins are part of file tier
        assert!(!posture.hooks_locked); // later drop-in (60-second) overrides earlier (50-first)
        assert!(!posture.mcp_locked);
        assert_eq!(posture.error, None);
    }

    // Reader tests (R1, R2)

    #[test]
    fn test_read_managed_sources_with_dropins() {
        use std::fs;
        let temp_dir = tempfile::tempdir().unwrap();
        let root = temp_dir.path();

        // Create base file
        fs::write(root.join("managed-settings.json"), r#"{"model":"base"}"#).unwrap();

        // Create drop-ins directory
        let dropins_dir = root.join("managed-settings.d");
        fs::create_dir(&dropins_dir).unwrap();

        // Create two .json drop-ins
        fs::write(dropins_dir.join("10-first.json"), r#"{"key1":"val1"}"#).unwrap();
        fs::write(dropins_dir.join("20-second.json"), r#"{"key2":"val2"}"#).unwrap();

        // Create a hidden .json file (should be skipped)
        fs::write(
            dropins_dir.join(".50-agentdesktop.json"),
            r#"{"hidden":"yes"}"#,
        )
        .unwrap();

        // Create a .txt file (should be skipped)
        fs::write(dropins_dir.join("30-text.txt"), "not json").unwrap();

        let sources = read_managed_sources(Some(root), || None);

        assert!(sources.hklm.is_none());
        assert!(sources.file.is_some());
        assert_eq!(
            sources.file.as_ref().unwrap().as_ref().unwrap(),
            r#"{"model":"base"}"#
        );
        assert_eq!(sources.drop_ins.len(), 2);
        assert_eq!(sources.drop_ins[0].0, "10-first.json");
        assert_eq!(
            sources.drop_ins[0].1.as_ref().unwrap(),
            r#"{"key1":"val1"}"#
        );
        assert_eq!(sources.drop_ins[1].0, "20-second.json");
        assert_eq!(
            sources.drop_ins[1].1.as_ref().unwrap(),
            r#"{"key2":"val2"}"#
        );
    }

    #[test]
    fn test_read_managed_sources_missing_root() {
        use std::path::Path;
        let nonexistent = Path::new("/nonexistent/path/to/managed/settings");

        let sources = read_managed_sources(Some(nonexistent), || None);

        assert!(sources.hklm.is_none());
        assert!(sources.file.is_none());
        assert!(sources.drop_ins.is_empty());
    }

    // Windows-only tests (W1, W2)

    #[cfg(windows)]
    #[test]
    fn test_read_hklm_settings_reg_sz_and_reg_expand_sz() {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::Registry::*;

        // Generate random test key name
        let random_id: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let test_key_path = format!(r"Software\agentdesktop-test\{}", random_id);

        // Create temp test key
        let key_path_wide: Vec<u16> = OsStr::new(&test_key_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut hkey: HKEY = std::ptr::null_mut();
        let result = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key_path_wide.as_ptr(),
                0,
                std::ptr::null(),
                0,
                KEY_ALL_ACCESS,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0, "Failed to create test registry key");

        // Cleanup guard
        struct KeyGuard(HKEY, String);
        impl Drop for KeyGuard {
            fn drop(&mut self) {
                use std::ffi::OsStr;
                use std::os::windows::ffi::OsStrExt;
                use windows_sys::Win32::System::Registry::*;
                unsafe {
                    RegCloseKey(self.0);
                    let path_wide: Vec<u16> = OsStr::new(&self.1)
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect();
                    RegDeleteKeyW(HKEY_CURRENT_USER, path_wide.as_ptr());
                }
            }
        }
        let _guard = KeyGuard(hkey, test_key_path.clone());

        // Test REG_SZ
        let sz_value = r#"{"test":"value"}"#;
        let sz_wide: Vec<u16> = OsStr::new(sz_value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let settings_wide: Vec<u16> = OsStr::new("Settings")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            RegSetValueExW(
                hkey,
                settings_wide.as_ptr(),
                0,
                REG_SZ,
                sz_wide.as_ptr() as *const u8,
                (sz_wide.len() * 2) as u32,
            )
        };

        let result_sz = read_hklm_settings(HKEY_CURRENT_USER, &test_key_path);
        assert!(result_sz.is_some());
        assert_eq!(result_sz.unwrap().unwrap(), sz_value);

        // Test REG_EXPAND_SZ
        let expand_value = r#"%TEMP%\test"#;
        let expand_wide: Vec<u16> = OsStr::new(expand_value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            RegSetValueExW(
                hkey,
                settings_wide.as_ptr(),
                0,
                REG_EXPAND_SZ,
                expand_wide.as_ptr() as *const u8,
                (expand_wide.len() * 2) as u32,
            )
        };

        let result_expand = read_hklm_settings(HKEY_CURRENT_USER, &test_key_path);
        assert!(result_expand.is_some());
        // Should be read back unexpanded
        assert_eq!(result_expand.unwrap().unwrap(), expand_value);
    }

    #[cfg(windows)]
    #[test]
    fn test_read_hklm_settings_reg_dword_and_absent() {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::Registry::*;

        // Generate random test key name
        let random_id: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let test_key_path = format!(r"Software\agentdesktop-test\{}", random_id);

        // Create temp test key
        let key_path_wide: Vec<u16> = OsStr::new(&test_key_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut hkey: HKEY = std::ptr::null_mut();
        let result = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key_path_wide.as_ptr(),
                0,
                std::ptr::null(),
                0,
                KEY_ALL_ACCESS,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0, "Failed to create test registry key");

        // Cleanup guard
        struct KeyGuard(HKEY, String);
        impl Drop for KeyGuard {
            fn drop(&mut self) {
                use std::ffi::OsStr;
                use std::os::windows::ffi::OsStrExt;
                use windows_sys::Win32::System::Registry::*;
                unsafe {
                    RegCloseKey(self.0);
                    let path_wide: Vec<u16> = OsStr::new(&self.1)
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect();
                    RegDeleteKeyW(HKEY_CURRENT_USER, path_wide.as_ptr());
                }
            }
        }
        let _guard = KeyGuard(hkey, test_key_path.clone());

        // Test REG_DWORD (should return Err(InvalidData))
        let dword_value: u32 = 1;
        let settings_wide: Vec<u16> = OsStr::new("Settings")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            RegSetValueExW(
                hkey,
                settings_wide.as_ptr(),
                0,
                REG_DWORD,
                &dword_value as *const u32 as *const u8,
                4,
            )
        };

        let result_dword = read_hklm_settings(HKEY_CURRENT_USER, &test_key_path);
        assert!(result_dword.is_some());
        let err = result_dword.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Test absent value (should return None)
        unsafe {
            RegDeleteValueW(hkey, settings_wide.as_ptr());
        };

        let result_absent = read_hklm_settings(HKEY_CURRENT_USER, &test_key_path);
        assert!(result_absent.is_none());
    }
}
