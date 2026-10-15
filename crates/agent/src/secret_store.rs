use std::path::Path;
#[cfg(any(target_os = "linux", windows))]
use std::path::PathBuf;

use anyhow::Context;
#[cfg(target_os = "macos")]
use apple_native_keyring_store::keychain::{Cred, MacKeychainDomain};

#[cfg(any(target_os = "linux", windows))]
use crate::secure_fs;

/// Platform-native durable storage for daemon secrets.
///
/// On Windows a secret is stored as an encrypted file in the daemon's private
/// state directory, and only its small random key goes into Credential
/// Manager, which limits a credential to 2560 bytes. OAuth credentials with
/// refresh tokens exceed that.
pub struct SecretStore {
    #[cfg(any(target_os = "linux", windows))]
    directory: PathBuf,
    #[cfg(target_os = "macos")]
    keychain: MacKeychainDomain,
}

impl SecretStore {
    pub fn new(state_dir: &Path) -> anyhow::Result<Self> {
        #[cfg(any(target_os = "linux", windows))]
        {
            let directory = state_dir.join("secrets");
            secure_fs::ensure_private_dir(&directory)?;
            Ok(Self { directory })
        }

        #[cfg(target_os = "macos")]
        {
            let _ = state_dir;
            // SAFETY: geteuid has no preconditions.
            let effective_uid = unsafe { libc::geteuid() };
            Ok(Self {
                keychain: macos_keychain_domain(effective_uid),
            })
        }
    }

    pub fn get(&self, service: &str, account: &str) -> anyhow::Result<String> {
        self.get_optional(service, account)?
            .context("secret was not found")
    }

    pub fn get_optional(&self, service: &str, account: &str) -> anyhow::Result<Option<String>> {
        #[cfg(target_os = "linux")]
        {
            let path = self.entry_path(service, account);
            match std::fs::read(&path) {
                Ok(secret) => String::from_utf8(secret)
                    .context("stored secret is not UTF-8")
                    .map(Some),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => {
                    Err(error).with_context(|| format!("read secret from {}", path.display()))
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let entry = Cred::build(self.keychain.clone(), service, account)
                .context("open operating system credential store")?;
            match entry.get_password() {
                Ok(secret) => Ok(Some(secret)),
                Err(keyring_core::Error::NoEntry) => Ok(None),
                Err(error) => {
                    Err(error).context("read secret from operating system credential store")
                }
            }
        }

        #[cfg(windows)]
        {
            envelope::get(
                &self.entry_path(service, account),
                &CredentialManager,
                service,
                account,
            )
        }
    }

    pub fn set(&self, service: &str, account: &str, secret: &str) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let path = self.entry_path(service, account);
            secure_fs::atomic_write(&path, secret.as_bytes(), 0o600)
                .with_context(|| format!("store secret in {}", path.display()))
        }

        #[cfg(target_os = "macos")]
        {
            Cred::build(self.keychain.clone(), service, account)
                .context("open operating system credential store")?
                .set_password(secret)
                .context("store secret in operating system credential store")
        }

        #[cfg(windows)]
        {
            envelope::set(
                &self.entry_path(service, account),
                &CredentialManager,
                service,
                account,
                secret,
            )
        }
    }

    pub fn delete(&self, service: &str, account: &str) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let path = self.entry_path(service, account);
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => {
                    Err(error).with_context(|| format!("remove secret {}", path.display()))
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let entry = Cred::build(self.keychain.clone(), service, account)
                .context("open operating system credential store")?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
                Err(error) => {
                    Err(error).context("delete secret from operating system credential store")
                }
            }
        }

        #[cfg(windows)]
        {
            envelope::delete(
                &self.entry_path(service, account),
                &CredentialManager,
                service,
                account,
            )
        }
    }

    #[cfg(any(target_os = "linux", windows))]
    fn entry_path(&self, service: &str, account: &str) -> PathBuf {
        use sha2::{Digest, Sha256};

        let mut digest = Sha256::new();
        digest.update(service.as_bytes());
        digest.update([0]);
        digest.update(account.as_bytes());
        let name = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        self.directory.join(name)
    }
}

/// Windows Credential Manager entries, used for the per-secret file keys and
/// for reading secrets stored before the files existed.
#[cfg(windows)]
struct CredentialManager;

#[cfg(windows)]
impl envelope::KeyBackend for CredentialManager {
    fn get(&self, service: &str, account: &str) -> anyhow::Result<Option<String>> {
        let entry = keyring::Entry::new(service, account)
            .context("open operating system credential store")?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error).context("read from operating system credential store"),
        }
    }

    fn set(&self, service: &str, account: &str, value: &str) -> anyhow::Result<()> {
        keyring::Entry::new(service, account)
            .context("open operating system credential store")?
            .set_password(value)
            .context("store in operating system credential store")
    }

    fn delete(&self, service: &str, account: &str) -> anyhow::Result<()> {
        let entry = keyring::Entry::new(service, account)
            .context("open operating system credential store")?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error).context("delete from operating system credential store"),
        }
    }
}

/// Secrets of any size kept as AES-256-GCM files whose keys live in a small
/// key store. Compiled on every platform for tests; used on Windows.
#[cfg(any(windows, test))]
mod envelope {
    use std::{
        fs,
        io::ErrorKind,
        path::Path,
        sync::{Mutex, PoisonError},
    };

    use anyhow::{Context, bail};
    use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
    use base64::{Engine, engine::general_purpose::STANDARD};

    use crate::secure_fs;

    const KEY_LEN: usize = 32;
    const TAG_LEN: usize = 16;
    const FORMAT_VERSION: u8 = 1;
    /// Appended to the secret's service to name the entry that holds its key.
    /// The secret's own service and account keep any value stored before the
    /// encrypted files existed, so it can still be read until it is replaced.
    const KEY_SERVICE_SUFFIX: &str = ".file-key";

    /// Small values in the operating system credential store. Deleting an
    /// entry that does not exist succeeds.
    pub(super) trait KeyBackend {
        fn get(&self, service: &str, account: &str) -> anyhow::Result<Option<String>>;
        fn set(&self, service: &str, account: &str, value: &str) -> anyhow::Result<()>;
        fn delete(&self, service: &str, account: &str) -> anyhow::Result<()>;
    }

    /// Serializes writes so that two first writes of one secret cannot leave
    /// one write's key next to the other's file.
    static WRITES: Mutex<()> = Mutex::new(());

    pub(super) fn get(
        path: &Path,
        keys: &impl KeyBackend,
        service: &str,
        account: &str,
    ) -> anyhow::Result<Option<String>> {
        let sealed = match read_sealed(path)? {
            Some(sealed) => sealed,
            // A secret stored directly in the credential store by an earlier
            // version, or none at all.
            None => match keys.get(service, account)? {
                Some(value) => return Ok(Some(value)),
                // A first write may have stored the file and removed that value
                // since the file was looked up. It writes the file first, so the
                // file is there now if that happened.
                None => match read_sealed(path)? {
                    Some(sealed) => sealed,
                    None => return Ok(None),
                },
            },
        };
        match read_key(keys, service, account)? {
            StoredKey::Key(key) => open(&key, service, account, sealed).map(Some),
            // Nothing can open the file any more (the credential store was
            // reset, or the state directory restored without it), so the secret
            // is gone. Reporting it as absent lets callers sign in again; the
            // next write replaces the file.
            StoredKey::Missing => {
                tracing::warn!(
                    service,
                    path = %path.display(),
                    "the key of a stored secret is missing; treating the secret as absent"
                );
                Ok(None)
            }
            StoredKey::Malformed => bail!("the key of a stored secret is malformed"),
        }
    }

    pub(super) fn set(
        path: &Path,
        keys: &impl KeyBackend,
        service: &str,
        account: &str,
        secret: &str,
    ) -> anyhow::Result<()> {
        let _writes = WRITES.lock().unwrap_or_else(PoisonError::into_inner);
        // The key is created once and reused, so replacing the file is the only
        // step that changes the stored secret. A key that cannot be decoded
        // cannot open the current file either, so it is replaced.
        let key = match read_key(keys, service, account)? {
            StoredKey::Key(key) => key,
            StoredKey::Missing | StoredKey::Malformed => {
                let mut key = [0; KEY_LEN];
                aws_lc_rs::rand::fill(&mut key)
                    .map_err(|_| anyhow::anyhow!("generate secret file key"))?;
                keys.set(&key_service(service), account, &STANDARD.encode(key))
                    .context("store secret file key")?;
                key
            }
        };
        // Only the first write can replace a value an earlier version stored
        // directly; later writes skip the credential store lookup.
        let first_write = !path.try_exists().unwrap_or(true);
        secure_fs::atomic_write(path, &seal(&key, service, account, secret)?, 0o600)
            .with_context(|| format!("store secret in {}", path.display()))?;
        // The file now shadows that value; remove it so no stale copy is left.
        if first_write && let Err(error) = keys.delete(service, account) {
            tracing::warn!(%error, service, "could not remove the replaced credential store entry");
        }
        Ok(())
    }

    pub(super) fn delete(
        path: &Path,
        keys: &impl KeyBackend,
        service: &str,
        account: &str,
    ) -> anyhow::Result<()> {
        let _writes = WRITES.lock().unwrap_or_else(PoisonError::into_inner);
        // An earlier version's value goes first: it would be read again once
        // the file is gone, so a delete that stops halfway must not leave it.
        keys.delete(service, account)
            .context("delete secret from operating system credential store")?;
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("remove secret {}", path.display()));
            }
        }
        keys.delete(&key_service(service), account)
            .context("delete secret file key")
    }

    fn read_sealed(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
        match fs::read(path) {
            Ok(sealed) => Ok(Some(sealed)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => {
                Err(error).with_context(|| format!("read secret from {}", path.display()))
            }
        }
    }

    fn key_service(service: &str) -> String {
        format!("{service}{KEY_SERVICE_SUFFIX}")
    }

    enum StoredKey {
        Missing,
        Malformed,
        Key([u8; KEY_LEN]),
    }

    fn read_key(keys: &impl KeyBackend, service: &str, account: &str) -> anyhow::Result<StoredKey> {
        let Some(encoded) = keys
            .get(&key_service(service), account)
            .context("read secret file key")?
        else {
            return Ok(StoredKey::Missing);
        };
        Ok(STANDARD
            .decode(encoded)
            .ok()
            .and_then(|key| key.try_into().ok())
            .map_or(StoredKey::Malformed, StoredKey::Key))
    }

    /// Binds the file to its entry, so a file moved to another entry's path
    /// does not open.
    fn aad(service: &str, account: &str) -> Vec<u8> {
        let mut aad = b"agentdesktop secret v1\0".to_vec();
        aad.extend_from_slice(service.as_bytes());
        aad.push(0);
        aad.extend_from_slice(account.as_bytes());
        aad
    }

    /// `version || nonce || ciphertext || tag`
    fn seal(
        key: &[u8; KEY_LEN],
        service: &str,
        account: &str,
        secret: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let key = RandomizedNonceKey::new(&AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("load secret file key"))?;
        let mut ciphertext = secret.as_bytes().to_vec();
        let nonce = key
            .seal_in_place_append_tag(Aad::from(aad(service, account)), &mut ciphertext)
            .map_err(|_| anyhow::anyhow!("encrypt secret"))?;
        let mut sealed = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        sealed.push(FORMAT_VERSION);
        sealed.extend_from_slice(nonce.as_ref());
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn open(
        key: &[u8; KEY_LEN],
        service: &str,
        account: &str,
        mut sealed: Vec<u8>,
    ) -> anyhow::Result<String> {
        if sealed.len() < 1 + NONCE_LEN + TAG_LEN {
            bail!("stored secret is truncated");
        }
        if sealed[0] != FORMAT_VERSION {
            bail!("stored secret has unknown format version {}", sealed[0]);
        }
        let nonce = Nonce::try_assume_unique_for_key(&sealed[1..1 + NONCE_LEN])
            .map_err(|_| anyhow::anyhow!("read stored secret nonce"))?;
        let key = RandomizedNonceKey::new(&AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("load secret file key"))?;
        let plaintext = key
            .open_in_place(
                nonce,
                Aad::from(aad(service, account)),
                &mut sealed[1 + NONCE_LEN..],
            )
            .map_err(|_| anyhow::anyhow!("stored secret does not match its key"))?;
        String::from_utf8(plaintext.to_vec()).context("stored secret is not UTF-8")
    }

    #[cfg(test)]
    mod tests {
        use std::{
            cell::{Cell, RefCell},
            collections::BTreeMap,
            fs,
            path::PathBuf,
        };

        use super::{KeyBackend, delete, get, key_service, set};

        const SERVICE: &str = "dev.agentdesktop.test";
        const ACCOUNT: &str = "device";

        /// In-memory credential store with injectable failures.
        #[derive(Default)]
        struct FakeKeys {
            entries: RefCell<BTreeMap<(String, String), String>>,
            fail_sets: Cell<bool>,
            fail_deletes_of: RefCell<Option<String>>,
            deletes: Cell<usize>,
            /// Runs a concurrent first write (installs the file, removes the
            /// earlier version's value) when that value is looked up.
            first_write_during_lookup: RefCell<Option<(PathBuf, PathBuf)>>,
        }

        impl FakeKeys {
            fn value(&self, service: &str) -> Option<String> {
                self.entries
                    .borrow()
                    .get(&(service.to_owned(), ACCOUNT.to_owned()))
                    .cloned()
            }

            fn insert(&self, service: &str, value: &str) {
                self.entries
                    .borrow_mut()
                    .insert((service.to_owned(), ACCOUNT.to_owned()), value.to_owned());
            }
        }

        impl KeyBackend for FakeKeys {
            fn get(&self, service: &str, account: &str) -> anyhow::Result<Option<String>> {
                if service == SERVICE
                    && let Some((staged, path)) = self.first_write_during_lookup.take()
                {
                    fs::rename(staged, path).unwrap();
                    self.entries
                        .borrow_mut()
                        .remove(&(service.to_owned(), account.to_owned()));
                }
                Ok(self
                    .entries
                    .borrow()
                    .get(&(service.to_owned(), account.to_owned()))
                    .cloned())
            }

            fn set(&self, service: &str, account: &str, value: &str) -> anyhow::Result<()> {
                if self.fail_sets.get() {
                    anyhow::bail!("injected set failure");
                }
                // Windows Credential Manager limit; keyring stores UTF-16.
                let size = value.encode_utf16().count() * 2;
                assert!(size <= 2560, "credential too large: {size} bytes");
                self.entries
                    .borrow_mut()
                    .insert((service.to_owned(), account.to_owned()), value.to_owned());
                Ok(())
            }

            fn delete(&self, service: &str, account: &str) -> anyhow::Result<()> {
                self.deletes.set(self.deletes.get() + 1);
                if self.fail_deletes_of.borrow().as_deref() == Some(service) {
                    anyhow::bail!("injected delete failure");
                }
                self.entries
                    .borrow_mut()
                    .remove(&(service.to_owned(), account.to_owned()));
                Ok(())
            }
        }

        fn entry(directory: &tempfile::TempDir, name: &str) -> PathBuf {
            directory.path().join(name)
        }

        #[test]
        fn a_secret_larger_than_a_credential_round_trips() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let keys = FakeKeys::default();
            let secret = "x".repeat(20_000);

            set(&path, &keys, SERVICE, ACCOUNT, &secret).unwrap();
            assert_eq!(get(&path, &keys, SERVICE, ACCOUNT).unwrap(), Some(secret));
            assert!(
                !fs::read(&path)
                    .unwrap()
                    .windows(16)
                    .any(|w| w == b"xxxxxxxxxxxxxxxx")
            );
            assert_eq!(keys.entries.borrow().len(), 1);

            set(&path, &keys, SERVICE, ACCOUNT, "second").unwrap();
            assert_eq!(
                get(&path, &keys, SERVICE, ACCOUNT).unwrap().as_deref(),
                Some("second")
            );
        }

        #[test]
        fn the_key_is_created_once_and_reused() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let keys = FakeKeys::default();

            set(&path, &keys, SERVICE, ACCOUNT, "first").unwrap();
            let key = keys.value(&key_service(SERVICE)).unwrap();
            set(&path, &keys, SERVICE, ACCOUNT, "second").unwrap();
            assert_eq!(keys.value(&key_service(SERVICE)).unwrap(), key);
        }

        #[test]
        fn a_value_stored_by_an_earlier_version_is_read_and_replaced() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let keys = FakeKeys::default();
            keys.insert(SERVICE, "legacy");

            assert_eq!(
                get(&path, &keys, SERVICE, ACCOUNT).unwrap().as_deref(),
                Some("legacy")
            );
            set(&path, &keys, SERVICE, ACCOUNT, "new").unwrap();
            assert_eq!(keys.value(SERVICE), None);
            assert_eq!(
                get(&path, &keys, SERVICE, ACCOUNT).unwrap().as_deref(),
                Some("new")
            );
        }

        #[test]
        fn a_read_racing_the_first_write_still_finds_the_secret() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let staged = entry(&directory, "staged");
            let keys = FakeKeys::default();
            set(&path, &keys, SERVICE, ACCOUNT, "migrated").unwrap();
            fs::rename(&path, &staged).unwrap();
            keys.insert(SERVICE, "legacy");

            // The read misses the file, then the write lands before the
            // fallback lookup.
            *keys.first_write_during_lookup.borrow_mut() = Some((staged, path.clone()));
            assert_eq!(
                get(&path, &keys, SERVICE, ACCOUNT).unwrap().as_deref(),
                Some("migrated")
            );
        }

        #[test]
        fn only_the_first_write_removes_an_earlier_versions_value() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let keys = FakeKeys::default();
            keys.insert(SERVICE, "legacy");

            set(&path, &keys, SERVICE, ACCOUNT, "first").unwrap();
            assert_eq!(keys.deletes.get(), 1);
            set(&path, &keys, SERVICE, ACCOUNT, "second").unwrap();
            assert_eq!(keys.deletes.get(), 1);
        }

        #[test]
        fn a_failed_key_write_keeps_the_current_value() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let keys = FakeKeys::default();
            keys.insert(SERVICE, "legacy");
            keys.fail_sets.set(true);

            assert!(set(&path, &keys, SERVICE, ACCOUNT, "new").is_err());
            assert!(!path.exists());
            assert_eq!(
                get(&path, &keys, SERVICE, ACCOUNT).unwrap().as_deref(),
                Some("legacy")
            );
        }

        #[test]
        fn a_failed_file_write_keeps_the_current_value() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let keys = FakeKeys::default();
            set(&path, &keys, SERVICE, ACCOUNT, "current").unwrap();

            // Writing into a directory that does not exist fails.
            let missing = directory.path().join("missing").join("entry");
            assert!(set(&missing, &keys, SERVICE, ACCOUNT, "new").is_err());
            assert_eq!(
                get(&path, &keys, SERVICE, ACCOUNT).unwrap().as_deref(),
                Some("current")
            );
        }

        #[test]
        fn a_failed_legacy_cleanup_still_stores_the_secret() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let keys = FakeKeys::default();
            keys.insert(SERVICE, "legacy");
            *keys.fail_deletes_of.borrow_mut() = Some(SERVICE.to_owned());

            set(&path, &keys, SERVICE, ACCOUNT, "new").unwrap();
            assert_eq!(
                get(&path, &keys, SERVICE, ACCOUNT).unwrap().as_deref(),
                Some("new")
            );
        }

        #[test]
        fn a_file_does_not_open_under_another_entry() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let other = entry(&directory, "other");
            let keys = FakeKeys::default();
            set(&path, &keys, SERVICE, ACCOUNT, "secret").unwrap();
            // Same key for both entries, so only the binding can reject the copy.
            let key = keys.value(&key_service(SERVICE)).unwrap();
            keys.insert(&key_service("dev.agentdesktop.other"), &key);
            set(&other, &keys, "dev.agentdesktop.other", ACCOUNT, "other").unwrap();
            assert_eq!(
                keys.value(&key_service("dev.agentdesktop.other")).unwrap(),
                key
            );

            fs::copy(&path, &other).unwrap();
            assert!(get(&other, &keys, "dev.agentdesktop.other", ACCOUNT).is_err());
        }

        #[test]
        fn a_tampered_file_or_malformed_key_is_an_error_and_a_missing_key_reads_as_absent() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let keys = FakeKeys::default();
            set(&path, &keys, SERVICE, ACCOUNT, "secret").unwrap();

            let mut sealed = fs::read(&path).unwrap();
            *sealed.last_mut().unwrap() ^= 1;
            fs::write(&path, sealed).unwrap();
            assert!(get(&path, &keys, SERVICE, ACCOUNT).is_err());
            set(&path, &keys, SERVICE, ACCOUNT, "repaired").unwrap();
            assert_eq!(
                get(&path, &keys, SERVICE, ACCOUNT).unwrap().as_deref(),
                Some("repaired")
            );

            keys.entries.borrow_mut().clear();
            assert_eq!(get(&path, &keys, SERVICE, ACCOUNT).unwrap(), None);
            set(&path, &keys, SERVICE, ACCOUNT, "rekeyed").unwrap();
            assert_eq!(
                get(&path, &keys, SERVICE, ACCOUNT).unwrap().as_deref(),
                Some("rekeyed")
            );

            keys.insert(&key_service(SERVICE), "not base64!");
            assert!(get(&path, &keys, SERVICE, ACCOUNT).is_err());
            set(&path, &keys, SERVICE, ACCOUNT, "fixed").unwrap();
            assert_eq!(
                get(&path, &keys, SERVICE, ACCOUNT).unwrap().as_deref(),
                Some("fixed")
            );
        }

        #[test]
        fn delete_removes_everything_and_a_partial_delete_never_resurrects_an_old_value() {
            let directory = tempfile::tempdir().unwrap();
            let path = entry(&directory, "entry");
            let keys = FakeKeys::default();
            keys.insert(SERVICE, "legacy");
            *keys.fail_deletes_of.borrow_mut() = Some(SERVICE.to_owned());
            set(&path, &keys, SERVICE, ACCOUNT, "new").unwrap();
            *keys.fail_deletes_of.borrow_mut() = None;

            // Stops after the file: the secret reads as gone, a retry finishes.
            *keys.fail_deletes_of.borrow_mut() = Some(key_service(SERVICE));
            assert!(delete(&path, &keys, SERVICE, ACCOUNT).is_err());
            assert_eq!(get(&path, &keys, SERVICE, ACCOUNT).unwrap(), None);
            *keys.fail_deletes_of.borrow_mut() = None;
            delete(&path, &keys, SERVICE, ACCOUNT).unwrap();

            assert!(!path.exists());
            assert!(keys.entries.borrow().is_empty());
            delete(&path, &keys, SERVICE, ACCOUNT).unwrap();
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_keychain_domain(effective_uid: u32) -> MacKeychainDomain {
    if effective_uid == 0 {
        MacKeychainDomain::System
    } else {
        MacKeychainDomain::User
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use apple_native_keyring_store::keychain::MacKeychainDomain;

    use super::macos_keychain_domain;

    #[test]
    fn keychain_domain_follows_daemon_privilege() {
        assert_eq!(macos_keychain_domain(0), MacKeychainDomain::System);
        assert_eq!(macos_keychain_domain(501), MacKeychainDomain::User);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::SecretStore;

    #[test]
    fn a_secret_larger_than_a_credential_round_trips_through_credential_manager() {
        let directory = tempfile::tempdir().unwrap();
        let store = SecretStore::new(directory.path()).unwrap();
        let account = format!("test-{}", rand::random::<u64>());
        let secret = "x".repeat(10_000);

        store
            .set("dev.agentdesktop.test", &account, &secret)
            .unwrap();
        assert_eq!(
            store.get("dev.agentdesktop.test", &account).unwrap(),
            secret
        );
        store.delete("dev.agentdesktop.test", &account).unwrap();
        assert_eq!(
            store
                .get_optional("dev.agentdesktop.test", &account)
                .unwrap(),
            None
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::SecretStore;

    #[test]
    fn linux_store_round_trips_private_entries() {
        let directory = std::env::temp_dir().join(format!(
            "agentdesktop-secret-store-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&directory).unwrap();
        let store = SecretStore::new(&directory).unwrap();

        store.set("service", "account", "secret").unwrap();
        assert_eq!(store.get("service", "account").unwrap(), "secret");

        let entries: Vec<_> = fs::read_dir(directory.join("secrets"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            fs::metadata(&entries[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );

        store.delete("service", "account").unwrap();
        assert!(!entries[0].exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
