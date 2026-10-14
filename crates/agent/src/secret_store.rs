use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use anyhow::Context;
#[cfg(target_os = "macos")]
use apple_native_keyring_store::keychain::{Cred, MacKeychainDomain};

#[cfg(target_os = "linux")]
use crate::secure_fs;

/// Platform-native durable storage for daemon secrets.
pub struct SecretStore {
    #[cfg(target_os = "linux")]
    directory: PathBuf,
    #[cfg(target_os = "macos")]
    keychain: MacKeychainDomain,
}

impl SecretStore {
    pub fn new(state_dir: &Path) -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
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

        #[cfg(windows)]
        {
            let _ = state_dir;
            Ok(Self {})
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
            chunked::get(&KeyringBackend, service, account)
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
            chunked::set(&KeyringBackend, service, account, secret)
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
            chunked::delete(&KeyringBackend, service, account)
        }
    }

    #[cfg(target_os = "linux")]
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

/// Windows Credential Manager, through `keyring`.
#[cfg(windows)]
struct KeyringBackend;

#[cfg(windows)]
impl chunked::CredentialBackend for KeyringBackend {
    fn get(&self, service: &str, account: &str) -> anyhow::Result<Option<String>> {
        let entry = keyring::Entry::new(service, account)
            .context("open operating system credential store")?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error).context("read secret from operating system credential store"),
        }
    }

    fn set(&self, service: &str, account: &str, value: &str) -> anyhow::Result<()> {
        keyring::Entry::new(service, account)
            .context("open operating system credential store")?
            .set_password(value)
            .context("store secret in operating system credential store")
    }

    fn delete(&self, service: &str, account: &str) -> anyhow::Result<()> {
        let entry = keyring::Entry::new(service, account)
            .context("open operating system credential store")?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => {
                Err(error).context("delete secret from operating system credential store")
            }
        }
    }
}

/// Secrets larger than one Windows Credential Manager entry (2560 bytes of
/// UTF-16, so 1280 UTF-16 units) stored as chunks behind a manifest.
///
/// The primary entry holds either the secret itself or a manifest
/// `agentdesktop-secret-chunks-v2:<slot>:<count>:<tag>` naming one of two
/// fixed chunk slots, `a` and `b`. Every chunk value starts with the write's
/// random `tag`:
///
/// - A write fills the slot the current value does not use, then switches the
///   manifest in one entry write. The current value stays complete until the
///   new one is committed, so nothing has to be restored after a failure, and
///   cleanup after the commit can't fail the write.
/// - A read checks every chunk's tag against the manifest and reads again
///   when they differ or a chunk is gone, so a read that overlaps a write
///   never returns a value spliced from two writes.
/// - Chunks are written in ascending and deleted in descending index order,
///   so each slot always holds a contiguous run from index 0. Leftovers of a
///   failed cleanup are found by walking up from the end of the live chunks
///   until the first missing entry, which costs one lookup per slot when there
///   is nothing to clean.
#[cfg(any(windows, test))]
mod chunked {
    use anyhow::{Context, bail};

    /// Credential store operations the chunking needs.
    pub(super) trait CredentialBackend {
        fn get(&self, service: &str, account: &str) -> anyhow::Result<Option<String>>;
        fn set(&self, service: &str, account: &str, value: &str) -> anyhow::Result<()>;
        /// Deletes the entry; a missing entry is not an error.
        fn delete(&self, service: &str, account: &str) -> anyhow::Result<()>;
    }

    /// UTF-8 bytes of secret per chunk. With the 8-character tag a chunk is at
    /// most 1208 UTF-16 units, below the 1280-unit entry limit.
    pub(super) const CHUNK_SIZE: usize = 1_200;
    /// Chunks per secret (about 75 KB), checked before writing and when reading
    /// a manifest, so a corrupt manifest can't drive unbounded reads.
    pub(super) const MAX_CHUNKS: usize = 64;
    /// Values starting with this are always stored chunked, so a plain secret
    /// can never be mistaken for a manifest.
    const RESERVED_PREFIX: &str = "agentdesktop-secret-chunks-";
    const MANIFEST_PREFIX: &str = "agentdesktop-secret-chunks-v2:";
    /// Written by the first version of the chunked store (no slots, no tags).
    const LEGACY_MANIFEST_PREFIX: &str = "agentdesktop-secret-chunks-v1:";
    const CHUNK_SEPARATOR: &str = ":agentdesktop-secret-chunk:";
    const TAG_LEN: usize = 8;
    const READ_ATTEMPTS: usize = 3;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Slot {
        A,
        B,
    }

    impl Slot {
        fn name(self) -> &'static str {
            match self {
                Self::A => "a",
                Self::B => "b",
            }
        }

        fn other(self) -> Self {
            match self {
                Self::A => Self::B,
                Self::B => Self::A,
            }
        }
    }

    /// What the primary entry holds.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Stored {
        Plain,
        Chunked {
            slot: Slot,
            count: usize,
            tag: String,
        },
        Legacy {
            count: usize,
        },
    }

    pub(super) fn chunk_account(account: &str, slot: Slot, index: usize) -> String {
        format!("{account}{CHUNK_SEPARATOR}{}:{index}", slot.name())
    }

    fn legacy_chunk_account(account: &str, index: usize) -> String {
        format!("{account}{CHUNK_SEPARATOR}{index}")
    }

    fn manifest_value(slot: Slot, count: usize, tag: &str) -> String {
        format!("{MANIFEST_PREFIX}{}:{count}:{tag}", slot.name())
    }

    fn chunk_count(count: &str) -> anyhow::Result<usize> {
        let count = count
            .parse::<usize>()
            .context("parse Windows secret chunk manifest")?;
        if !(2..=MAX_CHUNKS).contains(&count) {
            bail!("Windows secret chunk manifest must reference 2 to {MAX_CHUNKS} chunks");
        }
        Ok(count)
    }

    /// An error for a manifest that is malformed or out of bounds.
    pub(super) fn parse(value: &str) -> anyhow::Result<Stored> {
        if let Some(count) = value.strip_prefix(LEGACY_MANIFEST_PREFIX) {
            return Ok(Stored::Legacy {
                count: chunk_count(count)?,
            });
        }
        let Some(rest) = value.strip_prefix(MANIFEST_PREFIX) else {
            if value.starts_with(RESERVED_PREFIX) {
                bail!("unknown Windows secret chunk manifest version");
            }
            return Ok(Stored::Plain);
        };
        let mut parts = rest.split(':');
        let (Some(slot), Some(count), Some(tag), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            bail!("malformed Windows secret chunk manifest");
        };
        let slot = match slot {
            "a" => Slot::A,
            "b" => Slot::B,
            _ => bail!("unknown slot in Windows secret chunk manifest"),
        };
        if tag.len() != TAG_LEN || !tag.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("malformed tag in Windows secret chunk manifest");
        }
        Ok(Stored::Chunked {
            slot,
            count: chunk_count(count)?,
            tag: tag.to_owned(),
        })
    }

    pub(super) fn get(
        backend: &impl CredentialBackend,
        service: &str,
        account: &str,
    ) -> anyhow::Result<Option<String>> {
        for _ in 0..READ_ATTEMPTS {
            let Some(value) = backend.get(service, account)? else {
                return Ok(None);
            };
            match parse(&value)? {
                Stored::Plain => return Ok(Some(value)),
                Stored::Legacy { count } => {
                    let mut secret = String::new();
                    for index in 0..count {
                        let chunk = backend
                            .get(service, &legacy_chunk_account(account, index))?
                            .with_context(|| format!("secret chunk {} is missing", index + 1))?;
                        secret.push_str(&chunk);
                    }
                    return Ok(Some(secret));
                }
                Stored::Chunked { slot, count, tag } => {
                    if let Some(secret) = read_chunks(backend, service, account, slot, count, &tag)?
                    {
                        return Ok(Some(secret));
                    }
                    // A write replaced the chunks while they were read.
                }
            }
        }
        bail!("secret kept changing while it was read, or a chunk is missing")
    }

    /// `None` when a chunk is gone or carries another write's tag.
    fn read_chunks(
        backend: &impl CredentialBackend,
        service: &str,
        account: &str,
        slot: Slot,
        count: usize,
        tag: &str,
    ) -> anyhow::Result<Option<String>> {
        let mut secret = String::new();
        for index in 0..count {
            let Some(chunk) = backend.get(service, &chunk_account(account, slot, index))? else {
                return Ok(None);
            };
            let Some(data) = chunk.strip_prefix(tag) else {
                return Ok(None);
            };
            secret.push_str(data);
        }
        Ok(Some(secret))
    }

    pub(super) fn set(
        backend: &impl CredentialBackend,
        service: &str,
        account: &str,
        secret: &str,
    ) -> anyhow::Result<()> {
        // An unreadable or corrupt current value is overwritten, as a plain
        // write would; every chunk name it could have used is cleaned below.
        let current = match backend.get(service, account) {
            Ok(Some(value)) => parse(&value).ok(),
            Ok(None) => Some(Stored::Plain),
            Err(_) => None,
        };

        if secret.len() <= CHUNK_SIZE && !secret.starts_with(RESERVED_PREFIX) {
            backend.set(service, account, secret)?;
            clean(backend, service, account, current.as_ref(), None);
            return Ok(());
        }

        // A short value that looks like a manifest is split in two as well.
        let size = CHUNK_SIZE.min(secret.len().div_ceil(2)).max(1);
        let chunks = utf8_chunks(secret, size);
        if chunks.len() > MAX_CHUNKS {
            bail!(
                "secret needs {} chunks; the Windows credential store keeps at most {MAX_CHUNKS}",
                chunks.len()
            );
        }
        let slot = match current {
            Some(Stored::Chunked { slot, .. }) => slot.other(),
            _ => Slot::A,
        };
        let tag = format!("{:08x}", rand::random::<u32>());
        for (index, chunk) in chunks.iter().enumerate() {
            let value = format!("{tag}{chunk}");
            if let Err(error) = backend.set(service, &chunk_account(account, slot, index), &value) {
                // The current value lives elsewhere and is untouched.
                remove_from(
                    backend,
                    service,
                    |index| chunk_account(account, slot, index),
                    0,
                );
                return Err(error.context(format!(
                    "store secret chunk {} in operating system credential store",
                    index + 1
                )));
            }
        }
        let manifest = manifest_value(slot, chunks.len(), &tag);
        if let Err(error) = backend.set(service, account, &manifest) {
            // The write may have been applied although it reported an error.
            if backend.get(service, account).ok().flatten().as_deref() != Some(manifest.as_str()) {
                remove_from(
                    backend,
                    service,
                    |index| chunk_account(account, slot, index),
                    0,
                );
                return Err(error);
            }
        }
        clean(
            backend,
            service,
            account,
            current.as_ref(),
            Some((slot, chunks.len())),
        );
        Ok(())
    }

    /// Removes the primary entry, then every chunk it could have used.
    /// Leftover chunks no longer belong to any value; failing to remove them
    /// is logged and retried by the next write or delete, not reported.
    pub(super) fn delete(
        backend: &impl CredentialBackend,
        service: &str,
        account: &str,
    ) -> anyhow::Result<()> {
        let current = backend.get(service, account).ok().and_then(|value| {
            value
                .map(|value| parse(&value).ok())
                .unwrap_or(Some(Stored::Plain))
        });
        backend.delete(service, account)?;
        clean(backend, service, account, current.as_ref(), None);
        Ok(())
    }

    /// Best-effort cleanup after a committed write or a delete: every chunk
    /// except the live ones in `keep`. `previous` is the replaced value, or
    /// `None` when it couldn't be read.
    fn clean(
        backend: &impl CredentialBackend,
        service: &str,
        account: &str,
        previous: Option<&Stored>,
        keep: Option<(Slot, usize)>,
    ) {
        for slot in [Slot::A, Slot::B] {
            let start = match keep {
                Some((live, count)) if live == slot => count,
                _ => 0,
            };
            remove_from(
                backend,
                service,
                |index| chunk_account(account, slot, index),
                start,
            );
        }
        if matches!(previous, None | Some(Stored::Legacy { .. })) {
            remove_from(
                backend,
                service,
                |index| legacy_chunk_account(account, index),
                0,
            );
        }
    }

    /// Deletes the contiguous run of chunks from `start` up to the first
    /// missing one, highest index first, and stops at the first failure so
    /// what remains is still a run from `start`.
    fn remove_from(
        backend: &impl CredentialBackend,
        service: &str,
        name: impl Fn(usize) -> String,
        start: usize,
    ) {
        let mut end = start;
        while end < MAX_CHUNKS && matches!(backend.get(service, &name(end)), Ok(Some(_))) {
            end += 1;
        }
        for index in (start..end).rev() {
            if let Err(error) = backend.delete(service, &name(index)) {
                tracing::warn!(
                    service,
                    error = %format!("{error:#}"),
                    "could not delete stale secret chunks; the next write or delete retries"
                );
                return;
            }
        }
    }

    fn utf8_chunks(secret: &str, size: usize) -> Vec<&str> {
        let mut chunks = Vec::new();
        let mut start = 0;
        while start < secret.len() {
            let mut end = secret.floor_char_boundary(start + size);
            if end == start {
                // A size below one character still takes the character.
                end = start + secret[start..].chars().next().map_or(1, char::len_utf8);
            }
            chunks.push(&secret[start..end]);
            start = end;
        }
        chunks
    }

    #[cfg(test)]
    mod tests {
        use std::{cell::RefCell, collections::BTreeMap};

        use super::*;

        /// In-memory credential store with injectable failures for exact
        /// account names.
        #[derive(Default)]
        struct FakeBackend {
            entries: RefCell<BTreeMap<String, String>>,
            fail_set: RefCell<Vec<String>>,
            fail_delete: RefCell<Vec<String>>,
            /// Applies the write but reports an error, for these accounts.
            phantom_set: RefCell<Vec<String>>,
        }

        impl FakeBackend {
            fn accounts(&self) -> Vec<String> {
                self.entries.borrow().keys().cloned().collect()
            }
        }

        impl CredentialBackend for FakeBackend {
            fn get(&self, _service: &str, account: &str) -> anyhow::Result<Option<String>> {
                Ok(self.entries.borrow().get(account).cloned())
            }

            fn set(&self, _service: &str, account: &str, value: &str) -> anyhow::Result<()> {
                if self
                    .fail_set
                    .borrow()
                    .iter()
                    .any(|failing| failing == account)
                {
                    bail!("injected write failure");
                }
                // The real limit: 2560 bytes of UTF-16.
                assert!(
                    value.encode_utf16().count() * 2 <= 2560,
                    "entry over the platform limit"
                );
                self.entries
                    .borrow_mut()
                    .insert(account.to_owned(), value.to_owned());
                if self
                    .phantom_set
                    .borrow()
                    .iter()
                    .any(|phantom| phantom == account)
                {
                    bail!("injected error after the write was applied");
                }
                Ok(())
            }

            fn delete(&self, _service: &str, account: &str) -> anyhow::Result<()> {
                if self
                    .fail_delete
                    .borrow()
                    .iter()
                    .any(|failing| failing == account)
                {
                    bail!("injected delete failure");
                }
                self.entries.borrow_mut().remove(account);
                Ok(())
            }
        }

        fn long(byte: char, len: usize) -> String {
            std::iter::repeat_n(byte, len).collect()
        }

        fn chunk(slot: Slot, index: usize) -> String {
            chunk_account("acct", slot, index)
        }

        fn chunks(slot: Slot, count: usize) -> Vec<String> {
            (0..count).map(|index| chunk(slot, index)).collect()
        }

        fn expect_entries(backend: &FakeBackend, mut expected: Vec<String>) {
            expected.push("acct".to_owned());
            expected.sort();
            assert_eq!(backend.accounts(), expected);
        }

        fn read(backend: &FakeBackend) -> Option<String> {
            get(backend, "svc", "acct").unwrap()
        }

        #[test]
        fn round_trips_and_transitions_leave_no_stale_chunks() {
            let backend = FakeBackend::default();
            assert_eq!(read(&backend), None);

            set(&backend, "svc", "acct", "short").unwrap();
            assert_eq!(read(&backend).as_deref(), Some("short"));
            expect_entries(&backend, Vec::new());

            let three = long('x', CHUNK_SIZE * 2 + 1);
            set(&backend, "svc", "acct", &three).unwrap();
            assert_eq!(read(&backend), Some(three));
            expect_entries(&backend, chunks(Slot::A, 3));

            let two = long('y', CHUNK_SIZE + 1);
            set(&backend, "svc", "acct", &two).unwrap();
            assert_eq!(read(&backend), Some(two));
            expect_entries(&backend, chunks(Slot::B, 2));

            set(&backend, "svc", "acct", "short again").unwrap();
            assert_eq!(read(&backend).as_deref(), Some("short again"));
            expect_entries(&backend, Vec::new());

            set(&backend, "svc", "acct", &long('z', CHUNK_SIZE * 4)).unwrap();
            delete(&backend, "svc", "acct").unwrap();
            assert!(backend.accounts().is_empty());
            assert_eq!(read(&backend), None);
        }

        #[test]
        fn a_plain_secret_that_looks_like_a_manifest_round_trips() {
            let backend = FakeBackend::default();
            let lookalike = manifest_value(Slot::A, 2, "0000beef");
            set(&backend, "svc", "acct", &lookalike).unwrap();
            assert_eq!(read(&backend), Some(lookalike));
            assert_eq!(backend.accounts().len(), 3);
        }

        #[test]
        fn utf8_boundaries_are_kept() {
            let secret = format!("{}🙂tail", long('a', CHUNK_SIZE - 1));
            let split = utf8_chunks(&secret, CHUNK_SIZE);
            assert_eq!(split.len(), 2);
            assert_eq!(split[0].len(), CHUNK_SIZE - 1);
            assert_eq!(split[1], "🙂tail");
            assert_eq!(utf8_chunks("🙂🙂", 1), vec!["🙂", "🙂"]);

            let backend = FakeBackend::default();
            let wide = std::iter::repeat_n('🙂', CHUNK_SIZE).collect::<String>();
            set(&backend, "svc", "acct", &wide).unwrap();
            assert_eq!(read(&backend), Some(wide));
        }

        #[test]
        fn manifests_are_bounded_and_validated() {
            assert_eq!(parse("plain-secret").unwrap(), Stored::Plain);
            assert_eq!(
                parse(&manifest_value(Slot::B, MAX_CHUNKS, "0123abcd")).unwrap(),
                Stored::Chunked {
                    slot: Slot::B,
                    count: MAX_CHUNKS,
                    tag: "0123abcd".to_owned()
                }
            );
            for invalid in [
                format!("{MANIFEST_PREFIX}a:1:0123abcd"),
                format!("{MANIFEST_PREFIX}a:{}:0123abcd", MAX_CHUNKS + 1),
                format!("{MANIFEST_PREFIX}a:{}:0123abcd", usize::MAX),
                format!("{MANIFEST_PREFIX}c:2:0123abcd"),
                format!("{MANIFEST_PREFIX}a:2:short"),
                format!("{MANIFEST_PREFIX}a:2"),
                format!("{MANIFEST_PREFIX}a:2:0123abcd:extra"),
                format!("{RESERVED_PREFIX}v3:a:2"),
                format!("{LEGACY_MANIFEST_PREFIX}{}", MAX_CHUNKS + 1),
            ] {
                assert!(parse(&invalid).is_err(), "{invalid} accepted");
            }

            let backend = FakeBackend::default();
            let too_big = long('x', MAX_CHUNKS * CHUNK_SIZE + 1);
            let error = set(&backend, "svc", "acct", &too_big).unwrap_err();
            assert!(error.to_string().contains("chunks"));
            assert!(backend.accounts().is_empty());
            let largest = long('x', MAX_CHUNKS * CHUNK_SIZE);
            set(&backend, "svc", "acct", &largest).unwrap();
            assert_eq!(read(&backend), Some(largest));
        }

        #[test]
        fn a_corrupt_or_unreadable_current_value_is_overwritten() {
            let backend = FakeBackend::default();
            backend.entries.borrow_mut().insert(
                "acct".to_owned(),
                format!("{MANIFEST_PREFIX}a:{}:x", usize::MAX),
            );
            backend
                .entries
                .borrow_mut()
                .insert(chunk(Slot::A, 0), "junk".to_owned());
            assert!(get(&backend, "svc", "acct").is_err());
            set(&backend, "svc", "acct", "fresh").unwrap();
            assert_eq!(read(&backend).as_deref(), Some("fresh"));
            expect_entries(&backend, Vec::new());
        }

        #[test]
        fn legacy_v1_values_are_read_and_cleaned_up() {
            let backend = FakeBackend::default();
            backend
                .entries
                .borrow_mut()
                .insert("acct".to_owned(), format!("{LEGACY_MANIFEST_PREFIX}2"));
            backend
                .entries
                .borrow_mut()
                .insert(legacy_chunk_account("acct", 0), "first-".to_owned());
            backend
                .entries
                .borrow_mut()
                .insert(legacy_chunk_account("acct", 1), "second".to_owned());
            assert_eq!(read(&backend).as_deref(), Some("first-second"));
            set(&backend, "svc", "acct", &long('n', CHUNK_SIZE + 1)).unwrap();
            expect_entries(&backend, chunks(Slot::A, 2));
        }

        #[test]
        fn leftover_chunks_above_the_new_count_are_removed() {
            let backend = FakeBackend::default();
            // Slot b holds leftovers of an earlier interrupted five-chunk write.
            for index in 0..5 {
                backend
                    .entries
                    .borrow_mut()
                    .insert(chunk(Slot::B, index), "old".to_owned());
            }
            set(&backend, "svc", "acct", &long('a', CHUNK_SIZE * 2)).unwrap();
            set(&backend, "svc", "acct", &long('b', CHUNK_SIZE * 2)).unwrap();
            expect_entries(&backend, chunks(Slot::B, 2));
        }

        #[test]
        fn failed_chunk_and_manifest_writes_keep_the_current_value() {
            let backend = FakeBackend::default();
            let current = long('c', CHUNK_SIZE * 2);
            set(&backend, "svc", "acct", &current).unwrap();

            *backend.fail_set.borrow_mut() = vec![chunk(Slot::B, 1)];
            assert!(set(&backend, "svc", "acct", &long('n', CHUNK_SIZE * 3)).is_err());
            assert_eq!(read(&backend), Some(current.clone()));
            expect_entries(&backend, chunks(Slot::A, 2));

            // All chunks written, only the manifest write fails.
            *backend.fail_set.borrow_mut() = vec!["acct".to_owned()];
            assert!(set(&backend, "svc", "acct", &long('n', CHUNK_SIZE * 3)).is_err());
            assert_eq!(read(&backend), Some(current));
            expect_entries(&backend, chunks(Slot::A, 2));
        }

        #[test]
        fn a_manifest_write_that_reports_an_error_after_applying_is_kept() {
            let backend = FakeBackend::default();
            set(&backend, "svc", "acct", &long('o', CHUNK_SIZE * 2)).unwrap();
            *backend.phantom_set.borrow_mut() = vec!["acct".to_owned()];
            let new = long('n', CHUNK_SIZE * 3);
            set(&backend, "svc", "acct", &new).unwrap();
            assert_eq!(read(&backend), Some(new));
            expect_entries(&backend, chunks(Slot::B, 3));
        }

        #[test]
        fn a_failed_cleanup_is_finished_by_the_next_write() {
            let backend = FakeBackend::default();
            set(&backend, "svc", "acct", &long('o', CHUNK_SIZE * 3)).unwrap();

            // a:1 can't be deleted: the write still succeeds, a:0 and a:1 stay.
            *backend.fail_delete.borrow_mut() = vec![chunk(Slot::A, 1)];
            let new = long('n', CHUNK_SIZE + 5);
            set(&backend, "svc", "acct", &new).unwrap();
            assert_eq!(read(&backend), Some(new));
            let mut stale = chunks(Slot::A, 2);
            stale.extend(chunks(Slot::B, 2));
            expect_entries(&backend, stale);

            *backend.fail_delete.borrow_mut() = Vec::new();
            set(&backend, "svc", "acct", "short").unwrap();
            expect_entries(&backend, Vec::new());
        }

        #[test]
        fn delete_succeeds_once_the_value_is_gone_and_a_retry_cleans_up() {
            let backend = FakeBackend::default();
            set(&backend, "svc", "acct", &long('d', CHUNK_SIZE * 2)).unwrap();
            *backend.fail_delete.borrow_mut() = vec![chunk(Slot::A, 1)];
            delete(&backend, "svc", "acct").unwrap();
            assert_eq!(read(&backend), None);
            assert_eq!(backend.accounts(), chunks(Slot::A, 2));

            *backend.fail_delete.borrow_mut() = Vec::new();
            delete(&backend, "svc", "acct").unwrap();
            assert!(backend.accounts().is_empty());

            *backend.fail_delete.borrow_mut() = vec!["acct".to_owned()];
            set(&backend, "svc", "acct", "kept").unwrap();
            assert!(delete(&backend, "svc", "acct").is_err());
        }

        #[test]
        fn a_read_racing_a_write_is_never_spliced() {
            let backend = FakeBackend::default();
            set(&backend, "svc", "acct", &long('1', CHUNK_SIZE * 2)).unwrap();
            let first_manifest = backend.entries.borrow()["acct"].clone();
            let Stored::Chunked { slot, count, tag } = parse(&first_manifest).unwrap() else {
                panic!("chunked");
            };
            // Two writes later slot a is reused with a new tag.
            set(&backend, "svc", "acct", &long('2', CHUNK_SIZE * 2)).unwrap();
            set(&backend, "svc", "acct", &long('3', CHUNK_SIZE * 2)).unwrap();
            // A reader still holding the first manifest must not accept them.
            assert_eq!(
                read_chunks(&backend, "svc", "acct", slot, count, &tag).unwrap(),
                None
            );
            assert_eq!(read(&backend), Some(long('3', CHUNK_SIZE * 2)));
        }

        #[test]
        fn a_plain_write_costs_one_lookup_per_slot() {
            #[derive(Default)]
            struct Counting {
                inner: FakeBackend,
                calls: RefCell<usize>,
            }
            impl CredentialBackend for Counting {
                fn get(&self, service: &str, account: &str) -> anyhow::Result<Option<String>> {
                    *self.calls.borrow_mut() += 1;
                    self.inner.get(service, account)
                }
                fn set(&self, service: &str, account: &str, value: &str) -> anyhow::Result<()> {
                    *self.calls.borrow_mut() += 1;
                    self.inner.set(service, account, value)
                }
                fn delete(&self, service: &str, account: &str) -> anyhow::Result<()> {
                    *self.calls.borrow_mut() += 1;
                    self.inner.delete(service, account)
                }
            }
            let backend = Counting::default();
            set(&backend, "svc", "acct", "one").unwrap();
            *backend.calls.borrow_mut() = 0;
            set(&backend, "svc", "acct", "two").unwrap();
            // read current, write, one lookup per slot
            assert_eq!(*backend.calls.borrow(), 4);
        }
    }
}

/// Round trips against the real Windows Credential Manager.
#[cfg(all(test, windows))]
mod windows_tests {
    use super::{KeyringBackend, chunked};

    /// Removes the test's credentials even when an assertion fails.
    struct Cleanup(String);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = chunked::delete(&KeyringBackend, &self.0, "account");
        }
    }

    fn present(service: &str, slot: chunked::Slot) -> usize {
        (0..chunked::MAX_CHUNKS)
            .filter(|index| {
                chunked::CredentialBackend::get(
                    &KeyringBackend,
                    service,
                    &chunked::chunk_account("account", slot, *index),
                )
                .unwrap()
                .is_some()
            })
            .count()
    }

    #[test]
    fn credential_manager_round_trips_long_secrets() {
        let service = format!(
            "agentdesktop-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        );
        let _cleanup = Cleanup(service.clone());
        let long: String = std::iter::repeat_n('x', chunked::CHUNK_SIZE * 3 + 7).collect();
        let shorter: String = std::iter::repeat_n('y', chunked::CHUNK_SIZE + 1).collect();
        // (value, chunks expected in slot a, in slot b) after each write
        for (value, a, b) in [
            (long.as_str(), 4, 0),
            ("short", 0, 0),
            (shorter.as_str(), 2, 0),
            (long.as_str(), 0, 4),
        ] {
            chunked::set(&KeyringBackend, &service, "account", value).unwrap();
            assert_eq!(
                chunked::get(&KeyringBackend, &service, "account")
                    .unwrap()
                    .as_deref(),
                Some(value)
            );
            assert_eq!(present(&service, chunked::Slot::A), a);
            assert_eq!(present(&service, chunked::Slot::B), b);
        }
        chunked::delete(&KeyringBackend, &service, "account").unwrap();
        assert_eq!(
            chunked::get(&KeyringBackend, &service, "account").unwrap(),
            None
        );
        assert_eq!(present(&service, chunked::Slot::A), 0);
        assert_eq!(present(&service, chunked::Slot::B), 0);
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
