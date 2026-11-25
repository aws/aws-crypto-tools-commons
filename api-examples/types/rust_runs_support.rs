// Helpers for rust_runs.rs, which compile_rust_types.py writes. Each run there passes one held type to
// one option, checks what happens, and prints one RUN line that compile_rust_types.py reads.
//
// Every run holds the same value as the others for its option, in its own type. Then a run that
// gives a different result than the others shows that the type, or the code that passes it, changes
// the value.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub use aws_crypto_mpl::key_store::types::KmsConfiguration;
pub use aws_crypto_mpl::key_store::DynamoDbKeyStore;
pub use aws_crypto_mpl::keyring::{AwsKmsKeyring, HierarchicalKeyring, RawAesKeyring};
pub use aws_crypto_mpl::types::AesWrappingAlg;

pub const KEY_NAMESPACE: &str = "my-key-namespace";
pub const KEY_NAME: &str = "my-key-name";
pub const KMS_KEY_ARN: &str = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
pub const GRANT_TOKEN: &str = "my-grant-token";
pub const BRANCH_KEY_ID: &str = "my-branch-key-id";
pub const CONTEXT_KEY: &str = "team";
pub const CONTEXT_VALUE: &str = "payments";
pub const FRAME_LENGTH: u64 = 128;
pub const MAX_ENCRYPTED_DATA_KEYS: u64 = 3;
pub const TTL_SECONDS: u64 = 60;

// Counts every byte allocated, so a run can tell whether passing a value copies it.
// compile_rust_types.py runs one test at a time, so the count belongs to one run.
struct Counting;
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATED.fetch_add(new_size, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

pub fn allocated() -> usize {
    ALLOCATED.load(Ordering::Relaxed)
}

// The value every run of an option holds. Text values are ASCII, so their bytes match the byte values.
pub fn key_bytes() -> Vec<u8> {
    b"0123456789abcdef0123456789abcdef".to_vec()
}
pub fn key_text() -> String {
    String::from_utf8(key_bytes()).unwrap()
}
pub fn plaintext_bytes() -> Vec<u8> {
    b"hello from the types page. ".repeat(2500)
}
pub fn plaintext_text() -> String {
    String::from_utf8(plaintext_bytes()).unwrap()
}
// Ciphertext held as text is base64, the way customers store it.
pub async fn ciphertext_bytes() -> Vec<u8> {
    aws_esdk::Client::default()
        .encrypt()
        .plaintext(&plaintext_bytes())
        .keyring(raw_aes_keyring())
        .send()
        .await
        .expect("the reference encrypt succeeds")
        .into_ciphertext()
        .into_inner()
}
pub async fn ciphertext_text() -> String {
    aws_smithy_types::base64::encode(ciphertext_bytes().await)
}

pub fn raw_aes_keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace(KEY_NAMESPACE)
        .key_name(KEY_NAME)
        .wrapping_key(key_bytes())
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .expect("the reference keyring builds")
}

// AWS clients with a fixed region. Building them makes no network call.
pub fn kms_config() -> aws_sdk_kms::Config {
    aws_sdk_kms::Config::builder()
        .region(aws_sdk_kms::config::Region::new("us-west-2"))
        .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
        .build()
}
pub fn kms_client() -> aws_sdk_kms::Client {
    aws_sdk_kms::Client::from_conf(kms_config())
}
pub fn sdk_config() -> aws_types::SdkConfig {
    aws_types::SdkConfig::builder()
        .region(aws_types::region::Region::new("us-west-2"))
        .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
        .build()
}
pub async fn key_store() -> DynamoDbKeyStore {
    let ddb_config = aws_sdk_dynamodb::Config::builder()
        .region(aws_sdk_dynamodb::config::Region::new("us-west-2"))
        .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
        .build();
    DynamoDbKeyStore::builder()
        .ddb_table_name("KeyStoreTable")
        .logical_key_store_name("KeyStoreTable")
        .kms_configuration(KmsConfiguration::kms_key_arn(KMS_KEY_ARN))
        .kms_client(kms_client())
        .ddb_client(aws_sdk_dynamodb::Client::from_conf(ddb_config))
        .build()
        .await
        .expect("the reference key store builds")
}

// A file that holds `bytes`, for the path and reader types.
pub fn temp_file(bytes: &[u8]) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("types-page-run-{}-{n}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    path
}

// What one run found. It prints as one RUN line when the run ends.
pub struct Report {
    name: &'static str,
    fields: Vec<(&'static str, String)>,
}

impl Report {
    pub fn new(name: &'static str) -> Self {
        Self { name, fields: Vec::new() }
    }
    fn set(&mut self, field: &'static str, json: String) {
        self.fields.push((field, json));
    }
    // A run that can't hold the option's value in its type says why and stops.
    pub fn skip(&mut self, why: &str) {
        self.set("skipped", quote(why));
    }
    // Whether passing the value allocated at least as many bytes as the value holds.
    pub fn copied(&mut self, bytes: usize, of: usize) {
        self.set("copies", (bytes >= of).to_string());
    }
    pub fn built<T, E: std::fmt::Debug>(&mut self, result: &Result<T, E>) {
        self.set("builds", result.is_ok().to_string());
        if let Err(e) = result {
            self.set("error", quote(&error_text(e)));
        }
    }
    // Whether the run gave the same result as the reference value.
    pub fn same(&mut self, same: bool) {
        self.set("same", same.to_string());
    }
}

impl Drop for Report {
    fn drop(&mut self) {
        let fields: Vec<String> = self.fields.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
        println!("RUN {} {{{}}}", self.name, fields.join(","));
    }
}

// The first line of an error's Debug output, so a long error stays readable on the page.
fn error_text(e: &impl std::fmt::Debug) -> String {
    let text = format!("{e:?}");
    text.lines().next().unwrap_or("").chars().take(200).collect()
}

fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// Checks for each kind of option. Each records whether the build or call worked and whether the
// result matches the reference.

pub async fn check_encrypt(r: &mut Report, result: Result<aws_esdk::operation::encrypt::EncryptOutput, aws_esdk::Error>) {
    r.built(&result);
    let Ok(out) = result else { return };
    let plaintext = aws_esdk::Client::default()
        .decrypt()
        .ciphertext(out.ciphertext())
        .keyring(raw_aes_keyring())
        .send()
        .await
        .map(|o| o.into_plaintext().into_inner());
    r.same(plaintext.ok() == Some(plaintext_bytes()));
}

pub async fn check_context(r: &mut Report, result: Result<aws_esdk::operation::encrypt::EncryptOutput, aws_esdk::Error>) {
    r.built(&result);
    let Ok(out) = result else { return };
    let decrypted = aws_esdk::Client::default()
        .decrypt()
        .ciphertext(out.ciphertext())
        .keyring(raw_aes_keyring())
        .send()
        .await;
    r.same(decrypted.map(|o| o.encryption_context().get(CONTEXT_KEY) == Some(CONTEXT_VALUE)).unwrap_or(false));
}

pub fn check_decrypt(r: &mut Report, result: Result<aws_esdk::operation::decrypt::DecryptOutput, aws_esdk::Error>) {
    r.built(&result);
    let Ok(out) = result else { return };
    r.same(out.into_plaintext().into_inner() == plaintext_bytes());
}

pub async fn check_client(r: &mut Report, result: Result<aws_esdk::Client, aws_esdk::Error>) {
    r.built(&result);
    let Ok(client) = result else { return };
    let encrypted = client.encrypt().plaintext(&plaintext_bytes()).keyring(raw_aes_keyring()).send().await;
    check_encrypt_quietly(r, encrypted).await;
}

async fn check_encrypt_quietly(r: &mut Report, result: Result<aws_esdk::operation::encrypt::EncryptOutput, aws_esdk::Error>) {
    let Ok(out) = result else {
        r.same(false);
        return;
    };
    let plaintext = aws_esdk::Client::default()
        .decrypt()
        .ciphertext(out.ciphertext())
        .keyring(raw_aes_keyring())
        .send()
        .await
        .map(|o| o.into_plaintext().into_inner());
    r.same(plaintext.ok() == Some(plaintext_bytes()));
}

// A raw AES keyring gives the same result when the reference keyring decrypts what it encrypts.
pub async fn check_raw_aes(r: &mut Report, result: Result<RawAesKeyring, aws_crypto_mpl::Error>) {
    r.built(&result);
    let Ok(keyring) = result else { return };
    let encrypted = aws_esdk::Client::default().encrypt().plaintext(&plaintext_bytes()).keyring(keyring).send().await;
    check_encrypt_quietly(r, encrypted).await;
}

pub fn check_kms(r: &mut Report, result: Result<AwsKmsKeyring, aws_crypto_mpl::Error>, same: fn(&AwsKmsKeyring) -> bool) {
    r.built(&result);
    if let Ok(keyring) = &result {
        r.same(same(keyring));
    }
}

pub fn check_hierarchical(
    r: &mut Report,
    result: Result<HierarchicalKeyring, aws_crypto_mpl::Error>,
    same: fn(&HierarchicalKeyring) -> bool,
) {
    r.built(&result);
    if let Ok(keyring) = &result {
        r.same(same(keyring));
    }
}

pub fn ttl() -> Duration {
    Duration::from_secs(TTL_SECONDS)
}
