//
// Copyright 2024, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This crate implements droidfoodattestation.

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve,
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use android_security_postprocessor::aidl::android::security::postprocessor::{
    CertificateChain::CertificateChain,
    IKeystoreCertificatePostProcessor::IKeystoreCertificatePostProcessor,
};
use android_security_postprocessor::binder::{Interface, Status};
use android_system_keystore2::aidl::android::system::keystore2::{
    AuthenticatorSpec::AuthenticatorSpec, Authorization::Authorization, Domain::Domain,
    IKeystoreSecurityLevel::IKeystoreSecurityLevel, IKeystoreService::IKeystoreService,
    KeyDescriptor::KeyDescriptor, KeyMetadata::KeyMetadata,
};
use android_system_keystore2::binder::{self, ThreadState};
use bytes::{Buf, BufMut};
use droidfood_attestation_proto::overwrite::{
    AttestationKeyCertificateProfile as WireAttestationKeyCertificateProfile,
    OverwriteAttestationRequest, OverwriteAttestationResponse,
    OverwriteAttestationResponsePlaintext, ProvisionAttestationKeyRequest,
    ProvisionAttestationKeyResponse, ProvisionAttestationKeyResponsePlaintext,
};
use http::uri::PathAndQuery;
use log::{debug, error};
use mystic_attestation_provisioner::aidl::mystic::attestation::provisioner::{
    AttestationKeyCertificateProfile::AttestationKeyCertificateProfile as BinderAttestationKeyCertificateProfile,
    HardeningStageContext::HardeningStageContext as BinderHardeningStageContext,
    HardeningStageResult::HardeningStageResult as BinderHardeningStageResult,
    IBackendAttestationKeyProvisioner::IBackendAttestationKeyProvisioner,
    ProtectedStageCompletion::ProtectedStageCompletion as BinderProtectedStageCompletion,
    ProvisionedAttestationKey::ProvisionedAttestationKey,
};
use mystic_hardening_proto::hardening::{
    GrantConsumptionV1, GrantTransitionV1, HardeningBeginRequestV1, HardeningChallengeV1,
    HardeningContextV1, HardeningCryptoNamespaceV1, HardeningGrantV1, HardeningRedeemRequestV1,
    ProtectedStageCompletionResultV1, ProtectedStageCompletionV1, RegisteredWrappingKeyV1,
    WrappingKeyPoolScopeV1, WrappingKeyPreparationChallengeV1, WrappingKeyPreparationRequestV1,
    WrappingKeyRegistrationRequestV1,
};
use openssl::hash::{Hasher, MessageDigest};
use openssl::hkdf::hkdf;
use openssl::hmac::hmac;
use openssl::md::Md;
use openssl::memcmp;
use openssl::sha::sha256;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::x509::{X509Ref, X509};
use protobuf::{Message, MessageField};
use rustutils::android::system_properties;
use rustutils::android::users::AID_KEYSTORE;
use std::cell::Cell;
use std::collections::HashSet;
use std::ffi::c_char;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tonic::client::Grpc;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Code, GrpcMethod, Request as TonicRequest, Status as TonicStatus};
use uuid::Uuid;

const BACKEND_GRPC_DIRECT_TARGET: &str = "greendroidfood-pa.helluvaos.com";
const BACKEND_GRPC_PROXY_TARGET: &str = "greendroidfood-pa.meowproxy.net";
const ERROR_SERVER_REQUEST: i32 = -2;
const ERROR_SERVER_RESPONSE: i32 = -3;
const ERROR_REPROVISION_ATTESTATION_KEY: i32 = -4;
const ERROR_HARDENING_UNAVAILABLE: i32 = -5;
const ERROR_HARDENING_TERMINAL: i32 = -6;
const KEYSTORE2_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";
const RESPONSE_KEY_ALIAS_PREFIX: &str = "mystic_response_";
const RESPONSE_KEY_CHALLENGE_PREFIX: &str = "MysticAttestation response key v1:";
const DEVICE_IDENTITY_TRUSTED_ALIAS: &str = "mystic_device_identity_v2";
const DEVICE_IDENTITY_FALLBACK_ALIAS: &str = "mystic_device_identity_fallback_v2";
const DEVICE_IDENTITY_CHALLENGE_DOMAIN: &[u8] = b"MysticAttestation persistent device identity v2";
const DEVICE_IDENTITY_REQUEST_DOMAIN: &[u8] = b"MysticAttestation device identity request v2";
const RESPONSE_HKDF_INFO: &[u8] = b"MysticAttestation overwrite response v1";
const RESPONSE_AAD_PREFIX: &str = "MysticAttestation overwrite response aad v1:";
const PROVISION_RESPONSE_HKDF_INFO: &[u8] = b"MysticAttestation provision response v1";
const PROVISION_RESPONSE_AAD_PREFIX: &str = "MysticAttestation provision response aad v1:";
const ATTESTATION_PROTOCOL_VERSION: u32 = 2;
const RESPONSE_CERT_NOT_AFTER_MS: i64 = 2_461_449_600_000;
const BACKEND_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PROVISION_REQUEST_ATTEMPTS: usize = 3;
const PROVISION_RETRY_DELAY: Duration = Duration::from_millis(250);
const GRPC_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_CERTIFICATE_INPUT_BYTES: usize = 768 * 1024;
const MAX_SECURE_KEY_WRAPPER_BYTES: usize = 256 * 1024;
const MAX_ENCRYPTED_RESPONSE_BYTES: usize = 768 * 1024;
const MAX_RESPONSE_EPHEMERAL_KEY_BYTES: usize = 2048;
const AES_GCM_NONCE_BYTES: usize = 12;
const HARDENING_SCHEMA_VERSION: u32 = 1;
const HARDENING_PROTOCOL_MAJOR: u32 = 3;
const HARDENING_CRYPTO_SUITE_V1: u32 = 1;
const HARDENING_PAYLOAD_HEADER_BYTES: usize = 4 + AES_GCM_NONCE_BYTES;
const AES_GCM_TAG_BYTES: usize = 16;
const MAX_HARDENING_PLAINTEXT_BYTES: usize = 64 * 1024;
const MAX_HARDENING_SEALED_PAYLOAD_BYTES: usize =
    HARDENING_PAYLOAD_HEADER_BYTES + MAX_HARDENING_PLAINTEXT_BYTES + AES_GCM_TAG_BYTES;
const HARDENING_TRANSCRIPT_DOMAIN: &[u8] = b"MYSTIC/HARDENING/GRANT/V1";
const HARDENING_CONTEXT_DOMAIN: &[u8] = b"MYSTIC/HARDENING/CONTEXT/V1";
const HARDENING_BEGIN_DOMAIN: &[u8] = b"MYSTIC/HARDENING/BEGIN/V1";
const HARDENING_PROTECTED_COMPLETION_DOMAIN: &[u8] = b"MYSTIC/HARDENING/PROTECTED-COMPLETION/V1";
const HARDENING_GRPC_SERVICE: &str = "mystic.attestation.hardening.v1.HardeningRuntime";
const HARDENING_BEGIN_PATH: &str = "/mystic.attestation.hardening.v1.HardeningRuntime/BeginSession";
const HARDENING_REDEEM_PATH: &str = "/mystic.attestation.hardening.v1.HardeningRuntime/RedeemGrant";
const HARDENING_CONSUME_PATH: &str =
    "/mystic.attestation.hardening.v1.HardeningRuntime/ConsumeGrant";
const HARDENING_PREPARE_WRAPPING_KEY_PATH: &str =
    "/mystic.attestation.hardening.v1.HardeningRuntime/PrepareWrappingKey";
const HARDENING_REGISTER_WRAPPING_KEY_PATH: &str =
    "/mystic.attestation.hardening.v1.HardeningRuntime/RegisterWrappingKey";
const HARDENING_COMPLETE_PROTECTED_STAGE_PATH: &str =
    "/mystic.attestation.hardening.v1.HardeningRuntime/CompleteProtectedStage";
const HARDENING_ALIAS_PREFIX: &str = "__rkp_cert_processor_runtime_stage_v1__";
const HARDENING_WRAPPING_ALIAS_KIND: &str = "wrapping_";
const HARDENING_CAPABILITY_ALIAS_KIND: &str = "capability_";
const HARDENING_POOL_ALIAS_KIND: &str = "pool_";
const HARDENING_MAX_ID_BYTES: usize = 128;
const HARDENING_MAX_TOKEN_BYTES: usize = 512;
const HARDENING_MAX_WRAPPER_BYTES: usize = 16 * 1024;
const HARDENING_APPLY_DESCRIPTOR_BYTES: usize = 40;
const HARDENING_APPLY_DESCRIPTOR_VERSION: u32 = 1;
const HARDENING_ATTESTATION_KEY_IMPORT_PROGRAM_DOMAIN: [u8; 8] =
    [0xc4, 0xe7, 0x61, 0x2b, 0x9d, 0x38, 0x05, 0xaf];
const HARDENING_PROCESSED_REPLY_PROGRAM_DOMAIN: [u8; 8] =
    [0x3b, 0x49, 0x4c, 0x40, 0xb4, 0x1a, 0x6f, 0xaf];
const HARDENING_AUTHORIZATION_TAG_BYTES: usize = 32;
const HARDENING_VERIFICATION_PROOF_BYTES: usize = 64;
const HARDENING_OPAQUE_RESULT_EXTENSION_BYTES: usize = 96;
const HARDENING_TRANSCRIPT_BYTES: usize = 32;
const HARDENING_MAX_RESULT_BYTES: usize = HARDENING_APPLY_DESCRIPTOR_BYTES
    + HARDENING_AUTHORIZATION_TAG_BYTES
    + HARDENING_VERIFICATION_PROOF_BYTES
    + HARDENING_OPAQUE_RESULT_EXTENSION_BYTES
    + HARDENING_TRANSCRIPT_BYTES;
const HARDENING_PURPOSE_FUNCTIONAL: u32 = 1;
const HARDENING_PURPOSE_PROTECTED: u32 = 2;
const HARDENING_ATTESTATION_KEY_IMPORT_ROUTE: u32 = 1;
const HARDENING_PROCESSED_REPLY_ROUTE: u32 = 2;
const HARDENING_INITIAL_STAGE: u32 = 0;
const HARDENING_PROTECTED_ROUTE: u32 = 1;
const HARDENING_PROTECTED_INITIAL_STAGE: u32 = 1;
const HARDENING_PROTECTED_FINAL_STAGE: u32 = 3;
const HARDENING_LATENT_BINDING_BYTES: usize = 32;
const HARDENING_MAX_PROTECTED_BUNDLE_BYTES: usize = MAX_HARDENING_PLAINTEXT_BYTES;
const HARDENING_RECOVERY_SELECTOR_BYTES: usize = 32;
const HARDENING_RECOVERY_CACHE_CAPACITY: usize = HARDENING_POOL_CAPACITY;
const HARDENING_MAX_SERVER_CLOCK_SKEW_MS: i64 = 15_000;
const HARDENING_RECOVERY_MAX_SERVER_LIFETIME_MS: i64 =
    2 * 60 * 1000 + HARDENING_MAX_SERVER_CLOCK_SKEW_MS;
const HARDENING_RECOVERY_SCOPE_DOMAIN: &[u8] = b"MYSTIC/HARDENING/RECOVERY-SCOPE/V1";

#[derive(Clone, Copy)]
struct HardeningApplyRouteSpec {
    purpose: u32,
    route_id: u32,
    stage_id: u32,
    instruction_count: u32,
    program_domain: [u8; 8],
}

#[derive(Clone, Copy)]
struct HardeningApplyIdentity {
    vm_schema_version: u32,
    purpose: u32,
    route_id: u32,
    stage_id: u32,
}

#[derive(Clone, Copy)]
enum HardeningStageKind {
    FunctionalApply(HardeningApplyIdentity),
    ProtectedBundle,
}

const HARDENING_APPLY_ROUTES: [HardeningApplyRouteSpec; 2] = [
    HardeningApplyRouteSpec {
        purpose: HARDENING_PURPOSE_FUNCTIONAL,
        route_id: HARDENING_ATTESTATION_KEY_IMPORT_ROUTE,
        stage_id: HARDENING_INITIAL_STAGE,
        instruction_count: 2,
        program_domain: HARDENING_ATTESTATION_KEY_IMPORT_PROGRAM_DOMAIN,
    },
    HardeningApplyRouteSpec {
        purpose: HARDENING_PURPOSE_FUNCTIONAL,
        route_id: HARDENING_PROCESSED_REPLY_ROUTE,
        stage_id: HARDENING_INITIAL_STAGE,
        instruction_count: 1,
        program_domain: HARDENING_PROCESSED_REPLY_PROGRAM_DOMAIN,
    },
];
const HARDENING_MAX_CHAIN_CERTIFICATES: usize = 16;
const HARDENING_MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const HARDENING_MAX_CHAIN_BYTES: usize = 256 * 1024;
const HARDENING_MAX_SERVER_LIFETIME_MS: i64 = 30_000;
const HARDENING_BEGIN_RPC_TIMEOUT_MS: i64 = 5_000;
const HARDENING_RPC_MAX_ATTEMPT_TIMEOUT_MS: i64 = 5_000;
const HARDENING_RPC_MIN_ATTEMPT_TIMEOUT_MS: i64 = 250;
const HARDENING_RPC_RETRY_DELAY_MS: i64 = 250;
const HARDENING_RPC_EXPIRY_MARGIN_MS: i64 = 500;
const HARDENING_POOL_MAX_SERVER_LIFETIME_MS: i64 = 15 * 60 * 1_000;
const HARDENING_COMPLETION_MAX_SERVER_LIFETIME_MS: i64 = 5 * 60 * 1_000;
const HARDENING_POOL_CLAIM_UNKNOWN_LIFETIME_MS: i64 = HARDENING_MAX_SERVER_LIFETIME_MS;
const HARDENING_POOL_CAPACITY: usize = 15;
const HARDENING_POOL_REFILL_THRESHOLD: usize = 1;
const HARDENING_POOL_FOREGROUND_WAIT_MS: u64 = 1_000;
const HARDENING_POOL_SCOPE_DOMAIN: &[u8] = b"MYSTIC/HARDENING/WRAPPING-KEY-POOL-SCOPE/V1";
const HARDENING_POOL_PREPARE_DOMAIN: &[u8] = b"MYSTIC/HARDENING/WRAPPING-KEY-PREPARE/V1";
const GRPC_SERVICE: &str = "mystic.attestation.public.v1.AttestationOverwriter";
const OVERWRITE_ATTESTATION_PATH: &str =
    "/mystic.attestation.public.v1.AttestationOverwriter/OverwriteAttestation";
const PROVISION_ATTESTATION_KEY_PATH: &str =
    "/mystic.attestation.public.v1.AttestationOverwriter/ProvisionAttestationKey";

static BACKEND_CHANNEL: OnceLock<Channel> = OnceLock::new();
static TOKIO_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static PROCESSOR_SHA256: OnceLock<Result<[u8; 32], ()>> = OnceLock::new();
static HARDENING_KEY_RECOVERY: OnceLock<bool> = OnceLock::new();
static HARDENING_WRAPPING_POOL: OnceLock<HardeningWrappingPool> = OnceLock::new();
static HARDENING_RECOVERY_CACHE: OnceLock<Mutex<HardeningRecoveryCacheState>> = OnceLock::new();

const ATRACE_TAG: u64 = 1 << 0;

/// Clears sensitive bytes before their storage is released.
#[allow(clippy::undocumented_unsafe_blocks)]
fn secure_wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // A volatile store prevents the compiler from deleting this clear.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Deref for SensitiveBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SensitiveBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        secure_wipe(&mut self.0);
    }
}

struct SensitiveKey([u8; 32]);

impl Deref for SensitiveKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveKey {
    fn drop(&mut self) {
        secure_wipe(&mut self.0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardeningCryptoNamespace {
    Release,
    Debug,
}

impl HardeningCryptoNamespace {
    fn wire_value(self) -> u32 {
        match self {
            Self::Release => 1,
            Self::Debug => 2,
        }
    }

    fn wire_enum(self) -> HardeningCryptoNamespaceV1 {
        match self {
            Self::Release => HardeningCryptoNamespaceV1::HARDENING_CRYPTO_NAMESPACE_RELEASE,
            Self::Debug => HardeningCryptoNamespaceV1::HARDENING_CRYPTO_NAMESPACE_DEBUG,
        }
    }

    fn capability_domain(self) -> &'static [u8] {
        match self {
            Self::Release => b"MYSTIC/RELEASE/HARDENING/CAPABILITY/V1",
            Self::Debug => b"MYSTIC/DEBUG/HARDENING/CAPABILITY/V1",
        }
    }

    fn outer_domain(self) -> &'static [u8] {
        match self {
            Self::Release => b"MYSTIC/RELEASE/HARDENING/OUTER/V1",
            Self::Debug => b"MYSTIC/DEBUG/HARDENING/OUTER/V1",
        }
    }

    fn runtime_domain(self) -> &'static [u8] {
        match self {
            Self::Release => b"MYSTIC/RELEASE/HARDENING/RUNTIME/V1",
            Self::Debug => b"MYSTIC/DEBUG/HARDENING/RUNTIME/V1",
        }
    }

    fn apply_key_domain(self) -> &'static [u8] {
        match self {
            Self::Release => b"MYSTIC/RELEASE/HARDENING/APPLY-KEY/V1",
            Self::Debug => b"MYSTIC/DEBUG/HARDENING/APPLY-KEY/V1",
        }
    }

    fn apply_authorization_domain(self) -> &'static [u8] {
        match self {
            Self::Release => b"MYSTIC/RELEASE/HARDENING/APPLY-AUTH/V1",
            Self::Debug => b"MYSTIC/DEBUG/HARDENING/APPLY-AUTH/V1",
        }
    }

    fn consume_domain(self) -> &'static [u8] {
        match self {
            Self::Release => b"MYSTIC/RELEASE/HARDENING/GRANT-CONSUME/V1",
            Self::Debug => b"MYSTIC/DEBUG/HARDENING/GRANT-CONSUME/V1",
        }
    }

    fn sealed_payload_domain(self) -> &'static [u8] {
        match self {
            Self::Release => b"MYSTIC/RELEASE/HARDENING/SEALED-PAYLOAD/V1",
            Self::Debug => b"MYSTIC/DEBUG/HARDENING/SEALED-PAYLOAD/V1",
        }
    }
}

struct CanonicalWriter(SensitiveBytes);

impl CanonicalWriter {
    fn new() -> Self {
        Self(SensitiveBytes::new(Vec::new()))
    }

    fn field(&mut self, value: &[u8]) -> Result<(), String> {
        let size = u32::try_from(value.len())
            .map_err(|_| "hardening canonical field is too large".to_owned())?;
        self.0 .0.extend_from_slice(&size.to_be_bytes());
        self.0 .0.extend_from_slice(value);
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), String> {
        self.field(value.as_bytes())
    }

    fn u32(&mut self, value: u32) {
        self.0 .0.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0 .0.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

struct HardeningTranscriptV1<'a> {
    protocol_minor: u32,
    context_sha256: &'a [u8; 32],
    build_id: &'a str,
    payload_sha256: &'a [u8; 32],
    session_id: &'a str,
    grant_id: &'a str,
    grant_generation: u64,
    crypto_namespace: HardeningCryptoNamespace,
    server_nonce: &'a [u8; 32],
    purpose: u32,
    route_id: u32,
    stage_id: u32,
    device_identity_spki_sha256: &'a [u8; 32],
    wrapping_key_id: &'a str,
    latent_binding: &'a [u8],
    wrapping_spki_sha256: &'a [u8; 32],
    wrapping_attestation_sha256: &'a [u8; 32],
    request_sha256: &'a [u8; 32],
    response_sha256: &'a [u8; 32],
    previous_receipt: &'a [u8],
    voucher: &'a [u8],
    server_expires_at_ms: u64,
    policy_epoch: u64,
}

#[derive(Clone, Copy)]
struct HardeningGrantBinding<'a> {
    build_id: &'a str,
    session_id: &'a str,
    grant_id: &'a str,
    grant_generation: u64,
    crypto_namespace: HardeningCryptoNamespace,
    server_nonce: &'a [u8; 32],
    transcript_sha256: &'a [u8; 32],
    policy_epoch: u64,
}

#[link(name = "cutils")]
unsafe extern "C" {
    fn atrace_get_enabled_tags() -> u64;
    fn atrace_begin_body(name: *const c_char);
    fn atrace_end_body();
}

/// Emits a named Android trace section when Perfetto tracing is enabled.
struct TraceSection(bool);

#[allow(clippy::undocumented_unsafe_blocks)]
impl TraceSection {
    fn new(name: &'static [u8]) -> Self {
        debug_assert!(name.last() == Some(&0));
        let enabled = unsafe { atrace_get_enabled_tags() } & ATRACE_TAG != 0;
        if enabled {
            unsafe { atrace_begin_body(name.as_ptr().cast()) };
        }

        Self(enabled)
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
impl Drop for TraceSection {
    fn drop(&mut self) {
        if self.0 {
            unsafe { atrace_end_body() };
        }
    }
}

/// Routes overwrite requests through the proxy instead of the direct backend.
pub const USE_BACKEND_PROXY: bool = false;

/// Enables verbose Droidfood-only diagnostics in this processor binary.
pub const INTENSIVE_LOGS_ENABLED: bool = true;

fn backend_grpc_target() -> &'static str {
    if USE_BACKEND_PROXY {
        BACKEND_GRPC_PROXY_TARGET
    } else {
        BACKEND_GRPC_DIRECT_TARGET
    }
}

macro_rules! intensive_log {
    ($($arg:tt)+) => {
        if INTENSIVE_LOGS_ENABLED {
            debug!($($arg)+);
        }
    };
}

/// The `IKeystoreCertificatePostProcessor` implementation.
pub struct KeystoreCertificatePostProcessor;

impl Interface for KeystoreCertificatePostProcessor {}

impl IKeystoreCertificatePostProcessor for KeystoreCertificatePostProcessor {
    fn processKeystoreCertificates(
        &self,
        old_keymint_certificates: &CertificateChain,
    ) -> Result<CertificateChain, Status> {
        let _trace = TraceSection::new(b"mystic.overwrite.total\0");
        if is_internal_identity_certificate(&old_keymint_certificates.leafCertificate) {
            intensive_log!("skipping overwrite for internal KeyMint identity attestation");
            return Ok(CertificateChain {
                leafCertificate: old_keymint_certificates.leafCertificate.clone(),
                remainingChain: old_keymint_certificates.remainingChain.clone(),
            });
        }
        validate_certificate_input(
            &old_keymint_certificates.leafCertificate,
            &old_keymint_certificates.remainingChain,
        )
        .map_err(|err| service_error(ERROR_SERVER_REQUEST, &err))?;

        match leaf_is_signed_by_first_issuer(
            &old_keymint_certificates.leafCertificate,
            &old_keymint_certificates.remainingChain,
        ) {
            Ok(true) => {}
            Ok(false) => {
                intensive_log!(
                    "attestation leaf does not match the supplied attest key; requesting V2 reprovisioning"
                );
                return Err(service_error(
                    ERROR_REPROVISION_ATTESTATION_KEY,
                    "Supplied attestation key does not sign the generated certificate.",
                ));
            }
            Err(err) => {
                return Err(service_error(ERROR_SERVER_REQUEST, &err));
            }
        }

        let request_id = Uuid::new_v4().to_string();
        intensive_log!("sending attestation overwrite request: request_id={request_id}");

        let device_identity = load_or_generate_device_identity()?;
        let response_key = generate_response_key(&request_id)?;
        let response = request_overwrite(
            &request_id,
            &old_keymint_certificates.leafCertificate,
            &old_keymint_certificates.remainingChain,
            &device_identity,
            &response_key.certificate_chain,
        );
        let response = match response {
            Ok(response) => response,
            Err(OverwriteRequestError::InvalidArgument(message)) => {
                intensive_log!(
                    "attestation overwrite rejected: request_id={request_id} message={message}"
                );
                return Err(service_error(ERROR_SERVER_REQUEST, &message));
            }
            Err(OverwriteRequestError::Backend(message)) => {
                intensive_log!(
                    "attestation overwrite backend failed: request_id={request_id} error={message}"
                );
                return Err(service_error(ERROR_SERVER_REQUEST, &message));
            }
        };

        let decrypted = match decrypt_response(&request_id, &response_key.descriptor, &response) {
            Ok(decrypted) => decrypted,
            Err(err) => {
                intensive_log!(
                    "attestation overwrite encrypted response failed: request_id={request_id} error={err}"
                );
                return Err(service_error(ERROR_SERVER_RESPONSE, &err));
            }
        };

        if decrypted.reprovision_attestation_key {
            intensive_log!(
                "backend requested V2 attestation-key reprovisioning: request_id={request_id}"
            );
            return Err(service_error(
                ERROR_REPROVISION_ATTESTATION_KEY,
                "Backend requested attestation-key reprovisioning.",
            ));
        }

        validate_overwritten_chain(
            &old_keymint_certificates.leafCertificate,
            &decrypted.leaf_certificate,
            &decrypted.remaining_chain,
        )
        .map_err(|err| {
            intensive_log!(
                "attestation overwrite response is invalid: request_id={request_id} error={err}"
            );
            service_error(ERROR_SERVER_RESPONSE, &err)
        })?;

        if decrypted.leaf_certificate == old_keymint_certificates.leafCertificate
            && decrypted.remaining_chain == old_keymint_certificates.remainingChain
        {
            error!(
                "attestation overwrite backend authorized original-chain fallback: request_id={request_id}"
            );
        }

        intensive_log!(
            "attestation overwrite response received: request_id={} leaf_bytes={} chain_bytes={}",
            request_id,
            decrypted.leaf_certificate.len(),
            decrypted.remaining_chain.len()
        );
        Ok(CertificateChain {
            leafCertificate: decrypted.leaf_certificate,
            remainingChain: decrypted.remaining_chain,
        })
    }
}

impl IBackendAttestationKeyProvisioner for KeystoreCertificatePostProcessor {
    fn provisionAttestationKey(
        &self,
        certificate_profile: &BinderAttestationKeyCertificateProfile,
        wrapping_key_leaf_certificate: &[u8],
        wrapping_key_remaining_chain: &[u8],
    ) -> Result<ProvisionedAttestationKey, Status> {
        let _trace = TraceSection::new(b"mystic.provision.total\0");
        let request_id = Uuid::new_v4().to_string();
        intensive_log!("sending attestation-key provisioning request: request_id={request_id}");

        let device_identity = load_or_generate_device_identity()?;
        let response_key = generate_response_key(&request_id)?;
        let response = request_provision(
            &request_id,
            &device_identity,
            &response_key.certificate_chain,
            certificate_profile,
            wrapping_key_leaf_certificate,
            wrapping_key_remaining_chain,
        );
        let response = match response {
            Ok(response) => response,
            Err(OverwriteRequestError::InvalidArgument(message)) => {
                intensive_log!(
                    "attestation-key provisioning rejected: request_id={request_id} message={message}"
                );
                return Err(service_error(ERROR_SERVER_REQUEST, &message));
            }
            Err(OverwriteRequestError::Backend(message)) => {
                intensive_log!(
                    "attestation-key provisioning backend failed: request_id={request_id} error={message}"
                );
                return Err(service_error(ERROR_SERVER_REQUEST, &message));
            }
        };

        let decrypted = match decrypt_provision_response(
            &request_id,
            &response_key.descriptor,
            &response,
        ) {
            Ok(decrypted) => decrypted,
            Err(err) => {
                intensive_log!(
                    "attestation-key provisioning encrypted response failed: request_id={request_id} error={err}"
                );
                return Err(service_error(ERROR_SERVER_RESPONSE, &err));
            }
        };

        validate_provisioned_attestation_key(&decrypted).map_err(|err| {
            intensive_log!(
                "attestation-key provisioning material invalid: request_id={request_id} error={err}"
            );
            service_error(ERROR_SERVER_RESPONSE, &err)
        })?;

        intensive_log!(
            "attestation-key provisioning response received: request_id={} wrapper_bytes={} leaf_bytes={} chain_bytes={}",
            request_id,
            decrypted.secure_key_wrapper.len(),
            decrypted.leaf_certificate.len(),
            decrypted.remaining_chain.len()
        );
        Ok(ProvisionedAttestationKey {
            secureKeyWrapper: decrypted.secure_key_wrapper,
            leafCertificate: decrypted.leaf_certificate,
            remainingChain: decrypted.remaining_chain,
        })
    }

    fn authorizeHardeningStage(
        &self,
        context: &BinderHardeningStageContext,
    ) -> Result<BinderHardeningStageResult, Status> {
        if ThreadState::get_calling_uid() != AID_KEYSTORE {
            return Err(hardening_service_error());
        }
        reset_hardening_failure_disposition();
        authorize_hardening_stage(context).map_err(|_| hardening_failure_service_error())
    }

    fn completeProtectedStage(
        &self,
        completion: &BinderProtectedStageCompletion,
    ) -> Result<(), Status> {
        if ThreadState::get_calling_uid() != AID_KEYSTORE {
            return Err(service_error(
                ERROR_HARDENING_TERMINAL,
                "Protected stage completion is invalid.",
            ));
        }
        complete_protected_stage(completion).map_err(|error| {
            service_error(
                hardening_completion_service_code(error),
                "Protected stage completion failed.",
            )
        })
    }
}

fn complete_protected_stage(
    completion: &BinderProtectedStageCompletion,
) -> Result<(), HardeningCompletionError> {
    let schema_version =
        aidl_u32(completion.schemaVersion).map_err(|_| HardeningCompletionError::Terminal)?;
    let protocol_major =
        aidl_u32(completion.protocolMajor).map_err(|_| HardeningCompletionError::Terminal)?;
    let protocol_minor =
        aidl_u32(completion.protocolMinor).map_err(|_| HardeningCompletionError::Terminal)?;
    if schema_version != HARDENING_SCHEMA_VERSION
        || protocol_major != HARDENING_PROTOCOL_MAJOR
        || !valid_prefixed_lower_hex_16(&completion.sessionId, "hs_")
        || !valid_prefixed_lower_hex_16(&completion.grantId, "hgr_")
        || completion.contextSha256.len() != 32
        || completion.contextSha256.iter().all(|byte| *byte == 0)
        || completion.completionToken.len() != 32
        || completion.completionToken.iter().all(|byte| *byte == 0)
        || completion.receipt.is_empty()
        || completion.receipt.len() > HARDENING_MAX_TOKEN_BYTES
        || completion.nextVoucher.is_empty()
        || completion.nextVoucher.len() > HARDENING_MAX_TOKEN_BYTES
    {
        return Err(HardeningCompletionError::Terminal);
    }

    let identity =
        load_or_generate_device_identity().map_err(|_| HardeningCompletionError::Terminal)?;
    if !identity.untrusted_device_serial.is_empty() || identity.certificate_chain.is_empty() {
        return Err(HardeningCompletionError::Terminal);
    }

    let mut request = ProtectedCompletionRequest(ProtectedStageCompletionV1::new());
    request.0.schema_version = schema_version;
    request.0.protocol_major = protocol_major;
    request.0.protocol_minor = protocol_minor;
    request.0.session_id = completion.sessionId.clone();
    request.0.grant_id = completion.grantId.clone();
    request.0.context_sha256 = completion.contextSha256.clone();
    request.0.receipt = completion.receipt.clone();
    request.0.next_voucher = completion.nextVoucher.clone();
    request.0.completion_token = completion.completionToken.clone();
    request.0.device_identity_chain = identity.certificate_chain.clone();
    let digest = protected_stage_completion_digest(&request.0)
        .map_err(|_| HardeningCompletionError::Terminal)?;
    request.0.device_identity_signature = sign_device_identity(&identity.descriptor, &digest)
        .map_err(|_| HardeningCompletionError::Terminal)?;

    let response: Result<ProtectedStageCompletionResultV1, HardeningRpcError> =
        hardening_rpc_detailed(
            HARDENING_COMPLETE_PROTECTED_STAGE_PATH,
            &request.0,
            HardeningRpcWindow::Completion,
        );
    let response = response.map_err(HardeningCompletionError::Rpc)?;
    let now_ms = unix_time_ms().map_err(|_| HardeningCompletionError::Terminal)?;
    if response.schema_version != HARDENING_SCHEMA_VERSION
        || response.protocol_major != HARDENING_PROTOCOL_MAJOR
        || response.protocol_minor != protocol_minor
        || response.server_expires_at_ms <= now_ms
        || response.server_expires_at_ms.saturating_sub(now_ms)
            > HARDENING_COMPLETION_MAX_SERVER_LIFETIME_MS
    {
        return Err(HardeningCompletionError::Terminal);
    }
    Ok(())
}

struct ProtectedCompletionRequest(ProtectedStageCompletionV1);

impl Drop for ProtectedCompletionRequest {
    fn drop(&mut self) {
        wipe_string(&mut self.0.session_id);
        wipe_string(&mut self.0.grant_id);
        secure_wipe(&mut self.0.context_sha256);
        secure_wipe(&mut self.0.receipt);
        secure_wipe(&mut self.0.next_voucher);
        secure_wipe(&mut self.0.completion_token);
        for certificate in &mut self.0.device_identity_chain {
            secure_wipe(certificate);
        }
        self.0.device_identity_chain.clear();
        secure_wipe(&mut self.0.device_identity_signature);
    }
}

fn hardening_completion_service_code(error: HardeningCompletionError) -> i32 {
    match error {
        HardeningCompletionError::Rpc(error) if hardening_completion_rpc_retryable(error) => {
            ERROR_HARDENING_UNAVAILABLE
        }
        HardeningCompletionError::Terminal | HardeningCompletionError::Rpc(_) => {
            ERROR_HARDENING_TERMINAL
        }
    }
}

fn hardening_completion_rpc_retryable(error: HardeningRpcError) -> bool {
    matches!(
        error,
        HardeningRpcError::Transient
            | HardeningRpcError::Status(
                Code::Unavailable | Code::DeadlineExceeded | Code::Cancelled
            )
    )
}

fn valid_prefixed_lower_hex_16(value: &str, prefix: &str) -> bool {
    let Some(encoded) = value.strip_prefix(prefix) else {
        return false;
    };
    encoded.len() == 32
        && encoded.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn protected_stage_completion_digest(
    value: &ProtectedStageCompletionV1,
) -> HardeningResult<[u8; 32]> {
    let mut canonical = CanonicalWriter::new();
    canonical.field(HARDENING_PROTECTED_COMPLETION_DOMAIN).map_err(|_| HardeningFailure)?;
    canonical.u32(value.schema_version);
    canonical.u32(value.protocol_major);
    canonical.u32(value.protocol_minor);
    canonical.text(&value.session_id).map_err(|_| HardeningFailure)?;
    canonical.text(&value.grant_id).map_err(|_| HardeningFailure)?;
    canonical.field(&value.context_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&value.receipt).map_err(|_| HardeningFailure)?;
    canonical.field(&value.next_voucher).map_err(|_| HardeningFailure)?;
    canonical.field(&value.completion_token).map_err(|_| HardeningFailure)?;
    Ok(sha256(canonical.bytes()))
}

struct ResponseKey {
    descriptor: KeyDescriptor,
    certificate_chain: Vec<Vec<u8>>,
}

impl Drop for ResponseKey {
    fn drop(&mut self) {
        delete_key(&self.descriptor);
    }
}

#[derive(Clone)]
struct DeviceIdentityKey {
    descriptor: KeyDescriptor,
    certificate_chain: Vec<Vec<u8>>,
    untrusted_device_serial: String,
}

#[derive(Clone, Copy, Debug)]
struct HardeningFailure;

type HardeningResult<T> = Result<T, HardeningFailure>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum HardeningFailureDisposition {
    Unknown,
    Transient,
    Terminal,
}

thread_local! {
    static HARDENING_FAILURE_DISPOSITION: Cell<HardeningFailureDisposition> =
        const { Cell::new(HardeningFailureDisposition::Unknown) };
    static HARDENING_FAILURE_REASON: Cell<&'static str> = const { Cell::new("unspecified") };
}

fn reset_hardening_failure_disposition() {
    HARDENING_FAILURE_DISPOSITION.with(|value| value.set(HardeningFailureDisposition::Unknown));
    HARDENING_FAILURE_REASON.with(|value| value.set("unspecified"));
}

fn hardening_failure_with_reason(reason: &'static str) -> HardeningFailure {
    HARDENING_FAILURE_REASON.with(|value| value.set(reason));
    HardeningFailure
}

fn take_hardening_failure_reason() -> &'static str {
    HARDENING_FAILURE_REASON.with(|value| value.replace("unspecified"))
}

fn record_hardening_rpc_error(error: HardeningRpcError) -> HardeningRpcError {
    HARDENING_FAILURE_DISPOSITION.with(|value| {
        let next = if error.is_transient() {
            HardeningFailureDisposition::Transient
        } else {
            HardeningFailureDisposition::Terminal
        };
        if value.get() != HardeningFailureDisposition::Terminal {
            value.set(next);
        }
    });
    error
}

fn hardening_failure_service_error() -> Status {
    let disposition = HARDENING_FAILURE_DISPOSITION.with(Cell::get);
    if disposition == HardeningFailureDisposition::Transient {
        hardening_service_error()
    } else {
        service_error(ERROR_HARDENING_TERMINAL, "Hardening runtime validation failed.")
    }
}

trait HardeningKeyDeleter {
    fn delete(&self, descriptor: &KeyDescriptor) -> HardeningResult<()>;
}

#[derive(Clone, Copy)]
struct BinderHardeningKeyDeleter;

impl HardeningKeyDeleter for BinderHardeningKeyDeleter {
    fn delete(&self, descriptor: &KeyDescriptor) -> HardeningResult<()> {
        raw_keystore_service()
            .and_then(|keystore| keystore.deleteKey(descriptor))
            .map_err(|_| HardeningFailure)
    }
}

struct TemporaryHardeningKey<D: HardeningKeyDeleter = BinderHardeningKeyDeleter> {
    descriptor: Option<KeyDescriptor>,
    deleter: D,
}

impl TemporaryHardeningKey<BinderHardeningKeyDeleter> {
    fn new(descriptor: KeyDescriptor) -> Self {
        Self { descriptor: Some(descriptor), deleter: BinderHardeningKeyDeleter }
    }
}

impl<D: HardeningKeyDeleter> TemporaryHardeningKey<D> {
    fn descriptor(&self) -> HardeningResult<&KeyDescriptor> {
        self.descriptor.as_ref().ok_or(HardeningFailure)
    }

    fn delete_checked(mut self) -> HardeningResult<()> {
        let descriptor = self.descriptor.as_ref().ok_or(HardeningFailure)?;
        self.deleter.delete(descriptor)?;
        if let Some(mut descriptor) = self.descriptor.take() {
            wipe_key_descriptor(&mut descriptor);
        }
        Ok(())
    }

    fn into_descriptor(mut self) -> HardeningResult<KeyDescriptor> {
        self.descriptor.take().ok_or(HardeningFailure)
    }
}

impl<D: HardeningKeyDeleter> Drop for TemporaryHardeningKey<D> {
    fn drop(&mut self) {
        if let Some(mut descriptor) = self.descriptor.take() {
            if self.deleter.delete(&descriptor).is_err() {
                error!("failed to delete temporary runtime stage key");
            }
            wipe_key_descriptor(&mut descriptor);
        }
    }
}

struct HardeningStageInput {
    context: HardeningContextV1,
    next_transition_sha256: [u8; 32],
    kind: HardeningStageKind,
    recovery_scope_sha256: Option<[u8; 32]>,
    recovery: Option<HardeningRecoveryUse>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HardeningRecoveryUse {
    selector: [u8; HARDENING_RECOVERY_SELECTOR_BYTES],
    expires_at_ms: i64,
}

struct HardeningRecoveryCacheEntry {
    scope_sha256: [u8; 32],
    selector: [u8; HARDENING_RECOVERY_SELECTOR_BYTES],
    expires_at_ms: i64,
}

impl Drop for HardeningRecoveryCacheEntry {
    fn drop(&mut self) {
        secure_wipe(&mut self.scope_sha256);
        secure_wipe(&mut self.selector);
        self.expires_at_ms = 0;
    }
}

#[derive(Default)]
struct HardeningRecoveryCacheState {
    entries: Vec<HardeningRecoveryCacheEntry>,
}

impl HardeningRecoveryCacheState {
    fn claim(
        &mut self,
        scope_sha256: &[u8; 32],
        now_ms: i64,
    ) -> HardeningResult<Option<HardeningRecoveryUse>> {
        if let Some(index) =
            self.entries.iter().position(|entry| memcmp::eq(&entry.scope_sha256, scope_sha256))
        {
            if self.entries[index].expires_at_ms <= now_ms {
                self.entries.swap_remove(index);
                return Ok(None);
            }
        }
        self.entries.retain(|entry| entry.expires_at_ms > now_ms);
        let Some(index) =
            self.entries.iter().position(|entry| memcmp::eq(&entry.scope_sha256, scope_sha256))
        else {
            return Ok(None);
        };
        let entry = &self.entries[index];
        Ok(Some(HardeningRecoveryUse {
            selector: entry.selector,
            expires_at_ms: entry.expires_at_ms,
        }))
    }

    fn remember(
        &mut self,
        scope_sha256: [u8; 32],
        selector: [u8; HARDENING_RECOVERY_SELECTOR_BYTES],
        expires_at_ms: i64,
        now_ms: i64,
    ) -> HardeningResult<()> {
        self.entries.retain(|entry| entry.expires_at_ms > now_ms);
        if expires_at_ms <= now_ms {
            return Err(HardeningFailure);
        }
        if let Some(entry) =
            self.entries.iter_mut().find(|entry| memcmp::eq(&entry.scope_sha256, &scope_sha256))
        {
            if !memcmp::eq(&entry.selector, &selector) || entry.expires_at_ms != expires_at_ms {
                return Err(HardeningFailure);
            }
            return Ok(());
        }
        if self.entries.len() >= HARDENING_RECOVERY_CACHE_CAPACITY {
            return Err(HardeningFailure);
        }
        self.entries.push(HardeningRecoveryCacheEntry { scope_sha256, selector, expires_at_ms });
        Ok(())
    }

    fn remove(&mut self, scope_sha256: &[u8; 32]) {
        if let Some(index) =
            self.entries.iter().position(|entry| memcmp::eq(&entry.scope_sha256, scope_sha256))
        {
            self.entries.swap_remove(index);
        }
    }
}

#[derive(Clone)]
struct HardeningWrappingPoolTarget {
    scope: WrappingKeyPoolScopeV1,
    binding_sha256: [u8; 32],
    device_identity: DeviceIdentityKey,
}

enum HardeningStageAttempt {
    Complete(BinderHardeningStageResult),
    RetryFresh(HardeningWrappingPoolTarget),
}

struct PooledHardeningWrappingKey {
    descriptor: KeyDescriptor,
    wrapping_key_id: String,
    binding_sha256: [u8; 32],
    wrapping_spki_sha256: [u8; 32],
    wrapping_attestation_sha256: [u8; 32],
    server_expires_at_ms: i64,
    namespace: Option<HardeningCryptoNamespace>,
    recovering: bool,
}

impl PooledHardeningWrappingKey {
    fn use_view(&self) -> HardeningWrappingKeyUse {
        HardeningWrappingKeyUse {
            descriptor: self.descriptor.clone(),
            wrapping_key_id: self.wrapping_key_id.clone(),
            wrapping_spki_sha256: self.wrapping_spki_sha256,
            wrapping_attestation_sha256: self.wrapping_attestation_sha256,
        }
    }
}

impl Drop for PooledHardeningWrappingKey {
    fn drop(&mut self) {
        if BinderHardeningKeyDeleter.delete(&self.descriptor).is_err() {
            error!("failed to delete prepared wrapping key");
        }
        wipe_key_descriptor(&mut self.descriptor);
        wipe_string(&mut self.wrapping_key_id);
    }
}

struct ClaimedHardeningWrappingKey {
    key: PooledHardeningWrappingKey,
    context_sha256: [u8; 32],
    expires_at_ms: i64,
    target: HardeningWrappingPoolTarget,
    cleanup_scheduled: bool,
    recovery_registration_allowed: bool,
}

struct PendingHardeningWrappingKey {
    wrapping_key_id: String,
    binding_sha256: [u8; 32],
}

#[derive(Default)]
struct HardeningWrappingPoolState {
    ready: Vec<PooledHardeningWrappingKey>,
    claimed: Vec<ClaimedHardeningWrappingKey>,
    pending: Option<PendingHardeningWrappingKey>,
    worker_active: bool,
    next_waiter_ticket: u64,
    serving_waiter_ticket: u64,
    cancelled_waiter_tickets: HashSet<u64>,
    quarantined_bindings: HashSet<[u8; 32]>,
}

struct HardeningWrappingPool {
    state: Mutex<HardeningWrappingPoolState>,
    ready_changed: Condvar,
}

impl Default for HardeningWrappingPool {
    fn default() -> Self {
        Self {
            state: Mutex::new(HardeningWrappingPoolState::default()),
            ready_changed: Condvar::new(),
        }
    }
}

struct HardeningWrappingKeyUse {
    descriptor: KeyDescriptor,
    wrapping_key_id: String,
    wrapping_spki_sha256: [u8; 32],
    wrapping_attestation_sha256: [u8; 32],
}

struct HardeningPoolClaim {
    wrapping_key_id: String,
    context_sha256: [u8; 32],
    target: HardeningWrappingPoolTarget,
    expires_at_ms: i64,
    registration_expires_at_ms: i64,
    recovery_registration_allowed: bool,
    completed: bool,
}

impl HardeningPoolClaim {
    fn update_expiry(&mut self, expires_at_ms: i64) {
        self.expires_at_ms = expires_at_ms;
        update_hardening_pool_claim_expiry(
            &self.wrapping_key_id,
            &self.context_sha256,
            expires_at_ms,
        );
    }

    fn complete(&mut self) {
        if self.completed {
            return;
        }
        complete_hardening_pool_claim(
            &self.wrapping_key_id,
            &self.context_sha256,
            self.target.clone(),
        );
        self.completed = true;
    }

    fn discard_without_refill(&mut self) -> HardeningWrappingPoolTarget {
        if !self.completed {
            discard_hardening_pool_claim(&self.wrapping_key_id, &self.context_sha256);
            self.completed = true;
        }
        self.target.clone()
    }

    fn mark_registration_recovered(&mut self) {
        self.recovery_registration_allowed = false;
        mark_hardening_pool_registration_recovered(&self.wrapping_key_id, &self.context_sha256);
    }
}

impl Drop for HardeningPoolClaim {
    fn drop(&mut self) {
        if !self.completed {
            retain_failed_hardening_pool_claim(
                &self.wrapping_key_id,
                &self.context_sha256,
                self.target.clone(),
                self.expires_at_ms,
            );
        }
        wipe_string(&mut self.wrapping_key_id);
    }
}

struct HardeningWrappingKeyMaterial {
    key_use: HardeningWrappingKeyUse,
    fresh_key: Option<TemporaryHardeningKey>,
    pool_claim: Option<HardeningPoolClaim>,
}

#[derive(Clone, Copy)]
enum HardeningRpcWindow {
    Begin,
    Completion,
    Grant { expires_at_ms: i64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardeningCompletionError {
    Terminal,
    Rpc(HardeningRpcError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardeningRpcError {
    Status(Code),
    Transient,
}

impl HardeningRpcError {
    fn is_transient(self) -> bool {
        matches!(
            self,
            Self::Transient
                | Self::Status(
                    Code::Unavailable
                        | Code::DeadlineExceeded
                        | Code::Cancelled
                        | Code::ResourceExhausted
                        | Code::Aborted
                        | Code::Internal
                        | Code::Unknown
                )
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PooledBeginFailureClass {
    Transient,
    KeyRejected,
    ScopeRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PooledGrantFailureClass {
    Transient,
    KeyRejected,
    ScopeRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardeningPoolPreparationError {
    Transient,
    RefillClosed,
    CandidateRejected,
    ScopeRejected,
}

impl From<HardeningFailure> for HardeningPoolPreparationError {
    fn from(_: HardeningFailure) -> Self {
        Self::CandidateRejected
    }
}

fn classify_pool_prepare_rpc_failure(
    error: HardeningRpcError,
    registration: bool,
) -> HardeningPoolPreparationError {
    if error.is_transient() && error != HardeningRpcError::Status(Code::ResourceExhausted) {
        return HardeningPoolPreparationError::Transient;
    }
    match error {
        HardeningRpcError::Status(Code::ResourceExhausted) if !registration => {
            HardeningPoolPreparationError::RefillClosed
        }
        HardeningRpcError::Status(Code::PermissionDenied | Code::InvalidArgument) => {
            HardeningPoolPreparationError::ScopeRejected
        }
        _ => HardeningPoolPreparationError::CandidateRejected,
    }
}

fn classify_pooled_begin_failure(error: HardeningRpcError) -> PooledBeginFailureClass {
    if error.is_transient() {
        return PooledBeginFailureClass::Transient;
    }
    match error {
        HardeningRpcError::Status(
            Code::InvalidArgument | Code::NotFound | Code::FailedPrecondition,
        ) => PooledBeginFailureClass::KeyRejected,
        _ => PooledBeginFailureClass::ScopeRejected,
    }
}

fn classify_pooled_grant_failure(error: HardeningRpcError) -> PooledGrantFailureClass {
    if error.is_transient() {
        return PooledGrantFailureClass::Transient;
    }
    match error {
        HardeningRpcError::Status(Code::NotFound | Code::FailedPrecondition) => {
            PooledGrantFailureClass::KeyRejected
        }
        _ => PooledGrantFailureClass::ScopeRejected,
    }
}

fn pooled_grant_fresh_retry_target(
    error: HardeningRpcError,
    pool_claim: Option<&mut HardeningPoolClaim>,
    rejected_pool_target: Option<&HardeningWrappingPoolTarget>,
) -> Option<HardeningWrappingPoolTarget> {
    let failure_class = classify_pooled_grant_failure(error);
    if let Some(pool_claim) = pool_claim {
        match failure_class {
            PooledGrantFailureClass::Transient => None,
            PooledGrantFailureClass::KeyRejected => Some(pool_claim.discard_without_refill()),
            PooledGrantFailureClass::ScopeRejected => {
                let target = pool_claim.discard_without_refill();
                quarantine_hardening_pool_scope(target.binding_sha256);
                None
            }
        }
    } else {
        if failure_class != PooledGrantFailureClass::Transient {
            if let Some(target) = rejected_pool_target {
                quarantine_hardening_pool_scope(target.binding_sha256);
            }
        }
        None
    }
}

enum OverwriteRequestError {
    InvalidArgument(String),
    Backend(String),
}

enum ProvisionAttemptError {
    InvalidArgument(String),
    Retryable(String),
    Backend(String),
}

fn hardening_phase<T>(phase: &'static str, result: HardeningResult<T>) -> HardeningResult<T> {
    match result {
        Ok(value) => {
            let _ = take_hardening_failure_reason();
            intensive_log!("optional runtime stage phase completed: phase={phase}");
            Ok(value)
        }
        Err(error) => {
            let reason = take_hardening_failure_reason();
            intensive_log!("optional runtime stage phase failed: phase={phase} reason={reason}");
            Err(error)
        }
    }
}

fn hardening_wrapping_pool() -> &'static HardeningWrappingPool {
    HARDENING_WRAPPING_POOL.get_or_init(HardeningWrappingPool::default)
}

fn claim_hardening_recovery(
    scope_sha256: &[u8; 32],
    now_ms: i64,
) -> HardeningResult<Option<HardeningRecoveryUse>> {
    HARDENING_RECOVERY_CACHE
        .get_or_init(|| Mutex::new(HardeningRecoveryCacheState::default()))
        .lock()
        .map_err(|_| HardeningFailure)?
        .claim(scope_sha256, now_ms)
}

fn remember_hardening_recovery(
    scope_sha256: [u8; 32],
    selector: [u8; HARDENING_RECOVERY_SELECTOR_BYTES],
    expires_at_ms: i64,
    now_ms: i64,
) -> HardeningResult<()> {
    HARDENING_RECOVERY_CACHE
        .get_or_init(|| Mutex::new(HardeningRecoveryCacheState::default()))
        .lock()
        .map_err(|_| HardeningFailure)?
        .remember(scope_sha256, selector, expires_at_ms, now_ms)
}

fn clear_hardening_recovery(scope_sha256: &[u8; 32]) {
    if let Ok(mut cache) = HARDENING_RECOVERY_CACHE
        .get_or_init(|| Mutex::new(HardeningRecoveryCacheState::default()))
        .lock()
    {
        cache.remove(scope_sha256);
    }
}

struct HardeningRecoveryGuard {
    scope_sha256: Option<[u8; 32]>,
    recovery_flow: bool,
    retain: bool,
}

impl HardeningRecoveryGuard {
    fn new(scope_sha256: Option<[u8; 32]>, recovery_flow: bool) -> Self {
        Self { scope_sha256, recovery_flow, retain: false }
    }

    fn retain_for_fresh_retry(&mut self) {
        if self.recovery_flow {
            self.retain = true;
        }
    }

    fn retain_after_ambiguous_consume(&mut self) {
        self.retain = true;
    }

    fn complete(&mut self) {
        if let Some(scope_sha256) = self.scope_sha256.take() {
            clear_hardening_recovery(&scope_sha256);
        }
    }

    fn retains_for_disposition(&self, disposition: HardeningFailureDisposition) -> bool {
        self.retain || (self.recovery_flow && disposition == HardeningFailureDisposition::Transient)
    }
}

impl Drop for HardeningRecoveryGuard {
    fn drop(&mut self) {
        let disposition = HARDENING_FAILURE_DISPOSITION.with(Cell::get);
        if !self.retains_for_disposition(disposition) {
            self.complete();
        }
        if let Some(mut scope_sha256) = self.scope_sha256.take() {
            secure_wipe(&mut scope_sha256);
        }
    }
}

fn prune_expired_hardening_pool_entries(
    state: &mut HardeningWrappingPoolState,
    now_ms: i64,
) -> Vec<HardeningWrappingPoolTarget> {
    let mut index = 0usize;
    while index < state.ready.len() {
        if state.ready[index].server_expires_at_ms <= now_ms {
            state.ready.swap_remove(index);
        } else {
            index += 1;
        }
    }

    let mut refill_targets = Vec::new();
    let mut index = 0usize;
    while index < state.claimed.len() {
        if state.claimed[index].expires_at_ms <= now_ms {
            let claimed = state.claimed.swap_remove(index);
            refill_targets.push(claimed.target);
        } else {
            index += 1;
        }
    }
    refill_targets
}

fn advance_hardening_pool_waiter(state: &mut HardeningWrappingPoolState) {
    state.serving_waiter_ticket = state.serving_waiter_ticket.saturating_add(1);
    while state.cancelled_waiter_tickets.remove(&state.serving_waiter_ticket) {
        state.serving_waiter_ticket = state.serving_waiter_ticket.saturating_add(1);
    }
}

fn cancel_hardening_pool_waiter(state: &mut HardeningWrappingPoolState, ticket: u64) {
    if ticket == state.serving_waiter_ticket {
        advance_hardening_pool_waiter(state);
    } else {
        state.cancelled_waiter_tickets.insert(ticket);
    }
}

fn hardening_pool_timeout_fallback<T>(
    state: &mut HardeningWrappingPoolState,
    ticket: u64,
) -> HardeningResult<Option<T>> {
    cancel_hardening_pool_waiter(state, ticket);
    Ok(None)
}

fn hardening_pool_waiter_can_claim(
    state: &HardeningWrappingPoolState,
    waiter_ticket: Option<u64>,
) -> bool {
    waiter_ticket.map_or_else(
        || state.next_waiter_ticket == state.serving_waiter_ticket,
        |ticket| ticket == state.serving_waiter_ticket,
    )
}

fn hardening_pool_live_count(
    ready: usize,
    claimed: usize,
    pending_or_in_flight: bool,
) -> Option<usize> {
    ready.checked_add(claimed)?.checked_add(usize::from(pending_or_in_flight))
}

fn hardening_pool_should_start_refill(
    ready: usize,
    claimed: usize,
    has_pending: bool,
    worker_active: bool,
) -> bool {
    if worker_active {
        return false;
    }
    if has_pending {
        return hardening_pool_live_count(ready, claimed, true)
            .is_some_and(|count| count <= HARDENING_POOL_CAPACITY);
    }
    ready <= HARDENING_POOL_REFILL_THRESHOLD
        && hardening_pool_live_count(ready, claimed, false)
            .is_some_and(|count| count < HARDENING_POOL_CAPACITY)
}

fn hardening_pool_can_prepare(ready: usize, claimed: usize) -> bool {
    hardening_pool_live_count(ready, claimed, true)
        .is_some_and(|count| count <= HARDENING_POOL_CAPACITY)
}

fn claim_hardening_pool_key(
    context: &mut HardeningContextV1,
    identity: &DeviceIdentityKey,
) -> HardeningResult<Option<(HardeningWrappingKeyUse, HardeningPoolClaim, [u8; 32])>> {
    let pool = hardening_wrapping_pool();
    let deadline = Instant::now() + Duration::from_millis(HARDENING_POOL_FOREGROUND_WAIT_MS);
    let mut waiter_ticket = None;

    loop {
        let now_ms = unix_time_ms()?;
        let mut state = pool.state.lock().map_err(|_| HardeningFailure)?;
        let refill_targets = prune_expired_hardening_pool_entries(&mut state, now_ms);
        drop(state);
        for target in refill_targets {
            schedule_hardening_pool_refill(target);
        }
        let mut state = pool.state.lock().map_err(|_| HardeningFailure)?;

        if let Some(ticket) = waiter_ticket {
            if ticket != state.serving_waiter_ticket {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    let fallback = hardening_pool_timeout_fallback(&mut state, ticket);
                    pool.ready_changed.notify_all();
                    return fallback;
                }
                let (next_state, timeout) = pool
                    .ready_changed
                    .wait_timeout(state, remaining)
                    .map_err(|_| HardeningFailure)?;
                state = next_state;
                if timeout.timed_out() {
                    let fallback = hardening_pool_timeout_fallback(&mut state, ticket);
                    pool.ready_changed.notify_all();
                    return fallback;
                }
                drop(state);
                continue;
            }
        }

        let can_claim = hardening_pool_waiter_can_claim(&state, waiter_ticket);
        let mut claimed_match = None;
        if can_claim {
            for claimed in &state.claimed {
                let namespace = claimed.key.namespace.ok_or(HardeningFailure)?;
                let target = hardening_pool_target(context, identity, namespace)?;
                if target.binding_sha256 != claimed.key.binding_sha256
                    || state.quarantined_bindings.contains(&target.binding_sha256)
                {
                    continue;
                }
                context.wrapping_key_id = claimed.key.wrapping_key_id.clone();
                let context_sha256 = hardening_context_digest(context)?;
                if context_sha256 != claimed.context_sha256 {
                    context.wrapping_key_id.clear();
                    continue;
                }
                claimed_match = Some((
                    claimed.key.use_view(),
                    HardeningPoolClaim {
                        wrapping_key_id: claimed.key.wrapping_key_id.clone(),
                        context_sha256,
                        target: claimed.target.clone(),
                        expires_at_ms: claimed.expires_at_ms,
                        registration_expires_at_ms: claimed.key.server_expires_at_ms,
                        recovery_registration_allowed: claimed.recovery_registration_allowed,
                        completed: false,
                    },
                    context_sha256,
                ));
                break;
            }
        }
        if let Some((key_use, claim, context_sha256)) = claimed_match {
            if waiter_ticket.is_some() {
                advance_hardening_pool_waiter(&mut state);
                pool.ready_changed.notify_all();
            }
            return Ok(Some((key_use, claim, context_sha256)));
        }

        let ready_match = can_claim
            .then(|| {
                state.ready.iter().enumerate().find_map(|(index, key)| {
                    [HardeningCryptoNamespace::Release, HardeningCryptoNamespace::Debug]
                        .into_iter()
                        .filter(|namespace| key.namespace.is_none_or(|stored| stored == *namespace))
                        .find_map(|namespace| {
                            hardening_pool_target(context, identity, namespace)
                                .ok()
                                .filter(|target| {
                                    target.binding_sha256 == key.binding_sha256
                                        && !state
                                            .quarantined_bindings
                                            .contains(&target.binding_sha256)
                                })
                                .map(|target| (index, namespace, target))
                        })
                })
            })
            .flatten();
        if let Some((ready_index, namespace, target)) = ready_match {
            let mut key = state.ready.swap_remove(ready_index);
            let recovery_registration_allowed = key.recovering;
            key.recovering = false;
            key.namespace = Some(namespace);
            context.wrapping_key_id = key.wrapping_key_id.clone();
            let context_sha256 = hardening_context_digest(context)?;
            let key_use = key.use_view();
            let wrapping_key_id = key.wrapping_key_id.clone();
            let registration_expires_at_ms = key.server_expires_at_ms;
            let expires_at_ms = now_ms
                .checked_add(HARDENING_POOL_CLAIM_UNKNOWN_LIFETIME_MS)
                .ok_or(HardeningFailure)?;
            state.claimed.push(ClaimedHardeningWrappingKey {
                key,
                context_sha256,
                expires_at_ms,
                target: target.clone(),
                cleanup_scheduled: false,
                recovery_registration_allowed,
            });
            let claim = HardeningPoolClaim {
                wrapping_key_id,
                context_sha256,
                target: target.clone(),
                expires_at_ms,
                registration_expires_at_ms,
                recovery_registration_allowed,
                completed: false,
            };
            let should_refill = state.ready.len() <= HARDENING_POOL_REFILL_THRESHOLD;
            if waiter_ticket.is_some() {
                advance_hardening_pool_waiter(&mut state);
            }
            drop(state);
            pool.ready_changed.notify_all();
            if should_refill {
                schedule_hardening_pool_refill(target);
            }
            return Ok(Some((key_use, claim, context_sha256)));
        }

        context.wrapping_key_id.clear();
        if !state.worker_active {
            if waiter_ticket.is_some() {
                advance_hardening_pool_waiter(&mut state);
                pool.ready_changed.notify_all();
            }
            return Ok(None);
        }

        let ticket = match waiter_ticket {
            Some(ticket) => ticket,
            None => {
                let ticket = state.next_waiter_ticket;
                state.next_waiter_ticket =
                    state.next_waiter_ticket.checked_add(1).ok_or(HardeningFailure)?;
                waiter_ticket = Some(ticket);
                ticket
            }
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let fallback = hardening_pool_timeout_fallback(&mut state, ticket);
            pool.ready_changed.notify_all();
            return fallback;
        }
        if ticket != state.serving_waiter_ticket {
            let (next_state, timeout) =
                pool.ready_changed.wait_timeout(state, remaining).map_err(|_| HardeningFailure)?;
            state = next_state;
            if timeout.timed_out() {
                let fallback = hardening_pool_timeout_fallback(&mut state, ticket);
                pool.ready_changed.notify_all();
                return fallback;
            }
            drop(state);
            continue;
        }
        let (next_state, timeout) =
            pool.ready_changed.wait_timeout(state, remaining).map_err(|_| HardeningFailure)?;
        state = next_state;
        if timeout.timed_out() {
            let fallback = hardening_pool_timeout_fallback(&mut state, ticket);
            pool.ready_changed.notify_all();
            return fallback;
        }
        drop(state);
    }
}

fn schedule_hardening_pool_refill(target: HardeningWrappingPoolTarget) {
    if HARDENING_KEY_RECOVERY.get().copied() != Some(true) {
        return;
    }
    let pool = hardening_wrapping_pool();
    let should_start = (|| -> HardeningResult<bool> {
        let now_ms = unix_time_ms()?;
        let mut state = pool.state.lock().map_err(|_| HardeningFailure)?;
        prune_expired_hardening_pool_entries(&mut state, now_ms);
        if state.quarantined_bindings.contains(&target.binding_sha256) {
            return Ok(false);
        }
        state.ready.retain(|key| key.binding_sha256 == target.binding_sha256);
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.binding_sha256 != target.binding_sha256)
        {
            state.pending = None;
        }
        if !hardening_pool_should_start_refill(
            state.ready.len(),
            state.claimed.len(),
            state.pending.is_some(),
            state.worker_active,
        ) {
            return Ok(false);
        }
        state.worker_active = true;
        Ok(true)
    })()
    .unwrap_or(false);
    if !should_start {
        return;
    }

    if std::thread::Builder::new()
        .name("mystic-wrap-pool".to_owned())
        .spawn(move || hardening_pool_refill_worker(target))
        .is_err()
    {
        if let Ok(mut state) = pool.state.lock() {
            state.worker_active = false;
            pool.ready_changed.notify_all();
        }
    }
}

fn hardening_pool_refill_worker(target: HardeningWrappingPoolTarget) {
    let pool = hardening_wrapping_pool();
    loop {
        let candidate = (|| -> HardeningResult<Option<String>> {
            let now_ms = unix_time_ms()?;
            let mut state = pool.state.lock().map_err(|_| HardeningFailure)?;
            prune_expired_hardening_pool_entries(&mut state, now_ms);
            if state.quarantined_bindings.contains(&target.binding_sha256)
                || !hardening_pool_can_prepare(state.ready.len(), state.claimed.len())
            {
                state.worker_active = false;
                pool.ready_changed.notify_all();
                return Ok(None);
            }
            let wrapping_key_id = match state.pending.take() {
                Some(pending) if pending.binding_sha256 == target.binding_sha256 => {
                    pending.wrapping_key_id
                }
                Some(_) | None => Uuid::new_v4().to_string(),
            };
            Ok(Some(wrapping_key_id))
        })();
        let wrapping_key_id = match candidate {
            Ok(Some(wrapping_key_id)) => wrapping_key_id,
            Ok(None) => return,
            Err(_) => {
                if let Ok(mut state) = pool.state.lock() {
                    state.worker_active = false;
                    pool.ready_changed.notify_all();
                }
                return;
            }
        };

        let prepared = prepare_hardening_pool_key(&target, &wrapping_key_id);
        let mut state = match pool.state.lock() {
            Ok(state) => state,
            Err(_) => return,
        };
        if state.quarantined_bindings.contains(&target.binding_sha256) {
            state.worker_active = false;
            pool.ready_changed.notify_all();
            return;
        }
        match prepared {
            Ok(key)
                if key.binding_sha256 == target.binding_sha256
                    && state
                        .ready
                        .iter()
                        .all(|ready| ready.wrapping_key_id != key.wrapping_key_id)
                    && state
                        .claimed
                        .iter()
                        .all(|claimed| claimed.key.wrapping_key_id != key.wrapping_key_id) =>
            {
                state.ready.push(key);
                state.ready.sort_by_key(|key| key.server_expires_at_ms);
                pool.ready_changed.notify_all();
            }
            Ok(_) => {}
            Err(error) => {
                intensive_log!("prepared wrapping-key refill stopped");
                if error == HardeningPoolPreparationError::Transient {
                    state.pending = Some(PendingHardeningWrappingKey {
                        wrapping_key_id,
                        binding_sha256: target.binding_sha256,
                    });
                }
                state.worker_active = false;
                pool.ready_changed.notify_all();
                drop(state);
                if error == HardeningPoolPreparationError::ScopeRejected {
                    quarantine_hardening_pool_scope(target.binding_sha256);
                }
                return;
            }
        }
    }
}

fn update_hardening_pool_claim_expiry(
    wrapping_key_id: &str,
    context_sha256: &[u8; 32],
    expires_at_ms: i64,
) {
    if let Ok(mut state) = hardening_wrapping_pool().state.lock() {
        if let Some(claimed) = state.claimed.iter_mut().find(|claimed| {
            claimed.key.wrapping_key_id == wrapping_key_id
                && claimed.context_sha256 == *context_sha256
        }) {
            claimed.expires_at_ms = expires_at_ms;
        }
    }
}

fn mark_hardening_pool_registration_recovered(wrapping_key_id: &str, context_sha256: &[u8; 32]) {
    if let Ok(mut state) = hardening_wrapping_pool().state.lock() {
        if let Some(claimed) = state.claimed.iter_mut().find(|claimed| {
            claimed.key.wrapping_key_id == wrapping_key_id
                && claimed.context_sha256 == *context_sha256
        }) {
            claimed.recovery_registration_allowed = false;
        }
    }
}

fn complete_hardening_pool_claim(
    wrapping_key_id: &str,
    context_sha256: &[u8; 32],
    target: HardeningWrappingPoolTarget,
) {
    let pool = hardening_wrapping_pool();
    if let Ok(mut state) = pool.state.lock() {
        if let Some(index) = state.claimed.iter().position(|claimed| {
            claimed.key.wrapping_key_id == wrapping_key_id
                && claimed.context_sha256 == *context_sha256
        }) {
            state.claimed.swap_remove(index);
        }
    }
    schedule_hardening_pool_refill(target);
}

fn discard_hardening_pool_claim(wrapping_key_id: &str, context_sha256: &[u8; 32]) {
    let pool = hardening_wrapping_pool();
    if let Ok(mut state) = pool.state.lock() {
        if let Some(index) = state.claimed.iter().position(|claimed| {
            claimed.key.wrapping_key_id == wrapping_key_id
                && claimed.context_sha256 == *context_sha256
        }) {
            state.claimed.swap_remove(index);
        }
    }
}

fn quarantine_hardening_pool_scope(binding_sha256: [u8; 32]) {
    let pool = hardening_wrapping_pool();
    if let Ok(mut state) = pool.state.lock() {
        state.quarantined_bindings.insert(binding_sha256);
        state.ready.retain(|key| key.binding_sha256 != binding_sha256);
        state.claimed.retain(|claimed| claimed.key.binding_sha256 != binding_sha256);
        if state.pending.as_ref().is_some_and(|pending| pending.binding_sha256 == binding_sha256) {
            state.pending = None;
        }
        pool.ready_changed.notify_all();
    }
}

fn retain_failed_hardening_pool_claim(
    wrapping_key_id: &str,
    context_sha256: &[u8; 32],
    target: HardeningWrappingPoolTarget,
    expires_at_ms: i64,
) {
    let pool = hardening_wrapping_pool();
    let should_schedule = if let Ok(mut state) = pool.state.lock() {
        if let Some(claimed) = state.claimed.iter_mut().find(|claimed| {
            claimed.key.wrapping_key_id == wrapping_key_id
                && claimed.context_sha256 == *context_sha256
        }) {
            claimed.expires_at_ms = expires_at_ms;
            if claimed.cleanup_scheduled {
                false
            } else {
                claimed.cleanup_scheduled = true;
                true
            }
        } else {
            false
        }
    } else {
        false
    };
    if !should_schedule {
        return;
    }

    let wrapping_key_id = wrapping_key_id.to_owned();
    let context_sha256 = *context_sha256;
    let _ = std::thread::Builder::new().name("mystic-wrap-expiry".to_owned()).spawn(move || {
        let delay_ms = expires_at_ms.saturating_sub(unix_time_ms().unwrap_or(expires_at_ms));
        if delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(delay_ms as u64));
        }
        let pool = hardening_wrapping_pool();
        if let Ok(mut state) = pool.state.lock() {
            if let Some(index) = state.claimed.iter().position(|claimed| {
                claimed.key.wrapping_key_id == wrapping_key_id
                    && claimed.context_sha256 == context_sha256
                    && claimed.expires_at_ms <= unix_time_ms().unwrap_or(i64::MAX)
            }) {
                state.claimed.swap_remove(index);
            }
        }
        schedule_hardening_pool_refill(target);
    });
}

fn authorize_hardening_stage(
    input: &BinderHardeningStageContext,
) -> HardeningResult<BinderHardeningStageResult> {
    match authorize_hardening_stage_once(input, None)? {
        HardeningStageAttempt::Complete(result) => Ok(result),
        HardeningStageAttempt::RetryFresh(target) => {
            reset_hardening_failure_disposition();
            match authorize_hardening_stage_once(input, Some(target))? {
                HardeningStageAttempt::Complete(result) => Ok(result),
                HardeningStageAttempt::RetryFresh(_) => Err(HardeningFailure),
            }
        }
    }
}

fn authorize_hardening_stage_once(
    input: &BinderHardeningStageContext,
    terminal_fallback_target: Option<HardeningWrappingPoolTarget>,
) -> HardeningResult<HardeningStageAttempt> {
    let _trace = TraceSection::new(b"mystic.hardening.total\0");
    if HARDENING_KEY_RECOVERY.get().copied() != Some(true) {
        intensive_log!("optional runtime stage phase failed: phase=startup_recovery");
        return Err(HardeningFailure);
    }

    let force_fresh = terminal_fallback_target.is_some();
    let (device_identity, mut stage, mut context_sha256, mut identity_signature, mut pooled_key) =
        hardening_phase(
            "context",
            (|| -> HardeningResult<_> {
                let device_identity =
                    load_or_generate_device_identity().map_err(|_| HardeningFailure)?;
                let mut stage = build_hardening_stage_input(input, &device_identity)?;
                if force_fresh {
                    stage.context.idempotency_key =
                        hardening_idempotency(&input.idempotencyKey, "fresh2")?;
                }
                if let Some(scope_sha256) = stage.recovery_scope_sha256.as_ref() {
                    stage.recovery = claim_hardening_recovery(scope_sha256, unix_time_ms()?)?;
                    if let Some(recovery) = stage.recovery {
                        stage.context.recovery_selector = recovery.selector.to_vec();
                    }
                }
                let pooled_key = if force_fresh {
                    None
                } else {
                    claim_hardening_pool_key(&mut stage.context, &device_identity)?
                };
                let identity_spki = hardening_identity_spki(&device_identity.certificate_chain)?;
                let context_sha256 = pooled_key
                    .as_ref()
                    .map(|(_, _, context_sha256)| *context_sha256)
                    .unwrap_or(hardening_context_digest(&stage.context)?);
                let begin_sha256 = hardening_begin_digest(&context_sha256, &identity_spki)?;
                let identity_signature =
                    sign_device_identity(&device_identity.descriptor, &begin_sha256)
                        .map_err(|_| HardeningFailure)?;
                if identity_signature.is_empty() || identity_signature.len() > 256 {
                    return Err(HardeningFailure);
                }
                let pooled_key = pooled_key.map(|(key_use, claim, _)| (key_use, claim));
                Ok((device_identity, stage, context_sha256, identity_signature, pooled_key))
            })(),
        )?;
    let mut recovery_guard =
        HardeningRecoveryGuard::new(stage.recovery_scope_sha256, stage.recovery.is_some());
    intensive_log!(
        "optional runtime stage started: purpose={} route={} stage={}",
        stage.context.purpose,
        stage.context.route_id,
        stage.context.stage_id
    );

    let mut rejected_pool_target = terminal_fallback_target;
    let (challenge, namespace) = hardening_phase(
        "begin",
        (|| -> HardeningResult<_> {
            loop {
                let mut begin = HardeningBeginRequestV1::new();
                begin.context = MessageField::some(stage.context.clone());
                begin.device_identity_chain = device_identity.certificate_chain.clone();
                begin.device_identity_signature = identity_signature.clone();
                match hardening_rpc_detailed(
                    HARDENING_BEGIN_PATH,
                    &begin,
                    HardeningRpcWindow::Begin,
                ) {
                    Ok(challenge) => {
                        let namespace = validate_hardening_challenge(
                            &challenge,
                            &stage.context,
                            &stage.context.wrapping_key_id,
                            stage.recovery,
                            unix_time_ms()?,
                        )?;
                        return Ok((challenge, namespace));
                    }
                    Err(error) if pooled_key.is_some() => {
                        let failure_class = classify_pooled_begin_failure(error);
                        if failure_class == PooledBeginFailureClass::Transient {
                            return Err(HardeningFailure);
                        }

                        if failure_class == PooledBeginFailureClass::KeyRejected {
                            let recovery = pooled_key
                                .as_ref()
                                .filter(|(_, claim)| claim.recovery_registration_allowed)
                                .map(|(key_use, claim)| {
                                    recover_hardening_pool_registration(
                                        key_use,
                                        claim,
                                        stage.context.protocol_minor,
                                    )
                                });
                            match recovery {
                                Some(Ok(())) => {
                                    let (_, claim) = pooled_key.as_mut().ok_or(HardeningFailure)?;
                                    claim.mark_registration_recovered();
                                    reset_hardening_failure_disposition();
                                    continue;
                                }
                                Some(Err(HardeningPoolPreparationError::Transient)) => {
                                    return Err(HardeningFailure);
                                }
                                Some(Err(HardeningPoolPreparationError::ScopeRejected)) => {
                                    let (_, claim) = pooled_key.as_mut().ok_or(HardeningFailure)?;
                                    let target = claim.discard_without_refill();
                                    quarantine_hardening_pool_scope(target.binding_sha256);
                                    return Err(HardeningFailure);
                                }
                                Some(Err(
                                    HardeningPoolPreparationError::RefillClosed
                                    | HardeningPoolPreparationError::CandidateRejected,
                                ))
                                | None => {}
                            }
                        }

                        let (_, claim) = pooled_key.as_mut().ok_or(HardeningFailure)?;
                        let target = claim.discard_without_refill();
                        if failure_class == PooledBeginFailureClass::ScopeRejected {
                            quarantine_hardening_pool_scope(target.binding_sha256);
                            return Err(HardeningFailure);
                        }
                        pooled_key = None;
                        rejected_pool_target = Some(target);
                        reset_hardening_failure_disposition();
                        stage.context.wrapping_key_id.clear();
                        stage.context.idempotency_key =
                            hardening_idempotency(&input.idempotencyKey, "fresh")?;
                        context_sha256 = hardening_context_digest(&stage.context)?;
                        let identity_spki =
                            hardening_identity_spki(&device_identity.certificate_chain)?;
                        let begin_sha256 = hardening_begin_digest(&context_sha256, &identity_spki)?;
                        identity_signature =
                            sign_device_identity(&device_identity.descriptor, &begin_sha256)
                                .map_err(|_| HardeningFailure)?;
                        if identity_signature.is_empty() || identity_signature.len() > 256 {
                            return Err(HardeningFailure);
                        }
                    }
                    Err(error) => {
                        if !error.is_transient() {
                            if let Some(target) = rejected_pool_target.as_ref() {
                                quarantine_hardening_pool_scope(target.binding_sha256);
                            }
                        }
                        return Err(HardeningFailure);
                    }
                }
            }
        })(),
    )?;
    if let Some((_, claim)) = pooled_key.as_mut() {
        if claim.target.scope.crypto_namespace
            != protobuf::EnumOrUnknown::new(namespace.wire_enum())
        {
            return Err(HardeningFailure);
        }
        claim.update_expiry(challenge.server_expires_at_ms);
    }

    let (mut wrapping_key, redeem_wrapping_chain, server_nonce, transcript_sha256) =
        hardening_phase(
            "wrapping_key",
            (|| -> HardeningResult<_> {
                let (wrapping_key, redeem_wrapping_chain) = match pooled_key.take() {
                    Some((key_use, pool_claim)) => (
                        HardeningWrappingKeyMaterial {
                            key_use,
                            fresh_key: None,
                            pool_claim: Some(pool_claim),
                        },
                        Vec::new(),
                    ),
                    None => {
                        let (fresh_key, wrapping_chain) = generate_hardening_wrapping_key(
                            &challenge.wrapping_attestation_challenge,
                            challenge.server_expires_at_ms,
                        )?;
                        let wrapping_certificates = hardening_chain_certificates(&wrapping_chain)?;
                        let wrapping_leaf =
                            X509::from_der(wrapping_certificates.first().ok_or(HardeningFailure)?)
                                .map_err(|_| HardeningFailure)?;
                        let wrapping_spki = wrapping_leaf
                            .public_key()
                            .and_then(|key| key.public_key_to_der())
                            .map_err(|_| HardeningFailure)?;
                        let key_use = HardeningWrappingKeyUse {
                            descriptor: fresh_key.descriptor()?.clone(),
                            wrapping_key_id: String::new(),
                            wrapping_spki_sha256: sha256(&wrapping_spki),
                            wrapping_attestation_sha256: hardening_chain_digest(
                                &wrapping_certificates,
                            ),
                        };
                        (
                            HardeningWrappingKeyMaterial {
                                key_use,
                                fresh_key: Some(fresh_key),
                                pool_claim: None,
                            },
                            wrapping_chain,
                        )
                    }
                };
                let server_nonce = array32(&challenge.server_nonce)?;
                let payload_sha256 = array32(&stage.context.payload_sha256)?;
                let device_identity_spki_sha256 =
                    array32(&stage.context.device_identity_spki_sha256)?;
                let request_sha256 = array32(&stage.context.request_sha256)?;
                let response_sha256 = array32(&stage.context.response_sha256)?;
                let server_expires_at_ms =
                    u64::try_from(challenge.server_expires_at_ms).map_err(|_| HardeningFailure)?;
                let transcript_sha256 = hardening_transcript_digest(&HardeningTranscriptV1 {
                    protocol_minor: stage.context.protocol_minor,
                    context_sha256: &context_sha256,
                    build_id: &stage.context.build_id,
                    payload_sha256: &payload_sha256,
                    session_id: &challenge.session_id,
                    grant_id: &challenge.grant_id,
                    grant_generation: challenge.grant_generation,
                    crypto_namespace: namespace,
                    server_nonce: &server_nonce,
                    purpose: stage.context.purpose,
                    route_id: stage.context.route_id,
                    stage_id: stage.context.stage_id,
                    device_identity_spki_sha256: &device_identity_spki_sha256,
                    wrapping_key_id: &wrapping_key.key_use.wrapping_key_id,
                    latent_binding: &stage.context.latent_binding,
                    wrapping_spki_sha256: &wrapping_key.key_use.wrapping_spki_sha256,
                    wrapping_attestation_sha256: &wrapping_key.key_use.wrapping_attestation_sha256,
                    request_sha256: &request_sha256,
                    response_sha256: &response_sha256,
                    previous_receipt: &stage.context.previous_receipt,
                    voucher: &stage.context.voucher,
                    server_expires_at_ms,
                    policy_epoch: challenge.policy_epoch,
                })
                .map_err(|_| HardeningFailure)?;
                Ok((wrapping_key, redeem_wrapping_chain, server_nonce, transcript_sha256))
            })(),
        )?;

    let mut redeem = HardeningRedeemRequestV1::new();
    redeem.schema_version = HARDENING_SCHEMA_VERSION;
    redeem.protocol_major = HARDENING_PROTOCOL_MAJOR;
    redeem.protocol_minor = stage.context.protocol_minor;
    redeem.session_id = challenge.session_id.clone();
    redeem.grant_id = challenge.grant_id.clone();
    redeem.wrapping_key_chain = redeem_wrapping_chain;
    redeem.transcript_sha256 = transcript_sha256.to_vec();
    redeem.idempotency_key = hardening_phase(
        "redeem_request",
        hardening_idempotency(&stage.context.idempotency_key, "redeem"),
    )?;
    let grant_window = HardeningRpcWindow::Grant { expires_at_ms: challenge.server_expires_at_ms };
    let mut grant: HardeningGrantV1 =
        match hardening_rpc_detailed(HARDENING_REDEEM_PATH, &redeem, grant_window) {
            Ok(grant)
                if validate_hardening_grant(
                    &grant,
                    &challenge,
                    &transcript_sha256,
                    unix_time_ms()?,
                )
                .is_ok() =>
            {
                intensive_log!("optional runtime stage phase completed: phase=redeem");
                grant
            }
            Ok(_) => {
                intensive_log!("optional runtime stage phase failed: phase=redeem");
                let _ = pooled_grant_fresh_retry_target(
                    HardeningRpcError::Status(Code::PermissionDenied),
                    wrapping_key.pool_claim.as_mut(),
                    rejected_pool_target.as_ref(),
                );
                return Err(HardeningFailure);
            }
            Err(error) => {
                intensive_log!("optional runtime stage phase failed: phase=redeem");
                if let Some(target) = pooled_grant_fresh_retry_target(
                    error,
                    wrapping_key.pool_claim.as_mut(),
                    rejected_pool_target.as_ref(),
                ) {
                    recovery_guard.retain_for_fresh_retry();
                    return Ok(HardeningStageAttempt::RetryFresh(target));
                }
                return Err(HardeningFailure);
            }
        };

    let secure_key_wrapper = SensitiveBytes::new(std::mem::take(&mut grant.secure_key_wrapper));
    let capability_key = hardening_phase(
        "capability_import",
        import_hardening_capability(
            &wrapping_key.key_use.descriptor,
            &secure_key_wrapper,
            grant.server_expires_at_ms,
        ),
    )?;
    drop(secure_key_wrapper);
    let derivation = hardening_phase(
        "capability_derivation",
        (|| -> HardeningResult<_> {
            hardening_capability_derivation(
                capability_key.descriptor()?,
                namespace,
                &transcript_sha256,
            )
        })(),
    )?;
    hardening_phase(
        "temporary_key_cleanup",
        (|| -> HardeningResult<()> {
            capability_key.delete_checked()?;
            if let Some(fresh_key) = wrapping_key.fresh_key.take() {
                fresh_key.delete_checked()?;
            }
            Ok(())
        })(),
    )?;

    let binding = HardeningGrantBinding {
        build_id: &stage.context.build_id,
        session_id: &grant.session_id,
        grant_id: &grant.grant_id,
        grant_generation: grant.grant_generation,
        crypto_namespace: namespace,
        server_nonce: &server_nonce,
        transcript_sha256: &transcript_sha256,
        policy_epoch: grant.policy_epoch,
    };
    let (outer_key, runtime_key, apply_key) = hardening_phase(
        "key_derivation",
        derive_hardening_keys(&derivation, &binding).map_err(|_| HardeningFailure),
    )?;
    let mut apply_key = Some(apply_key);
    drop(derivation);
    let sealed_payload = SensitiveBytes::new(std::mem::take(&mut grant.sealed_payload));
    let runtime_payload = hardening_phase(
        "payload_open",
        open_hardening_payload(&outer_key, &binding, &sealed_payload).map_err(|_| HardeningFailure),
    )?;
    drop(sealed_payload);
    drop(outer_key);
    let runtime_payload_sha256 = match stage.kind {
        HardeningStageKind::FunctionalApply(identity) => Some(hardening_phase(
            "descriptor_validation",
            hardening_apply_descriptor_digest(&runtime_payload, identity),
        )?),
        HardeningStageKind::ProtectedBundle => {
            hardening_phase(
                "protected_bundle_validation",
                validate_hardening_protected_bundle(&runtime_payload),
            )?;
            drop(apply_key.take());
            None
        }
    };
    let consume_proof = hardening_phase(
        "consume_proof",
        hardening_consume_proof(&runtime_key, &binding, &stage.next_transition_sha256)
            .map_err(|_| HardeningFailure),
    )?;
    drop(runtime_key);
    let consumption_idempotency_key = hardening_phase(
        "consume_request",
        hardening_idempotency(&stage.context.idempotency_key, "consume"),
    )?;

    let mut consumption = GrantConsumptionV1::new();
    consumption.schema_version = HARDENING_SCHEMA_VERSION;
    consumption.protocol_major = HARDENING_PROTOCOL_MAJOR;
    consumption.protocol_minor = stage.context.protocol_minor;
    consumption.session_id = grant.session_id.clone();
    consumption.grant_id = grant.grant_id.clone();
    consumption.transcript_sha256 = transcript_sha256.to_vec();
    consumption.next_transition_sha256 = stage.next_transition_sha256.to_vec();
    consumption.consume_proof = consume_proof.to_vec();
    drop(consume_proof);
    consumption.idempotency_key = consumption_idempotency_key;
    let consume_rpc_result =
        hardening_rpc_detailed(HARDENING_CONSUME_PATH, &consumption, grant_window);
    secure_wipe(&mut consumption.consume_proof);
    let mut transition: GrantTransitionV1 = match consume_rpc_result {
        Ok(transition)
            if validate_hardening_transition_for_stage(
                &transition,
                &grant,
                stage.kind,
                unix_time_ms()?,
            )
            .is_ok() =>
        {
            intensive_log!("optional runtime stage phase completed: phase=consume");
            transition
        }
        Ok(_) => {
            intensive_log!("optional runtime stage phase failed: phase=consume");
            let _ = pooled_grant_fresh_retry_target(
                HardeningRpcError::Status(Code::PermissionDenied),
                wrapping_key.pool_claim.as_mut(),
                rejected_pool_target.as_ref(),
            );
            return Err(HardeningFailure);
        }
        Err(error) => {
            intensive_log!("optional runtime stage phase failed: phase=consume");
            if error.is_transient() {
                if stage.recovery.is_none() {
                    if let Some(scope_sha256) = stage.recovery_scope_sha256 {
                        remember_hardening_recovery(
                            scope_sha256,
                            array32(&challenge.recovery_selector)?,
                            challenge.recovery_expires_at_ms,
                            unix_time_ms()?,
                        )?;
                    }
                }
                recovery_guard.retain_after_ambiguous_consume();
            }
            if let Some(target) = pooled_grant_fresh_retry_target(
                error,
                wrapping_key.pool_claim.as_mut(),
                rejected_pool_target.as_ref(),
            ) {
                recovery_guard.retain_for_fresh_retry();
                return Ok(HardeningStageAttempt::RetryFresh(target));
            }
            return Err(HardeningFailure);
        }
    };
    let result = match stage.kind {
        HardeningStageKind::FunctionalApply(apply_identity) => {
            let authorization_tag =
                SensitiveBytes::new(std::mem::take(&mut transition.authorized_payload));
            let consumed_receipt = SensitiveBytes::new(std::mem::take(&mut transition.receipt));
            let next_voucher = SensitiveBytes::new(std::mem::take(&mut transition.next_voucher));
            let consumed_receipt_sha256 = sha256(&consumed_receipt);
            let expected_authorization_tag = hardening_phase(
                "authorization_derivation",
                (|| -> HardeningResult<_> {
                    let apply_key = apply_key.take().ok_or(HardeningFailure)?;
                    hardening_apply_authorization(
                        &apply_key,
                        &binding,
                        &stage.next_transition_sha256,
                        &runtime_payload_sha256.ok_or(HardeningFailure)?,
                        &consumed_receipt_sha256,
                        u64::try_from(transition.server_expires_at_ms)
                            .map_err(|_| HardeningFailure)?,
                    )
                    .map_err(|_| HardeningFailure)
                })(),
            )?;
            let verification_proof = hardening_phase(
                "authorization_validation",
                verify_hardening_authorization_and_take_proof(
                    &authorization_tag,
                    expected_authorization_tag.as_slice(),
                    &mut transition.opaque_continuation,
                ),
            );
            drop(expected_authorization_tag);
            let verification_proof = verification_proof?;
            let opaque_result_extension = hardening_phase(
                "result_extension_validation",
                take_hardening_opaque_result_extension(&mut transition.auxiliary_capsule),
            )?;
            drop(consumed_receipt);
            drop(next_voucher);
            hardening_phase(
                "result_validation",
                (|| -> HardeningResult<_> {
                    validate_hardening_result(
                        &runtime_payload,
                        apply_identity,
                        &authorization_tag,
                        &verification_proof,
                        &transcript_sha256,
                        transition.server_expires_at_ms,
                        unix_time_ms()?,
                    )?;
                    Ok(BinderHardeningStageResult {
                        schemaVersion: i32::try_from(HARDENING_SCHEMA_VERSION)
                            .map_err(|_| HardeningFailure)?,
                        protocolMajor: i32::try_from(HARDENING_PROTOCOL_MAJOR)
                            .map_err(|_| HardeningFailure)?,
                        protocolMinor: i32::try_from(stage.context.protocol_minor)
                            .map_err(|_| HardeningFailure)?,
                        runtimePayload: runtime_payload.into_vec(),
                        authorizedPayload: authorization_tag.into_vec(),
                        opaqueContinuation: verification_proof,
                        opaqueResultExtension: opaque_result_extension,
                        protectedBundle: Vec::new(),
                        receipt: Vec::new(),
                        nextVoucher: Vec::new(),
                        contextSha256: Vec::new(),
                        transcriptSha256: transcript_sha256.to_vec(),
                        policyEpoch: i64::try_from(transition.policy_epoch)
                            .map_err(|_| HardeningFailure)?,
                        serverExpiresAtMs: transition.server_expires_at_ms,
                    })
                })(),
            )?
        }
        HardeningStageKind::ProtectedBundle => {
            drop(apply_key.take());
            let consumed_receipt = SensitiveBytes::new(std::mem::take(&mut transition.receipt));
            let next_voucher = SensitiveBytes::new(std::mem::take(&mut transition.next_voucher));
            let protected_proof = hardening_phase(
                "protected_proof_validation",
                take_hardening_protected_proof(&mut transition.opaque_continuation),
            )?;
            hardening_phase(
                "protected_result_validation",
                (|| -> HardeningResult<_> {
                    validate_hardening_protected_result(
                        &runtime_payload,
                        &consumed_receipt,
                        &next_voucher,
                        &transcript_sha256,
                        transition.server_expires_at_ms,
                        unix_time_ms()?,
                    )?;
                    Ok(BinderHardeningStageResult {
                        schemaVersion: i32::try_from(HARDENING_SCHEMA_VERSION)
                            .map_err(|_| HardeningFailure)?,
                        protocolMajor: i32::try_from(HARDENING_PROTOCOL_MAJOR)
                            .map_err(|_| HardeningFailure)?,
                        protocolMinor: i32::try_from(stage.context.protocol_minor)
                            .map_err(|_| HardeningFailure)?,
                        runtimePayload: Vec::new(),
                        authorizedPayload: Vec::new(),
                        opaqueContinuation: protected_proof,
                        opaqueResultExtension: Vec::new(),
                        protectedBundle: runtime_payload.into_vec(),
                        receipt: consumed_receipt.into_vec(),
                        nextVoucher: next_voucher.into_vec(),
                        contextSha256: context_sha256.to_vec(),
                        transcriptSha256: transcript_sha256.to_vec(),
                        policyEpoch: i64::try_from(transition.policy_epoch)
                            .map_err(|_| HardeningFailure)?,
                        serverExpiresAtMs: transition.server_expires_at_ms,
                    })
                })(),
            )?
        }
    };
    if let Some(pool_claim) = wrapping_key.pool_claim.as_mut() {
        pool_claim.complete();
    } else if let Ok(refill_target) =
        hardening_pool_target(&stage.context, &device_identity, namespace)
    {
        schedule_hardening_pool_refill(refill_target);
    }
    recovery_guard.complete();
    Ok(HardeningStageAttempt::Complete(result))
}

fn build_hardening_stage_input(
    input: &BinderHardeningStageContext,
    identity: &DeviceIdentityKey,
) -> HardeningResult<HardeningStageInput> {
    let schema_version = aidl_u32(input.schemaVersion)?;
    let protocol_major = aidl_u32(input.protocolMajor)?;
    let protocol_minor = aidl_u32(input.protocolMinor)?;
    let vm_schema_version = aidl_u32(input.vmSchemaVersion)?;
    let runtime_epoch = aidl_u64(input.runtimeEpoch)?;
    let purpose = aidl_u32(input.purpose)?;
    let route_id = aidl_u32(input.routeId)?;
    let stage_id = aidl_u32(input.stageId)?;
    let kind = hardening_stage_kind(
        vm_schema_version,
        purpose,
        route_id,
        stage_id,
        &input.previousReceipt,
        &input.voucher,
        &input.latentBinding,
    )?;
    if schema_version != HARDENING_SCHEMA_VERSION
        || protocol_major != HARDENING_PROTOCOL_MAJOR
        || input.buildId.is_empty()
        || input.buildId.len() > HARDENING_MAX_ID_BYTES
        || input.idempotencyKey.is_empty()
        || input.idempotencyKey.len() > 112
        || vm_schema_version == 0
        || runtime_epoch == 0
        || input.previousReceipt.len() > HARDENING_MAX_TOKEN_BYTES
        || input.voucher.len() > HARDENING_MAX_TOKEN_BYTES
        || !bounded_identifier(&input.buildId)
        || !bounded_identifier(&input.idempotencyKey)
    {
        return Err(HardeningFailure);
    }
    let payload_sha256 = array32(&input.payloadSha256)?;
    let profile_config_sha256 = array32(&input.profileConfigSha256)?;
    let request_sha256 = array32(&input.requestSha256)?;
    let response_sha256 = array32(&input.responseSha256)?;
    let challenge_sha256 = array32(&input.attestationChallengeSha256)?;
    let attestation_key_sha256 = array32(&input.attestationKeySpkiSha256)?;
    let next_transition_sha256 = array32(&input.nextTransitionSha256)?;
    if [
        payload_sha256,
        profile_config_sha256,
        request_sha256,
        response_sha256,
        challenge_sha256,
        attestation_key_sha256,
        next_transition_sha256,
    ]
    .contains(&[0u8; 32])
    {
        return Err(HardeningFailure);
    }
    let identity_spki = hardening_identity_spki(&identity.certificate_chain)?;
    let processor_sha256 = processor_sha256()?;
    let mut context = HardeningContextV1::new();
    context.schema_version = schema_version;
    context.protocol_major = protocol_major;
    context.protocol_minor = protocol_minor;
    context.build_id = input.buildId.clone();
    context.payload_sha256 = payload_sha256.to_vec();
    context.processor_sha256 = processor_sha256.to_vec();
    context.profile_config_sha256 = profile_config_sha256.to_vec();
    context.vm_schema_version = vm_schema_version;
    context.device_identity_spki_sha256 = sha256(&identity_spki).to_vec();
    context.caller_uid = AID_KEYSTORE;
    context.security_level = "TEE".to_owned();
    context.runtime_epoch = runtime_epoch;
    context.purpose = purpose;
    context.route_id = route_id;
    context.stage_id = stage_id;
    context.request_sha256 = request_sha256.to_vec();
    context.response_sha256 = response_sha256.to_vec();
    context.attestation_challenge_sha256 = challenge_sha256.to_vec();
    context.attestation_key_spki_sha256 = attestation_key_sha256.to_vec();
    context.previous_receipt = input.previousReceipt.clone();
    context.voucher = input.voucher.clone();
    context.idempotency_key = input.idempotencyKey.clone();
    context.latent_binding = input.latentBinding.clone();
    let recovery_scope_sha256 = match kind {
        HardeningStageKind::ProtectedBundle => Some(hardening_recovery_scope_digest(&context)?),
        HardeningStageKind::FunctionalApply(_) => None,
    };
    Ok(HardeningStageInput {
        context,
        next_transition_sha256,
        kind,
        recovery_scope_sha256,
        recovery: None,
    })
}

fn hardening_stage_kind(
    vm_schema_version: u32,
    purpose: u32,
    route_id: u32,
    stage_id: u32,
    previous_receipt: &[u8],
    voucher: &[u8],
    latent_binding: &[u8],
) -> HardeningResult<HardeningStageKind> {
    if vm_schema_version == 0
        || previous_receipt.len() > HARDENING_MAX_TOKEN_BYTES
        || voucher.len() > HARDENING_MAX_TOKEN_BYTES
    {
        return Err(HardeningFailure);
    }
    if is_functional_apply_stage(
        purpose,
        route_id,
        stage_id,
        previous_receipt,
        voucher,
        latent_binding,
    ) {
        return Ok(HardeningStageKind::FunctionalApply(hardening_apply_identity(
            vm_schema_version,
            purpose,
            route_id,
            stage_id,
        )));
    }
    if is_protected_bundle_stage(
        purpose,
        route_id,
        stage_id,
        previous_receipt,
        voucher,
        latent_binding,
    ) {
        return Ok(HardeningStageKind::ProtectedBundle);
    }
    Err(HardeningFailure)
}

fn is_functional_apply_stage(
    purpose: u32,
    route_id: u32,
    stage_id: u32,
    previous_receipt: &[u8],
    voucher: &[u8],
    latent_binding: &[u8],
) -> bool {
    hardening_apply_route_spec(purpose, route_id, stage_id).is_some()
        && previous_receipt.is_empty()
        && voucher.is_empty()
        && latent_binding.is_empty()
}

/// The processor accepts only the fixed protected tuple. It does not inspect
/// the opaque latent binding.
fn is_protected_bundle_stage(
    purpose: u32,
    route_id: u32,
    stage_id: u32,
    previous_receipt: &[u8],
    voucher: &[u8],
    latent_binding: &[u8],
) -> bool {
    purpose == HARDENING_PURPOSE_PROTECTED
        && route_id == HARDENING_PROTECTED_ROUTE
        && (HARDENING_PROTECTED_INITIAL_STAGE..=HARDENING_PROTECTED_FINAL_STAGE).contains(&stage_id)
        && latent_binding.len() == HARDENING_LATENT_BINDING_BYTES
        && latent_binding.iter().any(|value| *value != 0)
        && (if stage_id == HARDENING_PROTECTED_INITIAL_STAGE {
            previous_receipt.is_empty() && voucher.is_empty()
        } else {
            !previous_receipt.is_empty() && !voucher.is_empty()
        })
}

fn hardening_apply_route_spec(
    purpose: u32,
    route_id: u32,
    stage_id: u32,
) -> Option<&'static HardeningApplyRouteSpec> {
    HARDENING_APPLY_ROUTES.iter().find(|spec| {
        spec.purpose == purpose && spec.route_id == route_id && spec.stage_id == stage_id
    })
}

fn hardening_apply_identity(
    vm_schema_version: u32,
    purpose: u32,
    route_id: u32,
    stage_id: u32,
) -> HardeningApplyIdentity {
    HardeningApplyIdentity { vm_schema_version, purpose, route_id, stage_id }
}

fn request_overwrite(
    request_id: &str,
    leaf_certificate: &[u8],
    remaining_chain: &[u8],
    device_identity: &DeviceIdentityKey,
    response_key_chain: &[Vec<u8>],
) -> Result<OverwriteAttestationResponse, OverwriteRequestError> {
    validate_certificate_input(leaf_certificate, remaining_chain)
        .map_err(OverwriteRequestError::Backend)?;
    let mut request = OverwriteAttestationRequest::new();
    request.leaf_certificate = leaf_certificate.to_vec();
    request.remaining_chain = remaining_chain.to_vec();
    request.request_id = request_id.to_owned();
    request.device_attestation_chain = device_identity.certificate_chain.clone();
    request.response_encryption_key_chain = response_key_chain.to_vec();
    request.untrusted_device_serial = device_identity.untrusted_device_serial.clone();
    request.protocol_version = ATTESTATION_PROTOCOL_VERSION;
    let digest = overwrite_device_identity_digest(&request);
    request.device_identity_signature = sign_device_identity(&device_identity.descriptor, &digest)
        .map_err(OverwriteRequestError::Backend)?;

    request_overwrite_once(&request, BACKEND_REQUEST_TIMEOUT)
}

fn wire_attestation_key_profile(
    profile: &BinderAttestationKeyCertificateProfile,
) -> Result<WireAttestationKeyCertificateProfile, OverwriteRequestError> {
    let mut wire = WireAttestationKeyCertificateProfile::new();
    wire.subject_der = profile.subjectDer.clone();
    wire.serial_number = profile.serialNumber.clone();
    wire.not_before_ms = profile.notBeforeMs;
    wire.not_after_ms = profile.notAfterMs;
    wire.attestation_challenge = profile.attestationChallenge.clone();
    wire.attestation_application_id = profile.attestationApplicationId.clone();
    Ok(wire)
}

fn request_provision(
    request_id: &str,
    device_identity: &DeviceIdentityKey,
    response_key_chain: &[Vec<u8>],
    certificate_profile: &BinderAttestationKeyCertificateProfile,
    wrapping_key_leaf_certificate: &[u8],
    wrapping_key_remaining_chain: &[u8],
) -> Result<ProvisionAttestationKeyResponse, OverwriteRequestError> {
    validate_provision_request_input(
        certificate_profile,
        wrapping_key_leaf_certificate,
        wrapping_key_remaining_chain,
    )
    .map_err(OverwriteRequestError::Backend)?;
    let mut request = ProvisionAttestationKeyRequest::new();
    request.request_id = request_id.to_owned();
    request.device_attestation_chain = device_identity.certificate_chain.clone();
    request.response_encryption_key_chain = response_key_chain.to_vec();
    request.untrusted_device_serial = device_identity.untrusted_device_serial.clone();
    request.certificate_profile =
        MessageField::some(wire_attestation_key_profile(certificate_profile)?);
    let wrapping_leaf = split_concatenated_der_certificates(wrapping_key_leaf_certificate)
        .map_err(OverwriteRequestError::Backend)?;
    if wrapping_leaf.len() != 1 {
        return Err(OverwriteRequestError::Backend(
            "wrapping-key leaf field must contain exactly one certificate".to_owned(),
        ));
    }
    request.wrapping_key_chain.push(wrapping_leaf[0].to_vec());
    let wrapping_chain = split_concatenated_der_certificates(wrapping_key_remaining_chain)
        .map_err(OverwriteRequestError::Backend)?;
    request
        .wrapping_key_chain
        .extend(wrapping_chain.into_iter().map(|certificate| certificate.to_vec()));
    let digest = provision_device_identity_digest(&request);
    request.device_identity_signature = sign_device_identity(&device_identity.descriptor, &digest)
        .map_err(OverwriteRequestError::Backend)?;

    request_provision_with_retry(request_id, |timeout| request_provision_once(&request, timeout))
}

fn request_provision_with_retry<T>(
    request_id: &str,
    mut request: impl FnMut(Duration) -> Result<T, ProvisionAttemptError>,
) -> Result<T, OverwriteRequestError> {
    // The backend deduplicates the provisioned key by request ID and verified
    // request fingerprint. Each attempt below sends the same signed request.
    let deadline = Instant::now() + BACKEND_REQUEST_TIMEOUT;
    for attempt in 1..=PROVISION_REQUEST_ATTEMPTS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(OverwriteRequestError::Backend(
                "attestation-key provisioning request deadline exceeded".to_owned(),
            ));
        }
        match request(remaining) {
            Ok(response) => return Ok(response),
            Err(ProvisionAttemptError::InvalidArgument(message)) => {
                return Err(OverwriteRequestError::InvalidArgument(message));
            }
            Err(ProvisionAttemptError::Backend(message)) => {
                return Err(OverwriteRequestError::Backend(message));
            }
            Err(ProvisionAttemptError::Retryable(message)) => {
                if attempt == PROVISION_REQUEST_ATTEMPTS {
                    return Err(OverwriteRequestError::Backend(message));
                }
                let retry_delay = PROVISION_RETRY_DELAY * attempt as u32;
                if deadline.saturating_duration_since(Instant::now()) <= retry_delay {
                    return Err(OverwriteRequestError::Backend(message));
                }
                intensive_log!(
                    "attestation-key provisioning retry: request_id={request_id} attempt={attempt}/{PROVISION_REQUEST_ATTEMPTS} error={message}"
                );
                std::thread::sleep(retry_delay);
            }
        }
    }
    unreachable!()
}

fn hardening_rpc_detailed<Request, Response>(
    path: &'static str,
    request: &Request,
    window: HardeningRpcWindow,
) -> Result<Response, HardeningRpcError>
where
    Request: Message + Default + Clone + Send + Sync + 'static,
    Response: Message + Default + Send + Sync + 'static,
{
    let method = match path {
        HARDENING_BEGIN_PATH => "BeginSession",
        HARDENING_REDEEM_PATH => "RedeemGrant",
        HARDENING_CONSUME_PATH => "ConsumeGrant",
        HARDENING_PREPARE_WRAPPING_KEY_PATH => "PrepareWrappingKey",
        HARDENING_REGISTER_WRAPPING_KEY_PATH => "RegisterWrappingKey",
        HARDENING_COMPLETE_PROTECTED_STAGE_PATH => "CompleteProtectedStage",
        _ => return Err(record_hardening_rpc_error(HardeningRpcError::Transient)),
    };
    // Both attempts use the same request. Keep retry state in this call.
    for attempt in 0..2 {
        let now_ms =
            unix_time_ms().map_err(|_| record_hardening_rpc_error(HardeningRpcError::Transient))?;
        let timeout = hardening_rpc_attempt_timeout(window, now_ms, attempt)
            .map_err(|_| record_hardening_rpc_error(HardeningRpcError::Transient))?;
        let result = runtime().block_on(async {
            tokio::time::timeout(timeout, async {
                let mut grpc =
                    Grpc::new(backend_channel().map_err(|_| HardeningRpcError::Transient)?)
                        .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES)
                        .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES);
                grpc.ready().await.map_err(|_| HardeningRpcError::Transient)?;
                let mut request = TonicRequest::new(request.clone());
                request.extensions_mut().insert(GrpcMethod::new(HARDENING_GRPC_SERVICE, method));
                grpc.unary(
                    request,
                    PathAndQuery::from_static(path),
                    RustProtobufCodec::<Request, Response>(PhantomData),
                )
                .await
                .map(|response| response.into_inner())
                .map_err(|status| HardeningRpcError::Status(status.code()))
            })
            .await
            .map_err(|_| HardeningRpcError::Transient)?
        });
        match result {
            Ok(response) => return Ok(response),
            Err(error) if attempt == 0 && error.is_transient() => {
                let now_ms = unix_time_ms()
                    .map_err(|_| record_hardening_rpc_error(HardeningRpcError::Transient))?;
                let retry_delay = hardening_rpc_retry_delay(window, now_ms)
                    .map_err(|_| record_hardening_rpc_error(HardeningRpcError::Transient))?;
                std::thread::sleep(retry_delay);
            }
            Err(error) => return Err(record_hardening_rpc_error(error)),
        }
    }
    Err(record_hardening_rpc_error(HardeningRpcError::Transient))
}

fn hardening_rpc_attempt_timeout(
    window: HardeningRpcWindow,
    now_ms: i64,
    attempt: usize,
) -> HardeningResult<Duration> {
    let timeout_ms = match window {
        HardeningRpcWindow::Begin | HardeningRpcWindow::Completion => {
            HARDENING_BEGIN_RPC_TIMEOUT_MS
        }
        HardeningRpcWindow::Grant { expires_at_ms } => {
            let usable_ms = hardening_grant_usable_ms(expires_at_ms, now_ms)?;
            let reserved_ms = if attempt == 0 {
                HARDENING_RPC_RETRY_DELAY_MS + HARDENING_RPC_MIN_ATTEMPT_TIMEOUT_MS
            } else {
                0
            };
            let attempt_ms = usable_ms
                .checked_sub(reserved_ms)
                .filter(|remaining_ms| *remaining_ms >= HARDENING_RPC_MIN_ATTEMPT_TIMEOUT_MS)
                .unwrap_or(usable_ms);
            attempt_ms.min(HARDENING_RPC_MAX_ATTEMPT_TIMEOUT_MS)
        }
    };
    if timeout_ms < HARDENING_RPC_MIN_ATTEMPT_TIMEOUT_MS {
        return Err(HardeningFailure);
    }
    Ok(Duration::from_millis(u64::try_from(timeout_ms).map_err(|_| HardeningFailure)?))
}

fn hardening_rpc_retry_delay(window: HardeningRpcWindow, now_ms: i64) -> HardeningResult<Duration> {
    let delay_ms = match window {
        HardeningRpcWindow::Begin | HardeningRpcWindow::Completion => HARDENING_RPC_RETRY_DELAY_MS,
        HardeningRpcWindow::Grant { expires_at_ms } => {
            let usable_ms = hardening_grant_usable_ms(expires_at_ms, now_ms)?;
            usable_ms
                .checked_sub(HARDENING_RPC_MIN_ATTEMPT_TIMEOUT_MS)
                .ok_or(HardeningFailure)?
                .min(HARDENING_RPC_RETRY_DELAY_MS)
        }
    };
    if delay_ms <= 0 {
        return Err(HardeningFailure);
    }
    Ok(Duration::from_millis(u64::try_from(delay_ms).map_err(|_| HardeningFailure)?))
}

fn hardening_grant_usable_ms(expires_at_ms: i64, now_ms: i64) -> HardeningResult<i64> {
    expires_at_ms
        .checked_sub(now_ms)
        .and_then(|remaining_ms| remaining_ms.checked_sub(HARDENING_RPC_EXPIRY_MARGIN_MS))
        .filter(|usable_ms| *usable_ms >= HARDENING_RPC_MIN_ATTEMPT_TIMEOUT_MS)
        .ok_or(HardeningFailure)
}

fn runtime() -> &'static tokio::runtime::Runtime {
    TOKIO_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("failed to create Droidfood gRPC Tokio runtime")
    })
}

fn backend_channel() -> Result<Channel, String> {
    if let Some(channel) = BACKEND_CHANNEL.get() {
        return Ok(channel.clone());
    }

    let target = backend_grpc_target();
    let host = target.split(':').next().unwrap_or(target);
    let endpoint = Endpoint::from_shared(format!("https://{target}"))
        .map_err(|err| format!("invalid gRPC backend URI: {err}"))?
        .connect_timeout(BACKEND_REQUEST_TIMEOUT)
        .timeout(BACKEND_REQUEST_TIMEOUT)
        .http2_adaptive_window(true)
        .user_agent("DroidfoodAttestationFixer/0.1")
        .map_err(|err| format!("invalid gRPC user agent: {err}"))?
        .tls_config(
            ClientTlsConfig::new()
                .domain_name(host.to_owned())
                .with_native_roots()
                .timeout(BACKEND_REQUEST_TIMEOUT),
        )
        .map_err(|err| format!("failed to configure gRPC TLS: {err}"))?;

    let channel = endpoint.connect_lazy();
    let _ = BACKEND_CHANNEL.set(channel.clone());
    Ok(BACKEND_CHANNEL.get().cloned().unwrap_or(channel))
}

#[derive(Clone, Copy)]
struct RustProtobufCodec<Encode, Decode>(PhantomData<(Encode, Decode)>);

#[derive(Clone, Copy)]
struct RustProtobufEncoder<MessageType>(PhantomData<MessageType>);

#[derive(Clone, Copy)]
struct RustProtobufDecoder<MessageType>(PhantomData<MessageType>);

impl<Encode, Decode> Codec for RustProtobufCodec<Encode, Decode>
where
    Encode: Message + Send + Sync + 'static,
    Decode: Message + Default + Send + Sync + 'static,
{
    type Encode = Encode;
    type Decode = Decode;
    type Encoder = RustProtobufEncoder<Encode>;
    type Decoder = RustProtobufDecoder<Decode>;

    fn encoder(&mut self) -> Self::Encoder {
        RustProtobufEncoder(PhantomData)
    }

    fn decoder(&mut self) -> Self::Decoder {
        RustProtobufDecoder(PhantomData)
    }
}

impl<MessageType> Encoder for RustProtobufEncoder<MessageType>
where
    MessageType: Message,
{
    type Item = MessageType;
    type Error = TonicStatus;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        let encoded = item
            .write_to_bytes()
            .map_err(|err| TonicStatus::internal(format!("protobuf encode failed: {err}")))?;
        dst.put_slice(&encoded);
        Ok(())
    }
}

impl<MessageType> Decoder for RustProtobufDecoder<MessageType>
where
    MessageType: Message + Default,
{
    type Item = MessageType;
    type Error = TonicStatus;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        let encoded = src.copy_to_bytes(src.remaining());
        MessageType::parse_from_bytes(&encoded)
            .map(Some)
            .map_err(|err| TonicStatus::internal(format!("protobuf decode failed: {err}")))
    }
}

async fn unary_rpc<RequestMessage, ResponseMessage>(
    request: &RequestMessage,
    path: &'static str,
    method: &'static str,
    timeout: Duration,
) -> Result<ResponseMessage, TonicStatus>
where
    RequestMessage: Message + Clone + Send + Sync + 'static,
    ResponseMessage: Message + Default + Send + Sync + 'static,
{
    let channel = backend_channel().map_err(TonicStatus::unavailable)?;
    let mut client = Grpc::new(channel)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES)
        .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES);
    client
        .ready()
        .await
        .map_err(|err| TonicStatus::unavailable(format!("gRPC channel not ready: {err}")))?;

    let mut request = TonicRequest::new(request.clone());
    request.extensions_mut().insert(GrpcMethod::new(GRPC_SERVICE, method));
    let path = PathAndQuery::from_static(path);
    let rpc = client.unary(
        request,
        path,
        RustProtobufCodec::<RequestMessage, ResponseMessage>(PhantomData),
    );
    match tokio::time::timeout(timeout, rpc).await {
        Ok(result) => result.map(|response| response.into_inner()),
        Err(_) => Err(TonicStatus::deadline_exceeded("gRPC request deadline exceeded")),
    }
}

fn request_overwrite_once(
    request: &OverwriteAttestationRequest,
    timeout: Duration,
) -> Result<OverwriteAttestationResponse, OverwriteRequestError> {
    let _trace = TraceSection::new(b"mystic.grpc.rpc\0");
    runtime()
        .block_on(unary_rpc::<OverwriteAttestationRequest, OverwriteAttestationResponse>(
            request,
            OVERWRITE_ATTESTATION_PATH,
            "OverwriteAttestation",
            timeout,
        ))
        .map_err(|err| tonic_request_error("attestation overwrite", err))
}

fn request_provision_once(
    request: &ProvisionAttestationKeyRequest,
    timeout: Duration,
) -> Result<ProvisionAttestationKeyResponse, ProvisionAttemptError> {
    let _trace = TraceSection::new(b"mystic.grpc.rpc\0");
    runtime()
        .block_on(unary_rpc::<ProvisionAttestationKeyRequest, ProvisionAttestationKeyResponse>(
            request,
            PROVISION_ATTESTATION_KEY_PATH,
            "ProvisionAttestationKey",
            timeout,
        ))
        .map_err(provision_tonic_request_error)
}

fn tonic_request_error(operation: &str, status: TonicStatus) -> OverwriteRequestError {
    let code = status.code();
    match code {
        Code::InvalidArgument => OverwriteRequestError::InvalidArgument(format!(
            "{operation} request was rejected by the backend"
        )),
        _ => OverwriteRequestError::Backend(format!("{operation} gRPC failed with {code}")),
    }
}

fn provision_tonic_request_error(status: TonicStatus) -> ProvisionAttemptError {
    let code = status.code();
    match code {
        Code::InvalidArgument => ProvisionAttemptError::InvalidArgument(
            "attestation-key provisioning request was rejected by the backend".to_owned(),
        ),
        Code::Unavailable | Code::ResourceExhausted | Code::DeadlineExceeded => {
            ProvisionAttemptError::Retryable(format!(
                "attestation-key provisioning gRPC failed with {code}"
            ))
        }
        _ => ProvisionAttemptError::Backend(format!(
            "attestation-key provisioning gRPC failed with {code}"
        )),
    }
}

fn is_internal_identity_certificate(leaf_certificate: &[u8]) -> bool {
    let prefix = RESPONSE_KEY_CHALLENGE_PREFIX.as_bytes();
    let identity_challenge = device_identity_challenge();
    leaf_certificate.windows(prefix.len()).any(|window| window == prefix)
        || leaf_certificate
            .windows(identity_challenge.len())
            .any(|window| window == identity_challenge)
}

fn generate_response_key(request_id: &str) -> Result<ResponseKey, Status> {
    let _trace = TraceSection::new(b"mystic.keymint.response_key\0");
    let keystore = keystore_service()?;
    let security_level =
        keystore.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).map_err(|err| {
            service_error(ERROR_SERVER_REQUEST, &format!("keystore security level failed: {err:?}"))
        })?;
    let descriptor = KeyDescriptor {
        domain: Domain::APP,
        nspace: -1,
        alias: Some(format!("{RESPONSE_KEY_ALIAS_PREFIX}{request_id}")),
        blob: None,
    };
    let params = response_key_params(request_id, ResponseIdentity::None);
    let metadata = security_level
        .generateKey(&descriptor, None, &params, 0, b"MysticAttestation")
        .map_err(|err| {
            service_error(ERROR_SERVER_REQUEST, &format!("response key generation failed: {err:?}"))
        })?;
    // Construct the guard before certificate parsing. This deletes the key if
    // KeyMint returns malformed metadata.
    let mut response_key = ResponseKey { descriptor: metadata.key, certificate_chain: Vec::new() };
    response_key.certificate_chain = certificate_chain_from_metadata(
        metadata.certificate,
        metadata.certificateChain,
        "response key",
    )?;
    Ok(response_key)
}

fn load_or_generate_device_identity() -> Result<DeviceIdentityKey, Status> {
    let _trace = TraceSection::new(b"mystic.keymint.identity\0");
    if let Some(identity) = load_device_identity(DEVICE_IDENTITY_TRUSTED_ALIAS, false)? {
        return Ok(identity);
    }
    if let Some(identity) = load_device_identity(DEVICE_IDENTITY_FALLBACK_ALIAS, true)? {
        return Ok(identity);
    }

    let keystore = keystore_service()?;
    let security_level =
        keystore.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).map_err(|err| {
            service_error(ERROR_SERVER_REQUEST, &format!("keystore security level failed: {err:?}"))
        })?;
    let trusted_descriptor = app_key_descriptor(DEVICE_IDENTITY_TRUSTED_ALIAS);
    let full_params = device_identity_params(ResponseIdentity::Full);
    let metadata = match security_level.generateKey(
        &trusted_descriptor,
        None,
        &full_params,
        0,
        b"MysticAttestation",
    ) {
        Ok(metadata) => metadata,
        Err(full_err) => {
            delete_key(&trusted_descriptor);
            intensive_log!(
                "full persistent device identity rejected; retrying with serial: {full_err:?}"
            );
            let serial_params = device_identity_params(ResponseIdentity::Serial);
            match security_level.generateKey(
                &trusted_descriptor,
                None,
                &serial_params,
                0,
                b"MysticAttestation",
            ) {
                Ok(metadata) => metadata,
                Err(serial_err) => {
                    delete_key(&trusted_descriptor);
                    return generate_fallback_device_identity(
                        &security_level,
                        full_err,
                        serial_err,
                    );
                }
            }
        }
    };
    let certificate_chain = certificate_chain_from_metadata(
        metadata.certificate,
        metadata.certificateChain,
        "device identity",
    )?;
    Ok(DeviceIdentityKey {
        descriptor: metadata.key,
        certificate_chain,
        untrusted_device_serial: String::new(),
    })
}

fn load_device_identity(alias: &str, fallback: bool) -> Result<Option<DeviceIdentityKey>, Status> {
    let descriptor = app_key_descriptor(alias);
    let keystore = keystore_service()?;
    let entry = match keystore.getKeyEntry(&descriptor) {
        Ok(entry) => entry,
        Err(_) => return Ok(None),
    };
    let certificate_chain = certificate_chain_from_metadata(
        entry.metadata.certificate,
        entry.metadata.certificateChain,
        "stored device identity",
    )?;
    let untrusted_device_serial = if fallback { fallback_device_serial()? } else { String::new() };
    Ok(Some(DeviceIdentityKey {
        descriptor: entry.metadata.key,
        certificate_chain,
        untrusted_device_serial,
    }))
}

fn generate_fallback_device_identity(
    security_level: &binder::Strong<dyn IKeystoreSecurityLevel>,
    full_err: binder::Status,
    serial_err: binder::Status,
) -> Result<DeviceIdentityKey, Status> {
    let serial = fallback_device_serial()?;
    error!(
        "hardware serial attestation failed; using a persistent hardware key plus UNTRUSTED \
         ro.serialno: full={full_err:?}, serial={serial_err:?}"
    );
    let descriptor = app_key_descriptor(DEVICE_IDENTITY_FALLBACK_ALIAS);
    let metadata = security_level
        .generateKey(
            &descriptor,
            None,
            &device_identity_params(ResponseIdentity::None),
            0,
            b"MysticAttestation",
        )
        .map_err(|err| {
            service_error(
                ERROR_SERVER_REQUEST,
                &format!("fallback device identity generation failed: {err:?}"),
            )
        })?;
    let certificate_chain = certificate_chain_from_metadata(
        metadata.certificate,
        metadata.certificateChain,
        "fallback device identity",
    )?;
    Ok(DeviceIdentityKey {
        descriptor: metadata.key,
        certificate_chain,
        untrusted_device_serial: serial,
    })
}

fn fallback_device_serial() -> Result<String, Status> {
    let serial = String::from_utf8_lossy(&get_system_prop("ro.serialno")).trim().to_owned();
    if serial.is_empty() {
        return Err(service_error(
            ERROR_SERVER_REQUEST,
            "hardware serial attestation failed and ro.serialno is empty",
        ));
    }
    Ok(serial)
}

fn app_key_descriptor(alias: &str) -> KeyDescriptor {
    KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias.to_owned()), blob: None }
}

fn certificate_chain_from_metadata(
    certificate: Option<Vec<u8>>,
    remaining_chain: Option<Vec<u8>>,
    description: &str,
) -> Result<Vec<Vec<u8>>, Status> {
    let mut certificate_chain = Vec::new();
    certificate_chain.push(certificate.ok_or_else(|| {
        service_error(ERROR_SERVER_REQUEST, &format!("{description} returned no certificate"))
    })?);
    if let Some(chain) = remaining_chain {
        if !chain.is_empty() {
            certificate_chain.push(chain);
        }
    }
    Ok(certificate_chain)
}

#[derive(Clone, Copy)]
enum ResponseIdentity {
    Full,
    Serial,
    None,
}

fn response_key_params(request_id: &str, identity: ResponseIdentity) -> Vec<KeyParameter> {
    let mut params = vec![
        key_param(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        key_param(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        key_param(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::AGREE_KEY)),
        key_param(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        key_param(Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
        key_param(
            Tag::ATTESTATION_CHALLENGE,
            KeyParameterValue::Blob(response_key_challenge(request_id)),
        ),
        key_param(
            Tag::CERTIFICATE_NOT_AFTER,
            KeyParameterValue::DateTime(RESPONSE_CERT_NOT_AFTER_MS),
        ),
        key_param(Tag::CERTIFICATE_SERIAL, KeyParameterValue::Blob(vec![1])),
    ];
    params.extend(device_attestation_params(identity));
    params
}

fn device_identity_params(identity: ResponseIdentity) -> Vec<KeyParameter> {
    let mut params = vec![
        key_param(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        key_param(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        key_param(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::SIGN)),
        key_param(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        key_param(Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
        key_param(Tag::ATTESTATION_CHALLENGE, KeyParameterValue::Blob(device_identity_challenge())),
        key_param(
            Tag::CERTIFICATE_NOT_AFTER,
            KeyParameterValue::DateTime(RESPONSE_CERT_NOT_AFTER_MS),
        ),
        key_param(Tag::CERTIFICATE_SERIAL, KeyParameterValue::Blob(vec![2])),
    ];
    params.extend(device_attestation_params(identity));
    params
}

fn decrypt_response(
    request_id: &str,
    key: &KeyDescriptor,
    response: &OverwriteAttestationResponse,
) -> Result<OverwriteAttestationResponsePlaintext, String> {
    let plaintext = decrypt_response_envelope(
        request_id,
        key,
        &response.encrypted_response,
        &response.response_nonce,
        &response.response_ephemeral_public_key,
        RESPONSE_HKDF_INFO,
        RESPONSE_AAD_PREFIX,
    )?;
    OverwriteAttestationResponsePlaintext::parse_from_bytes(&plaintext)
        .map_err(|err| format!("response payload decode failed: {err:?}"))
}

fn decrypt_provision_response(
    request_id: &str,
    key: &KeyDescriptor,
    response: &ProvisionAttestationKeyResponse,
) -> Result<ProvisionAttestationKeyResponsePlaintext, String> {
    let plaintext = decrypt_response_envelope(
        request_id,
        key,
        &response.encrypted_response,
        &response.response_nonce,
        &response.response_ephemeral_public_key,
        PROVISION_RESPONSE_HKDF_INFO,
        PROVISION_RESPONSE_AAD_PREFIX,
    )?;
    ProvisionAttestationKeyResponsePlaintext::parse_from_bytes(&plaintext)
        .map_err(|err| format!("provisioning response payload decode failed: {err:?}"))
}

fn decrypt_response_envelope(
    request_id: &str,
    key: &KeyDescriptor,
    encrypted_response: &[u8],
    response_nonce: &[u8],
    response_ephemeral_public_key: &[u8],
    hkdf_info: &[u8],
    aad_prefix: &str,
) -> Result<SensitiveBytes, String> {
    let _trace = TraceSection::new(b"mystic.response.decrypt\0");
    if encrypted_response.is_empty() || response_ephemeral_public_key.is_empty() {
        return Err("server returned an incomplete encrypted response".to_owned());
    }
    if encrypted_response.len() > MAX_ENCRYPTED_RESPONSE_BYTES {
        return Err("server encrypted response is too large".to_owned());
    }
    if response_nonce.len() != AES_GCM_NONCE_BYTES {
        return Err("server encrypted response nonce has the wrong size".to_owned());
    }
    if response_ephemeral_public_key.len() > MAX_RESPONSE_EPHEMERAL_KEY_BYTES {
        return Err("server response public key is too large".to_owned());
    }
    let secret = derive_keymint_secret(key, response_ephemeral_public_key)?;
    let aes_key = derive_response_aes_key(request_id, &secret, hkdf_info)?;
    aes_gcm_decrypt(
        &aes_key[..],
        response_nonce,
        encrypted_response,
        response_aad(aad_prefix, request_id).as_bytes(),
    )
}

fn validate_provisioned_attestation_key(
    provisioned: &ProvisionAttestationKeyResponsePlaintext,
) -> Result<(), String> {
    if provisioned.secure_key_wrapper.is_empty()
        || provisioned.leaf_certificate.is_empty()
        || provisioned.remaining_chain.is_empty()
    {
        return Err("server returned incomplete attestation-key material".to_owned());
    }
    if provisioned.secure_key_wrapper.len() > MAX_SECURE_KEY_WRAPPER_BYTES {
        return Err("server returned an oversized secure key wrapper".to_owned());
    }
    validate_certificate_input(&provisioned.leaf_certificate, &provisioned.remaining_chain)?;

    let leaf_der = split_concatenated_der_certificates(&provisioned.leaf_certificate)?;
    if leaf_der.len() != 1 {
        return Err("provisioned leaf field contains more than one certificate".to_owned());
    }
    let certificate = X509::from_der(leaf_der[0])
        .map_err(|err| format!("provisioned leaf certificate is invalid: {err:?}"))?;
    let chain_der = split_concatenated_der_certificates(&provisioned.remaining_chain)?;
    let mut fingerprints = HashSet::with_capacity(chain_der.len() + 1);
    fingerprints.insert(sha256(leaf_der[0]));

    let mut chain = Vec::with_capacity(chain_der.len());
    for (index, der) in chain_der.iter().enumerate() {
        if !fingerprints.insert(sha256(der)) {
            return Err(format!(
                "provisioned certificate chain contains duplicate certificate {index}"
            ));
        }
        chain.push(
            X509::from_der(der)
                .map_err(|err| format!("provisioned certificate {index} is invalid: {err:?}"))?,
        );
    }

    verify_certificate_signature(&certificate, &chain[0], "leaf")?;
    for (index, pair) in chain.windows(2).enumerate() {
        verify_certificate_signature(&pair[0], &pair[1], &format!("chain certificate {index}"))?;
    }
    Ok(())
}

fn validate_certificate_input(
    leaf_certificate: &[u8],
    remaining_chain: &[u8],
) -> Result<(), String> {
    if leaf_certificate.is_empty() || remaining_chain.is_empty() {
        return Err("certificate input is incomplete".to_owned());
    }
    let total = leaf_certificate
        .len()
        .checked_add(remaining_chain.len())
        .ok_or_else(|| "certificate input size overflowed".to_owned())?;
    if total > MAX_CERTIFICATE_INPUT_BYTES {
        return Err("certificate input is too large".to_owned());
    }
    Ok(())
}

fn validate_provision_request_input(
    profile: &BinderAttestationKeyCertificateProfile,
    wrapping_key_leaf_certificate: &[u8],
    wrapping_key_remaining_chain: &[u8],
) -> Result<(), String> {
    validate_certificate_input(wrapping_key_leaf_certificate, wrapping_key_remaining_chain)?;
    let profile_bytes = profile
        .subjectDer
        .len()
        .checked_add(profile.serialNumber.len())
        .and_then(|total| total.checked_add(profile.attestationChallenge.len()))
        .and_then(|total| total.checked_add(profile.attestationApplicationId.len()))
        .ok_or_else(|| "attestation-key certificate profile size overflowed".to_owned())?;
    if profile_bytes > MAX_CERTIFICATE_INPUT_BYTES {
        return Err("attestation-key certificate profile is too large".to_owned());
    }
    if !certificate_validity_range_is_valid(profile.notBeforeMs, profile.notAfterMs) {
        return Err("attestation-key certificate validity range is invalid".to_owned());
    }
    Ok(())
}

fn certificate_validity_range_is_valid(not_before_ms: i64, not_after_ms: i64) -> bool {
    not_after_ms == 0 || not_after_ms > not_before_ms
}

fn validate_overwritten_chain(
    original_leaf_der: &[u8],
    overwritten_leaf_der: &[u8],
    overwritten_remaining_chain: &[u8],
) -> Result<(), String> {
    validate_certificate_input(overwritten_leaf_der, overwritten_remaining_chain)?;
    let original_leaf = X509::from_der(original_leaf_der)
        .map_err(|err| format!("original attestation leaf certificate is invalid: {err:?}"))?;
    let overwritten_leaf = X509::from_der(overwritten_leaf_der)
        .map_err(|err| format!("server attestation leaf certificate is invalid: {err:?}"))?;
    let original_spki = original_leaf
        .public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|err| format!("original attestation public key is invalid: {err:?}"))?;
    let overwritten_spki = overwritten_leaf
        .public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|err| format!("server attestation public key is invalid: {err:?}"))?;
    if original_spki != overwritten_spki {
        return Err("server attestation leaf changed the generated key".to_owned());
    }

    let chain_der = split_concatenated_der_certificates(overwritten_remaining_chain)?;
    let mut fingerprints = HashSet::with_capacity(chain_der.len() + 1);
    fingerprints.insert(sha256(overwritten_leaf_der));
    let mut chain = Vec::with_capacity(chain_der.len());
    for (index, der) in chain_der.iter().enumerate() {
        if !fingerprints.insert(sha256(der)) {
            return Err(format!("server certificate chain contains duplicate certificate {index}"));
        }
        chain.push(
            X509::from_der(der)
                .map_err(|err| format!("server certificate {index} is invalid: {err:?}"))?,
        );
    }
    verify_certificate_signature(&overwritten_leaf, &chain[0], "server leaf")?;
    for (index, pair) in chain.windows(2).enumerate() {
        verify_certificate_signature(
            &pair[0],
            &pair[1],
            &format!("server chain certificate {index}"),
        )?;
    }
    Ok(())
}

fn split_concatenated_der_certificates(mut encoded: &[u8]) -> Result<Vec<&[u8]>, String> {
    const MAX_CHAIN_CERTIFICATES: usize = 16;

    let mut certificates = Vec::new();
    while !encoded.is_empty() {
        if certificates.len() == MAX_CHAIN_CERTIFICATES {
            return Err("provisioned certificate chain is too long".to_owned());
        }
        if encoded.len() < 2 || encoded[0] != 0x30 {
            return Err("provisioned certificate chain is not concatenated DER".to_owned());
        }

        let first_length = encoded[1];
        let (header_length, content_length) = if first_length & 0x80 == 0 {
            (2usize, usize::from(first_length))
        } else {
            let length_bytes = usize::from(first_length & 0x7f);
            if length_bytes == 0 || length_bytes > std::mem::size_of::<usize>() {
                return Err("provisioned certificate has an invalid DER length".to_owned());
            }
            if encoded.len() < 2 + length_bytes || encoded[2] == 0 {
                return Err("provisioned certificate has a truncated or non-canonical DER length"
                    .to_owned());
            }
            let mut length = 0usize;
            for byte in &encoded[2..2 + length_bytes] {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or_else(|| "provisioned certificate DER length overflowed".to_owned())?;
            }
            if length < 128 {
                return Err("provisioned certificate has a non-canonical DER length".to_owned());
            }
            (2 + length_bytes, length)
        };

        let certificate_length = header_length
            .checked_add(content_length)
            .ok_or_else(|| "provisioned certificate DER length overflowed".to_owned())?;
        if certificate_length > encoded.len() {
            return Err("provisioned certificate is truncated".to_owned());
        }
        certificates.push(&encoded[..certificate_length]);
        encoded = &encoded[certificate_length..];
    }

    if certificates.is_empty() {
        return Err("provisioned certificate chain is empty".to_owned());
    }
    Ok(certificates)
}

fn leaf_is_signed_by_first_issuer(leaf_der: &[u8], remaining_chain: &[u8]) -> Result<bool, String> {
    let leaf = X509::from_der(leaf_der)
        .map_err(|err| format!("attestation leaf certificate is invalid: {err:?}"))?;
    let Ok(certificates) = split_concatenated_der_certificates(remaining_chain) else {
        return Ok(false);
    };
    let Some(issuer_der) = certificates.first() else {
        return Ok(false);
    };
    let Ok(issuer) = X509::from_der(issuer_der) else {
        return Ok(false);
    };
    let Ok(issuer_key) = issuer.public_key() else {
        return Ok(false);
    };
    Ok(leaf.verify(&issuer_key).unwrap_or(false))
}

fn verify_certificate_signature(
    child: &X509Ref,
    issuer: &X509Ref,
    description: &str,
) -> Result<(), String> {
    let issuer_name = child
        .issuer_name()
        .to_der()
        .map_err(|err| format!("{description} issuer name is invalid: {err:?}"))?;
    let subject_name = issuer
        .subject_name()
        .to_der()
        .map_err(|err| format!("{description} parent subject is invalid: {err:?}"))?;
    if issuer_name != subject_name {
        return Err(format!("{description} issuer does not match its parent subject"));
    }

    let issuer_key = issuer
        .public_key()
        .map_err(|err| format!("{description} parent public key is invalid: {err:?}"))?;
    if !child
        .verify(&issuer_key)
        .map_err(|err| format!("{description} signature validation failed: {err:?}"))?
    {
        return Err(format!("{description} is not signed by its parent certificate"));
    }
    Ok(())
}

fn derive_keymint_secret(
    key: &KeyDescriptor,
    peer_public_key: &[u8],
) -> Result<SensitiveBytes, String> {
    let _trace = TraceSection::new(b"mystic.keymint.agree\0");
    let keystore =
        raw_keystore_service().map_err(|err| format!("keystore connect failed: {err:?}"))?;
    let security_level = keystore
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .map_err(|err| format!("keystore security level failed: {err:?}"))?;
    let params =
        vec![key_param(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::AGREE_KEY))];
    let operation = security_level
        .createOperation(key, &params, false)
        .map_err(|err| format!("response key operation failed: {err:?}"))?;
    let operation =
        operation.iOperation.ok_or_else(|| "response key operation missing".to_owned())?;
    let secret = operation
        .finish(Some(peer_public_key), None)
        .map_err(|err| format!("response key agreement failed: {err:?}"))?
        .ok_or_else(|| "response key agreement returned no secret".to_owned())?;
    if secret.len() != 32 {
        let _secret = SensitiveBytes::new(secret);
        return Err("response key agreement returned an invalid secret size".to_owned());
    }
    Ok(SensitiveBytes::new(secret))
}

fn sign_device_identity(key: &KeyDescriptor, request_digest: &[u8]) -> Result<Vec<u8>, String> {
    let _trace = TraceSection::new(b"mystic.keymint.sign\0");
    if request_digest.len() != 32 {
        return Err("device identity request digest must be 32 bytes".to_owned());
    }
    let keystore =
        raw_keystore_service().map_err(|err| format!("keystore connect failed: {err:?}"))?;
    let security_level = keystore
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .map_err(|err| format!("keystore security level failed: {err:?}"))?;
    let params = vec![
        key_param(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::SIGN)),
        key_param(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
    ];
    let operation = security_level
        .createOperation(key, &params, false)
        .map_err(|err| format!("device identity signing operation failed: {err:?}"))?;
    let operation = operation
        .iOperation
        .ok_or_else(|| "device identity signing operation missing".to_owned())?;
    operation
        .finish(Some(request_digest), None)
        .map_err(|err| format!("device identity signing failed: {err:?}"))?
        .ok_or_else(|| "device identity signing returned no signature".to_owned())
}

fn prepare_hardening_pool_key(
    target: &HardeningWrappingPoolTarget,
    wrapping_key_id: &str,
) -> Result<PooledHardeningWrappingKey, HardeningPoolPreparationError> {
    if !canonical_v4_uuid(wrapping_key_id) {
        return Err(HardeningPoolPreparationError::CandidateRejected);
    }
    let mut scope = target.scope.clone();
    scope.idempotency_key = wrapping_key_id.to_owned();
    if hardening_pool_scope_binding_digest(&scope)? != target.binding_sha256 {
        return Err(HardeningFailure.into());
    }
    let identity_spki = hardening_identity_spki(&target.device_identity.certificate_chain)?;
    let preparation_sha256 = hardening_pool_preparation_digest(
        &target.binding_sha256,
        &scope.idempotency_key,
        &identity_spki,
    )?;
    let identity_signature =
        sign_device_identity(&target.device_identity.descriptor, &preparation_sha256)
            .map_err(|_| HardeningFailure)?;
    if identity_signature.is_empty() || identity_signature.len() > 256 {
        return Err(HardeningFailure.into());
    }

    let mut preparation = WrappingKeyPreparationRequestV1::new();
    preparation.scope = MessageField::some(scope.clone());
    preparation.device_identity_chain = target.device_identity.certificate_chain.clone();
    preparation.device_identity_signature = identity_signature;
    let challenge: WrappingKeyPreparationChallengeV1 = hardening_rpc_detailed(
        HARDENING_PREPARE_WRAPPING_KEY_PATH,
        &preparation,
        HardeningRpcWindow::Begin,
    )
    .map_err(|error| classify_pool_prepare_rpc_failure(error, false))?;
    let namespace = validate_hardening_pool_preparation_challenge(
        &challenge,
        &scope,
        wrapping_key_id,
        unix_time_ms()?,
    )?;
    let alias = hardening_pool_alias(
        &target.binding_sha256,
        challenge.server_expires_at_ms,
        wrapping_key_id,
    )?;
    let (key, chain) = generate_hardening_wrapping_key_at_alias(
        &challenge.wrapping_attestation_challenge,
        challenge.server_expires_at_ms,
        &alias,
    )?;
    let certificates = hardening_chain_certificates(&chain)?;
    let wrapping_leaf = X509::from_der(certificates.first().ok_or(HardeningFailure)?)
        .map_err(|_| HardeningFailure)?;
    let wrapping_spki = wrapping_leaf
        .public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|_| HardeningFailure)?;
    let wrapping_spki_sha256 = sha256(&wrapping_spki);
    let wrapping_attestation_sha256 = hardening_chain_digest(&certificates);

    let mut registration = WrappingKeyRegistrationRequestV1::new();
    registration.schema_version = HARDENING_SCHEMA_VERSION;
    registration.protocol_major = HARDENING_PROTOCOL_MAJOR;
    registration.protocol_minor = scope.protocol_minor;
    registration.wrapping_key_id = wrapping_key_id.to_owned();
    registration.wrapping_key_chain = certificates;
    registration.idempotency_key = wrapping_key_id.to_owned();
    let registered: Result<RegisteredWrappingKeyV1, HardeningRpcError> = hardening_rpc_detailed(
        HARDENING_REGISTER_WRAPPING_KEY_PATH,
        &registration,
        HardeningRpcWindow::Grant { expires_at_ms: challenge.server_expires_at_ms },
    );
    let (server_expires_at_ms, recovering) = match registered {
        Ok(registered) => {
            validate_registered_hardening_pool_key(
                &registered,
                &challenge,
                wrapping_key_id,
                unix_time_ms()?,
            )?;
            (registered.server_expires_at_ms, false)
        }
        Err(error)
            if classify_pool_prepare_rpc_failure(error, true)
                == HardeningPoolPreparationError::Transient =>
        {
            // The server can commit registration before the response is lost.
            // Keep the alias and retry the exact registration before first use.
            (challenge.server_expires_at_ms, true)
        }
        Err(error) => return Err(classify_pool_prepare_rpc_failure(error, true)),
    };

    Ok(PooledHardeningWrappingKey {
        descriptor: key.into_descriptor()?,
        wrapping_key_id: wrapping_key_id.to_owned(),
        binding_sha256: target.binding_sha256,
        wrapping_spki_sha256,
        wrapping_attestation_sha256,
        server_expires_at_ms,
        namespace: Some(namespace),
        recovering,
    })
}

fn recover_hardening_pool_registration(
    key_use: &HardeningWrappingKeyUse,
    claim: &HardeningPoolClaim,
    protocol_minor: u32,
) -> Result<(), HardeningPoolPreparationError> {
    if !claim.recovery_registration_allowed || claim.registration_expires_at_ms <= unix_time_ms()? {
        return Err(HardeningPoolPreparationError::CandidateRejected);
    }
    let keystore = raw_keystore_service().map_err(|_| HardeningFailure)?;
    let entry = keystore.getKeyEntry(&key_use.descriptor).map_err(|_| HardeningFailure)?;
    verify_hardening_wrapping_key_characteristics(
        &entry.metadata,
        claim.registration_expires_at_ms,
    )?;
    let chain = certificate_chain_from_metadata(
        entry.metadata.certificate,
        entry.metadata.certificateChain,
        "recovering prepared wrapping key",
    )
    .map_err(|_| HardeningFailure)?;
    let certificates = hardening_chain_certificates(&chain)?;

    let mut registration = WrappingKeyRegistrationRequestV1::new();
    registration.schema_version = HARDENING_SCHEMA_VERSION;
    registration.protocol_major = HARDENING_PROTOCOL_MAJOR;
    registration.protocol_minor = protocol_minor;
    registration.wrapping_key_id = claim.wrapping_key_id.clone();
    registration.wrapping_key_chain = certificates;
    registration.idempotency_key = claim.wrapping_key_id.clone();
    let registered: RegisteredWrappingKeyV1 = hardening_rpc_detailed(
        HARDENING_REGISTER_WRAPPING_KEY_PATH,
        &registration,
        HardeningRpcWindow::Grant { expires_at_ms: claim.registration_expires_at_ms },
    )
    .map_err(|error| classify_pool_prepare_rpc_failure(error, true))?;
    validate_recovered_hardening_pool_key(&registered, claim, protocol_minor, unix_time_ms()?)?;
    Ok(())
}

fn validate_recovered_hardening_pool_key(
    registered: &RegisteredWrappingKeyV1,
    claim: &HardeningPoolClaim,
    protocol_minor: u32,
    now_ms: i64,
) -> HardeningResult<()> {
    if registered.schema_version != HARDENING_SCHEMA_VERSION
        || registered.protocol_major != HARDENING_PROTOCOL_MAJOR
        || registered.protocol_minor != protocol_minor
        || registered.wrapping_key_id != claim.wrapping_key_id
        || registered.server_expires_at_ms != claim.registration_expires_at_ms
        || registered.server_expires_at_ms <= now_ms
        || registered.policy_epoch == 0
        || registered.crypto_namespace != claim.target.scope.crypto_namespace
        || registered.crypto_suite != HARDENING_CRYPTO_SUITE_V1
    {
        return Err(HardeningFailure);
    }
    Ok(())
}

fn validate_hardening_pool_preparation_challenge(
    challenge: &WrappingKeyPreparationChallengeV1,
    scope: &WrappingKeyPoolScopeV1,
    wrapping_key_id: &str,
    now_ms: i64,
) -> HardeningResult<HardeningCryptoNamespace> {
    if challenge.schema_version != HARDENING_SCHEMA_VERSION
        || challenge.protocol_major != HARDENING_PROTOCOL_MAJOR
        || challenge.protocol_minor != scope.protocol_minor
        || challenge.wrapping_key_id != wrapping_key_id
        || !canonical_v4_uuid(&challenge.wrapping_key_id)
        || challenge.wrapping_attestation_challenge.len() != 32
        || challenge.server_expires_at_ms <= now_ms
        || challenge.server_expires_at_ms.saturating_sub(now_ms)
            > HARDENING_POOL_MAX_SERVER_LIFETIME_MS
        || challenge.policy_epoch == 0
        || challenge.crypto_namespace != scope.crypto_namespace
        || challenge.crypto_suite != HARDENING_CRYPTO_SUITE_V1
    {
        return Err(HardeningFailure);
    }
    hardening_namespace(&challenge.crypto_namespace)
}

fn validate_registered_hardening_pool_key(
    registered: &RegisteredWrappingKeyV1,
    challenge: &WrappingKeyPreparationChallengeV1,
    wrapping_key_id: &str,
    now_ms: i64,
) -> HardeningResult<()> {
    if registered.schema_version != HARDENING_SCHEMA_VERSION
        || registered.protocol_major != HARDENING_PROTOCOL_MAJOR
        || registered.protocol_minor != challenge.protocol_minor
        || registered.wrapping_key_id != wrapping_key_id
        || registered.server_expires_at_ms != challenge.server_expires_at_ms
        || registered.server_expires_at_ms <= now_ms
        || registered.policy_epoch != challenge.policy_epoch
        || registered.crypto_namespace != challenge.crypto_namespace
        || registered.crypto_suite != challenge.crypto_suite
    {
        return Err(HardeningFailure);
    }
    Ok(())
}

fn generate_hardening_wrapping_key(
    challenge: &[u8],
    expires_at_ms: i64,
) -> HardeningResult<(TemporaryHardeningKey, Vec<Vec<u8>>)> {
    let alias =
        format!("{HARDENING_ALIAS_PREFIX}{HARDENING_WRAPPING_ALIAS_KIND}{}", Uuid::new_v4());
    generate_hardening_wrapping_key_at_alias(challenge, expires_at_ms, &alias)
}

fn generate_hardening_wrapping_key_at_alias(
    challenge: &[u8],
    expires_at_ms: i64,
    alias: &str,
) -> HardeningResult<(TemporaryHardeningKey, Vec<Vec<u8>>)> {
    if challenge.len() != 32 || expires_at_ms <= 0 || alias.is_empty() || alias.len() > 240 {
        return Err(HardeningFailure);
    }
    let keystore = raw_keystore_service().map_err(|_| HardeningFailure)?;
    let security_level = keystore
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .map_err(|_| HardeningFailure)?;
    let descriptor = app_key_descriptor(alias);
    let serial = get_attest_id_value(Tag::ATTESTATION_ID_SERIAL, "serialno");
    let params = hardening_wrapping_key_params(challenge, expires_at_ms, &serial)?;
    let metadata = security_level
        .generateKey(&descriptor, None, &params, 0, b"MysticAttestation")
        .map_err(|_| HardeningFailure)?;
    let guard = TemporaryHardeningKey::new(descriptor);
    verify_hardening_wrapping_key_characteristics(&metadata, expires_at_ms)?;
    let chain = certificate_chain_from_metadata(
        metadata.certificate,
        metadata.certificateChain,
        "hardening wrapping key",
    )
    .map_err(|_| HardeningFailure)?;
    hardening_chain_certificates(&chain)?;
    Ok((guard, chain))
}

fn verify_hardening_wrapping_key_characteristics(
    metadata: &KeyMetadata,
    expires_at_ms: i64,
) -> HardeningResult<()> {
    if metadata.keySecurityLevel != SecurityLevel::TRUSTED_ENVIRONMENT
        || metadata.authorizations.iter().any(|authorization| {
            matches!(
                authorization.keyParameter.tag,
                Tag::USER_SECURE_ID
                    | Tag::USER_AUTH_TYPE
                    | Tag::AUTH_TIMEOUT
                    | Tag::ALLOW_WHILE_ON_BODY
                    | Tag::TRUSTED_USER_PRESENCE_REQUIRED
                    | Tag::TRUSTED_CONFIRMATION_REQUIRED
                    | Tag::UNLOCKED_DEVICE_REQUIRED
            )
        })
        || !authorization_values_match(&metadata.authorizations, Tag::ALGORITHM, |value| {
            matches!(value, KeyParameterValue::Algorithm(Algorithm::RSA))
        })
        || !authorization_values_match(&metadata.authorizations, Tag::KEY_SIZE, |value| {
            matches!(value, KeyParameterValue::Integer(2048))
        })
        || !authorization_values_match(
            &metadata.authorizations,
            Tag::RSA_PUBLIC_EXPONENT,
            |value| matches!(value, KeyParameterValue::LongInteger(65537)),
        )
        || !authorization_values_match(&metadata.authorizations, Tag::PURPOSE, |value| {
            matches!(value, KeyParameterValue::KeyPurpose(KeyPurpose::WRAP_KEY))
        })
        || !authorization_values_match(&metadata.authorizations, Tag::PADDING, |value| {
            matches!(value, KeyParameterValue::PaddingMode(PaddingMode::RSA_OAEP))
        })
        || !authorization_values_match(&metadata.authorizations, Tag::DIGEST, |value| {
            matches!(value, KeyParameterValue::Digest(Digest::SHA_2_256))
        })
        || !authorization_values_match(
            &metadata.authorizations,
            Tag::RSA_OAEP_MGF_DIGEST,
            |value| matches!(value, KeyParameterValue::Digest(Digest::SHA1)),
        )
        || !authorization_values_match_at_any_level(
            &metadata.authorizations,
            Tag::NO_AUTH_REQUIRED,
            |value| matches!(value, KeyParameterValue::BoolValue(true)),
        )
    {
        return Err(HardeningFailure);
    }
    verify_hardening_wrapping_key_expiry(metadata, expires_at_ms)
}

fn verify_hardening_wrapping_key_expiry(
    metadata: &KeyMetadata,
    expires_at_ms: i64,
) -> HardeningResult<()> {
    if expires_at_ms <= 0
        || !authorization_values_match_at_any_level(
            &metadata.authorizations,
            Tag::USAGE_EXPIRE_DATETIME,
            |value| matches!(value, KeyParameterValue::DateTime(expiry) if *expiry == expires_at_ms),
        )
    {
        return Err(HardeningFailure);
    }
    Ok(())
}

fn hardening_wrapping_key_params(
    challenge: &[u8],
    expires_at_ms: i64,
    serial: &[u8],
) -> HardeningResult<Vec<KeyParameter>> {
    if challenge.len() != 32
        || expires_at_ms <= 0
        || serial.is_empty()
        || serial.len() > HARDENING_MAX_ID_BYTES
    {
        return Err(HardeningFailure);
    }
    Ok(vec![
        key_param(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::RSA)),
        key_param(Tag::KEY_SIZE, KeyParameterValue::Integer(2048)),
        key_param(Tag::RSA_PUBLIC_EXPONENT, KeyParameterValue::LongInteger(65537)),
        key_param(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::WRAP_KEY)),
        key_param(Tag::PADDING, KeyParameterValue::PaddingMode(PaddingMode::RSA_OAEP)),
        key_param(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        key_param(Tag::RSA_OAEP_MGF_DIGEST, KeyParameterValue::Digest(Digest::SHA1)),
        key_param(Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
        key_param(Tag::ATTESTATION_CHALLENGE, KeyParameterValue::Blob(challenge.to_vec())),
        key_param(Tag::USAGE_EXPIRE_DATETIME, KeyParameterValue::DateTime(expires_at_ms)),
        key_param(Tag::CERTIFICATE_NOT_AFTER, KeyParameterValue::DateTime(expires_at_ms)),
        key_param(Tag::CERTIFICATE_SERIAL, KeyParameterValue::Blob(vec![3])),
        key_param(Tag::ATTESTATION_ID_SERIAL, KeyParameterValue::Blob(serial.to_vec())),
    ])
}

fn import_hardening_capability(
    wrapping_key: &KeyDescriptor,
    secure_key_wrapper: &[u8],
    expires_at_ms: i64,
) -> HardeningResult<TemporaryHardeningKey> {
    if secure_key_wrapper.is_empty() || secure_key_wrapper.len() > HARDENING_MAX_WRAPPER_BYTES {
        return Err(HardeningFailure);
    }
    let keystore = raw_keystore_service().map_err(|_| HardeningFailure)?;
    let security_level = keystore
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .map_err(|_| HardeningFailure)?;
    let alias =
        format!("{HARDENING_ALIAS_PREFIX}{HARDENING_CAPABILITY_ALIAS_KIND}{}", Uuid::new_v4());
    let descriptor = KeyDescriptor {
        domain: Domain::APP,
        nspace: -1,
        alias: Some(alias),
        blob: Some(secure_key_wrapper.to_vec()),
    };
    let unwrap_params = vec![
        key_param(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        key_param(Tag::PADDING, KeyParameterValue::PaddingMode(PaddingMode::RSA_OAEP)),
        key_param(Tag::RSA_OAEP_MGF_DIGEST, KeyParameterValue::Digest(Digest::SHA1)),
    ];
    let authenticators = [AuthenticatorSpec {
        authenticatorType: HardwareAuthenticatorType::NONE,
        authenticatorId: 0,
    }];
    let metadata = match security_level.importWrappedKey(
        &descriptor,
        wrapping_key,
        None,
        &unwrap_params,
        &authenticators,
    ) {
        Ok(metadata) => {
            intensive_log!(
                "optional runtime stage capability import completed: operation=keymint_import"
            );
            metadata
        }
        Err(error) => {
            intensive_log!(
                "optional runtime stage capability import failed: operation=keymint_import exception={:?} service={}",
                error.exception_code(),
                error.service_specific_error()
            );
            return Err(HardeningFailure);
        }
    };
    let guard = TemporaryHardeningKey::new(metadata.key.clone());
    if let Err(reason) = verify_hardening_capability_characteristics(&metadata, expires_at_ms) {
        intensive_log!(
            "optional runtime stage capability import failed: operation=characteristics_validation reason={}",
            reason.log_class()
        );
        return Err(HardeningFailure);
    }
    intensive_log!(
        "optional runtime stage capability import completed: operation=characteristics_validation"
    );
    Ok(guard)
}

fn verify_hardening_capability_characteristics(
    metadata: &KeyMetadata,
    expires_at_ms: i64,
) -> Result<(), HardeningCapabilityCharacteristicsFailure> {
    if expires_at_ms <= 0 {
        return Err(HardeningCapabilityCharacteristicsFailure::InvalidExpiry);
    }
    if metadata.keySecurityLevel != SecurityLevel::TRUSTED_ENVIRONMENT {
        return Err(HardeningCapabilityCharacteristicsFailure::KeySecurityLevel);
    }
    if metadata.authorizations.iter().any(|authorization| {
        matches!(
            authorization.keyParameter.tag,
            Tag::USER_SECURE_ID
                | Tag::USER_AUTH_TYPE
                | Tag::AUTH_TIMEOUT
                | Tag::ALLOW_WHILE_ON_BODY
                | Tag::TRUSTED_USER_PRESENCE_REQUIRED
                | Tag::TRUSTED_CONFIRMATION_REQUIRED
                | Tag::UNLOCKED_DEVICE_REQUIRED
        )
    }) {
        return Err(HardeningCapabilityCharacteristicsFailure::UserAuthentication);
    }
    if !authorization_values_match(&metadata.authorizations, Tag::ALGORITHM, |value| {
        matches!(value, KeyParameterValue::Algorithm(Algorithm::HMAC))
    }) {
        return Err(HardeningCapabilityCharacteristicsFailure::Algorithm);
    }
    if !authorization_values_match(&metadata.authorizations, Tag::KEY_SIZE, |value| {
        matches!(value, KeyParameterValue::Integer(256))
    }) {
        return Err(HardeningCapabilityCharacteristicsFailure::KeySize);
    }
    if !authorization_values_match(&metadata.authorizations, Tag::PURPOSE, |value| {
        matches!(value, KeyParameterValue::KeyPurpose(KeyPurpose::SIGN))
    }) {
        return Err(HardeningCapabilityCharacteristicsFailure::Purpose);
    }
    if !authorization_values_match(&metadata.authorizations, Tag::DIGEST, |value| {
        matches!(value, KeyParameterValue::Digest(Digest::SHA_2_256))
    }) {
        return Err(HardeningCapabilityCharacteristicsFailure::Digest);
    }
    if !authorization_values_match(&metadata.authorizations, Tag::MIN_MAC_LENGTH, |value| {
        matches!(value, KeyParameterValue::Integer(256))
    }) {
        return Err(HardeningCapabilityCharacteristicsFailure::MinimumMacLength);
    }
    if !authorization_values_match(&metadata.authorizations, Tag::NO_AUTH_REQUIRED, |value| {
        matches!(value, KeyParameterValue::BoolValue(true))
    }) {
        return Err(HardeningCapabilityCharacteristicsFailure::NoAuthRequired);
    }
    if !authorization_values_match_at_any_level(
        &metadata.authorizations,
        Tag::ORIGINATION_EXPIRE_DATETIME,
        |value| matches!(value, KeyParameterValue::DateTime(expiry) if *expiry == expires_at_ms),
    ) {
        return Err(HardeningCapabilityCharacteristicsFailure::OriginationExpiry);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardeningCapabilityCharacteristicsFailure {
    InvalidExpiry,
    KeySecurityLevel,
    UserAuthentication,
    Algorithm,
    KeySize,
    Purpose,
    Digest,
    MinimumMacLength,
    NoAuthRequired,
    OriginationExpiry,
}

impl HardeningCapabilityCharacteristicsFailure {
    fn log_class(self) -> &'static str {
        match self {
            Self::InvalidExpiry => "invalid_expiry",
            Self::KeySecurityLevel => "key_security_level",
            Self::UserAuthentication => "user_authentication",
            Self::Algorithm => "algorithm",
            Self::KeySize => "key_size",
            Self::Purpose => "purpose",
            Self::Digest => "digest",
            Self::MinimumMacLength => "minimum_mac_length",
            Self::NoAuthRequired => "no_auth_required",
            Self::OriginationExpiry => "origination_expiry",
        }
    }
}

fn authorization_values_match(
    authorizations: &[Authorization],
    tag: Tag,
    expected: impl Fn(&KeyParameterValue) -> bool,
) -> bool {
    let mut found = false;
    for authorization in authorizations.iter().filter(|value| value.keyParameter.tag == tag) {
        found = true;
        if authorization.securityLevel != SecurityLevel::TRUSTED_ENVIRONMENT
            || !expected(&authorization.keyParameter.value)
        {
            return false;
        }
    }
    found
}

fn authorization_values_match_at_any_level(
    authorizations: &[Authorization],
    tag: Tag,
    expected: impl Fn(&KeyParameterValue) -> bool,
) -> bool {
    let mut found = false;
    for authorization in authorizations.iter().filter(|value| value.keyParameter.tag == tag) {
        found = true;
        if !expected(&authorization.keyParameter.value) {
            return false;
        }
    }
    found
}

fn hardening_capability_derivation(
    key: &KeyDescriptor,
    namespace: HardeningCryptoNamespace,
    transcript_sha256: &[u8; 32],
) -> HardeningResult<SensitiveKey> {
    let keystore = raw_keystore_service().map_err(|_| HardeningFailure)?;
    let security_level = keystore
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .map_err(|_| HardeningFailure)?;
    let params = vec![
        key_param(Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::SIGN)),
        key_param(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        key_param(Tag::MAC_LENGTH, KeyParameterValue::Integer(256)),
    ];
    let operation = security_level
        .createOperation(key, &params, false)
        .map_err(|_| HardeningFailure)?
        .iOperation
        .ok_or(HardeningFailure)?;
    let mut input = SensitiveBytes::new(Vec::with_capacity(
        namespace.capability_domain().len() + transcript_sha256.len(),
    ));
    input.0.extend_from_slice(namespace.capability_domain());
    input.0.extend_from_slice(transcript_sha256);
    let mut output = SensitiveBytes::new(
        operation
            .finish(Some(&input), None)
            .map_err(|_| HardeningFailure)?
            .ok_or(HardeningFailure)?,
    );
    if output.len() != 32 {
        return Err(HardeningFailure);
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&output);
    secure_wipe(&mut output);
    Ok(SensitiveKey(result))
}

fn overwrite_device_identity_digest(request: &OverwriteAttestationRequest) -> [u8; 32] {
    let mut canonical = Vec::new();
    push_identity_field(&mut canonical, DEVICE_IDENTITY_REQUEST_DOMAIN);
    push_identity_field(&mut canonical, b"OverwriteAttestation");
    push_identity_u32(&mut canonical, request.protocol_version);
    push_identity_field(&mut canonical, request.request_id.trim().as_bytes());
    push_identity_field(&mut canonical, &request.leaf_certificate);
    push_identity_field(&mut canonical, &request.remaining_chain);
    push_identity_fields(&mut canonical, &request.device_attestation_chain);
    push_identity_fields(&mut canonical, &request.response_encryption_key_chain);
    push_identity_field(&mut canonical, request.untrusted_device_serial.trim().as_bytes());
    let digest = sha256(&canonical);
    secure_wipe(&mut canonical);
    digest
}

fn provision_device_identity_digest(request: &ProvisionAttestationKeyRequest) -> [u8; 32] {
    let mut canonical = Vec::new();
    push_identity_field(&mut canonical, DEVICE_IDENTITY_REQUEST_DOMAIN);
    push_identity_field(&mut canonical, b"ProvisionAttestationKey");
    push_identity_u32(&mut canonical, ATTESTATION_PROTOCOL_VERSION);
    push_identity_field(&mut canonical, request.request_id.trim().as_bytes());
    push_identity_fields(&mut canonical, &request.device_attestation_chain);
    push_identity_fields(&mut canonical, &request.response_encryption_key_chain);
    push_identity_field(&mut canonical, request.untrusted_device_serial.trim().as_bytes());
    if let Some(profile) = request.certificate_profile.as_ref() {
        push_identity_u32(&mut canonical, 1);
        push_identity_field(&mut canonical, &profile.subject_der);
        push_identity_field(&mut canonical, &profile.serial_number);
        canonical.extend_from_slice(&profile.not_before_ms.to_be_bytes());
        canonical.extend_from_slice(&profile.not_after_ms.to_be_bytes());
        push_identity_field(&mut canonical, &profile.attestation_challenge);
        push_identity_field(&mut canonical, &profile.attestation_application_id);
    } else {
        push_identity_u32(&mut canonical, 0);
    }
    push_identity_fields(&mut canonical, &request.wrapping_key_chain);
    let digest = sha256(&canonical);
    secure_wipe(&mut canonical);
    digest
}

fn push_identity_fields(canonical: &mut Vec<u8>, values: &[Vec<u8>]) {
    push_identity_u32(canonical, values.len() as u32);
    for value in values {
        push_identity_field(canonical, value);
    }
}

fn push_identity_field(canonical: &mut Vec<u8>, value: &[u8]) {
    canonical.extend_from_slice(&(value.len() as u64).to_be_bytes());
    canonical.extend_from_slice(value);
}

fn push_identity_u32(canonical: &mut Vec<u8>, value: u32) {
    canonical.extend_from_slice(&value.to_be_bytes());
}

fn aidl_u32(value: i32) -> HardeningResult<u32> {
    u32::try_from(value).map_err(|_| HardeningFailure)
}

fn aidl_u64(value: i64) -> HardeningResult<u64> {
    u64::try_from(value).map_err(|_| HardeningFailure)
}

fn array32(value: &[u8]) -> HardeningResult<[u8; 32]> {
    value.try_into().map_err(|_| HardeningFailure)
}

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= HARDENING_MAX_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn canonical_v4_uuid(value: &str) -> bool {
    value.len() == 36
        && value.as_bytes().get(14) == Some(&b'4')
        && value.as_bytes().get(19).is_some_and(|byte| matches!(byte, b'8' | b'9' | b'a' | b'b'))
        && Uuid::parse_str(value).is_ok_and(|uuid| uuid.to_string() == value)
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn parse_lower_hex_32(value: &str) -> HardeningResult<[u8; 32]> {
    if value.len() != 64
        || value.bytes().any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(HardeningFailure);
    }
    let mut decoded = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16).ok_or(HardeningFailure)? as u8;
        let low = (pair[1] as char).to_digit(16).ok_or(HardeningFailure)? as u8;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn hardening_pool_alias(
    binding_sha256: &[u8; 32],
    server_expires_at_ms: i64,
    wrapping_key_id: &str,
) -> HardeningResult<String> {
    if server_expires_at_ms <= 0 || !canonical_v4_uuid(wrapping_key_id) {
        return Err(HardeningFailure);
    }
    Ok(format!(
        "{HARDENING_ALIAS_PREFIX}{HARDENING_POOL_ALIAS_KIND}{}_{:016x}_{wrapping_key_id}",
        lower_hex(binding_sha256),
        server_expires_at_ms as u64,
    ))
}

fn hardening_idempotency(base: &str, operation: &str) -> HardeningResult<String> {
    let value = format!("{base}:{operation}");
    if value.len() > HARDENING_MAX_ID_BYTES || !bounded_identifier(&value) {
        return Err(HardeningFailure);
    }
    Ok(value)
}

fn unix_time_ms() -> HardeningResult<i64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| HardeningFailure)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| HardeningFailure)
}

fn processor_sha256() -> HardeningResult<[u8; 32]> {
    match PROCESSOR_SHA256.get_or_init(|| {
        let mut file = File::open("/proc/self/exe").map_err(|_| ())?;
        let mut hasher = Hasher::new(MessageDigest::sha256()).map_err(|_| ())?;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(|_| ())?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]).map_err(|_| ())?;
        }
        let digest = hasher.finish().map_err(|_| ())?;
        digest.as_ref().try_into().map_err(|_| ())
    }) {
        Ok(value) => Ok(*value),
        Err(()) => Err(HardeningFailure),
    }
}

fn hardening_identity_spki(chain: &[Vec<u8>]) -> HardeningResult<Vec<u8>> {
    let certificates = hardening_chain_certificates(chain)?;
    let leaf = X509::from_der(certificates.first().ok_or(HardeningFailure)?)
        .map_err(|_| HardeningFailure)?;
    leaf.public_key().and_then(|key| key.public_key_to_der()).map_err(|_| HardeningFailure)
}

fn hardening_chain_certificates(chain: &[Vec<u8>]) -> HardeningResult<Vec<Vec<u8>>> {
    if chain.is_empty() || chain.len() > HARDENING_MAX_CHAIN_CERTIFICATES {
        return Err(HardeningFailure);
    }
    let mut total = 0usize;
    let mut certificates = Vec::new();
    for chunk in chain {
        if chunk.is_empty() || chunk.len() > HARDENING_MAX_CHAIN_BYTES {
            return Err(HardeningFailure);
        }
        for encoded in split_concatenated_der_certificates(chunk).map_err(|_| HardeningFailure)? {
            if encoded.len() > HARDENING_MAX_CERTIFICATE_BYTES
                || certificates.len() >= HARDENING_MAX_CHAIN_CERTIFICATES
            {
                return Err(HardeningFailure);
            }
            total = total.checked_add(encoded.len()).ok_or(HardeningFailure)?;
            if total > HARDENING_MAX_CHAIN_BYTES {
                return Err(HardeningFailure);
            }
            certificates.push(encoded.to_vec());
        }
    }
    if certificates.is_empty() {
        return Err(HardeningFailure);
    }
    Ok(certificates)
}

fn hardening_chain_digest(certificates: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = openssl::sha::Sha256::new();
    for certificate in certificates {
        hasher.update(certificate);
    }
    hasher.finish()
}

fn hardening_namespace(
    value: &protobuf::EnumOrUnknown<HardeningCryptoNamespaceV1>,
) -> HardeningResult<HardeningCryptoNamespace> {
    match value.enum_value().map_err(|_| HardeningFailure)? {
        HardeningCryptoNamespaceV1::HARDENING_CRYPTO_NAMESPACE_RELEASE => {
            Ok(HardeningCryptoNamespace::Release)
        }
        HardeningCryptoNamespaceV1::HARDENING_CRYPTO_NAMESPACE_DEBUG => {
            Ok(HardeningCryptoNamespace::Debug)
        }
        _ => Err(HardeningFailure),
    }
}

fn hardening_validation_checks(phase: &'static str, checks: &[(&'static str, bool)]) -> bool {
    let mut valid = true;
    for (reason, accepted) in checks {
        if !accepted {
            intensive_log!(
                "optional runtime stage validation failed: phase={} check={}",
                phase,
                reason
            );
            valid = false;
        }
    }
    valid
}

fn validate_hardening_challenge(
    challenge: &HardeningChallengeV1,
    context: &HardeningContextV1,
    expected_wrapping_key_id: &str,
    recovery: Option<HardeningRecoveryUse>,
    now_ms: i64,
) -> HardeningResult<HardeningCryptoNamespace> {
    let wrapping_key_mode_is_valid = if expected_wrapping_key_id.is_empty() {
        challenge.wrapping_key_id.is_empty() && challenge.wrapping_attestation_challenge.len() == 32
    } else {
        canonical_v4_uuid(expected_wrapping_key_id)
            && challenge.wrapping_key_id == expected_wrapping_key_id
            && challenge.wrapping_attestation_challenge.is_empty()
    };
    let protected = context.purpose == HARDENING_PURPOSE_PROTECTED;
    let recovery_shape_is_valid = if protected {
        challenge.recovery_selector.len() == HARDENING_RECOVERY_SELECTOR_BYTES
            && challenge.recovery_selector.iter().any(|byte| *byte != 0)
            && challenge.recovery_expires_at_ms > now_ms
            && challenge.recovery_expires_at_ms.saturating_sub(now_ms)
                <= HARDENING_RECOVERY_MAX_SERVER_LIFETIME_MS
    } else {
        recovery.is_none()
            && context.recovery_selector.is_empty()
            && challenge.recovery_selector.is_empty()
            && challenge.recovery_expires_at_ms == 0
    };
    let recovery_binding_is_valid = if protected {
        match recovery {
            Some(expected) => {
                memcmp::eq(&challenge.recovery_selector, &expected.selector)
                    && challenge.recovery_expires_at_ms == expected.expires_at_ms
                    && memcmp::eq(&context.recovery_selector, &expected.selector)
            }
            None => context.recovery_selector.is_empty(),
        }
    } else {
        true
    };
    let namespace = hardening_namespace(&challenge.crypto_namespace);
    let valid = hardening_validation_checks(
        "begin",
        &[
            ("challenge_schema", challenge.schema_version == HARDENING_SCHEMA_VERSION),
            ("challenge_protocol_major", challenge.protocol_major == HARDENING_PROTOCOL_MAJOR),
            ("challenge_protocol_minor", challenge.protocol_minor == context.protocol_minor),
            ("challenge_session", bounded_identifier(&challenge.session_id)),
            ("challenge_grant", bounded_identifier(&challenge.grant_id)),
            ("challenge_nonce", challenge.server_nonce.len() == 32),
            ("challenge_wrapping", wrapping_key_mode_is_valid),
            ("challenge_policy_epoch", challenge.policy_epoch != 0),
            ("challenge_generation", challenge.grant_generation != 0),
            ("challenge_crypto_suite", challenge.crypto_suite == HARDENING_CRYPTO_SUITE_V1),
            (
                "challenge_expiry",
                challenge.server_expires_at_ms > now_ms
                    && challenge.server_expires_at_ms.saturating_sub(now_ms)
                        <= HARDENING_MAX_SERVER_LIFETIME_MS,
            ),
            ("challenge_recovery_shape", recovery_shape_is_valid),
            ("challenge_recovery_binding", recovery_binding_is_valid),
            ("challenge_crypto_namespace", namespace.is_ok()),
        ],
    );
    if !valid {
        return Err(hardening_failure_with_reason("challenge_validation"));
    }
    namespace
}

fn validate_hardening_grant(
    grant: &HardeningGrantV1,
    challenge: &HardeningChallengeV1,
    transcript_sha256: &[u8; 32],
    now_ms: i64,
) -> HardeningResult<()> {
    if grant.schema_version != HARDENING_SCHEMA_VERSION
        || grant.protocol_major != HARDENING_PROTOCOL_MAJOR
        || grant.protocol_minor != challenge.protocol_minor
        || grant.session_id != challenge.session_id
        || grant.grant_id != challenge.grant_id
        || grant.grant_generation != challenge.grant_generation
        || grant.policy_epoch != challenge.policy_epoch
        || grant.crypto_namespace != challenge.crypto_namespace
        || grant.crypto_suite != HARDENING_CRYPTO_SUITE_V1
        || grant.server_expires_at_ms != challenge.server_expires_at_ms
        || grant.server_expires_at_ms <= now_ms
        || grant.transcript_sha256 != transcript_sha256
        || grant.secure_key_wrapper.is_empty()
        || grant.secure_key_wrapper.len() > HARDENING_MAX_WRAPPER_BYTES
        || grant.sealed_payload.len() < HARDENING_PAYLOAD_HEADER_BYTES + AES_GCM_TAG_BYTES
        || grant.sealed_payload.len() > MAX_HARDENING_SEALED_PAYLOAD_BYTES
        || grant.receipt.len() > HARDENING_MAX_TOKEN_BYTES
        || grant.receipt_metadata.len() > HARDENING_MAX_TOKEN_BYTES
    {
        return Err(HardeningFailure);
    }
    Ok(())
}

fn validate_hardening_transition(
    transition: &GrantTransitionV1,
    grant: &HardeningGrantV1,
    now_ms: i64,
) -> HardeningResult<()> {
    validate_hardening_transition_common(transition, grant, now_ms)?;
    if transition.authorized_payload.len() != HARDENING_AUTHORIZATION_TAG_BYTES
        || transition.authorized_payload.iter().all(|byte| *byte == 0)
    {
        return Err(HardeningFailure);
    }
    Ok(())
}

fn validate_hardening_transition_for_stage(
    transition: &GrantTransitionV1,
    grant: &HardeningGrantV1,
    kind: HardeningStageKind,
    now_ms: i64,
) -> HardeningResult<()> {
    match kind {
        HardeningStageKind::FunctionalApply(_) => {
            validate_hardening_transition(transition, grant, now_ms)
        }
        HardeningStageKind::ProtectedBundle => {
            validate_hardening_protected_transition(transition, grant, now_ms)
        }
    }
}

fn validate_hardening_transition_common(
    transition: &GrantTransitionV1,
    grant: &HardeningGrantV1,
    now_ms: i64,
) -> HardeningResult<()> {
    if transition.schema_version != HARDENING_SCHEMA_VERSION
        || transition.protocol_major != HARDENING_PROTOCOL_MAJOR
        || transition.protocol_minor != grant.protocol_minor
        || transition.session_id != grant.session_id
        || transition.grant_id != grant.grant_id
        || transition.policy_epoch != grant.policy_epoch
        || transition.crypto_namespace != grant.crypto_namespace
        || transition.crypto_suite != HARDENING_CRYPTO_SUITE_V1
        || transition.server_expires_at_ms != grant.server_expires_at_ms
        || transition.server_expires_at_ms <= now_ms
        || transition.receipt.is_empty()
        || transition.receipt.len() > HARDENING_MAX_TOKEN_BYTES
        || transition.next_voucher.is_empty()
        || transition.next_voucher.len() > HARDENING_MAX_TOKEN_BYTES
    {
        return Err(HardeningFailure);
    }
    Ok(())
}

fn validate_hardening_protected_transition(
    transition: &GrantTransitionV1,
    grant: &HardeningGrantV1,
    now_ms: i64,
) -> HardeningResult<()> {
    validate_hardening_transition_common(transition, grant, now_ms)?;
    if !transition.authorized_payload.is_empty()
        || validate_hardening_verification_proof(&transition.opaque_continuation).is_err()
        || !transition.auxiliary_capsule.is_empty()
    {
        return Err(HardeningFailure);
    }
    Ok(())
}

fn validate_hardening_result(
    runtime_payload: &[u8],
    identity: HardeningApplyIdentity,
    authorization_tag: &[u8],
    verification_proof: &[u8],
    transcript_sha256: &[u8],
    server_expires_at_ms: i64,
    now_ms: i64,
) -> HardeningResult<()> {
    hardening_apply_descriptor_digest(runtime_payload, identity)?;
    if authorization_tag.len() != HARDENING_AUTHORIZATION_TAG_BYTES
        || authorization_tag.iter().all(|byte| *byte == 0)
        || validate_hardening_verification_proof(verification_proof).is_err()
        || transcript_sha256.len() != HARDENING_TRANSCRIPT_BYTES
        || transcript_sha256.iter().all(|byte| *byte == 0)
        || server_expires_at_ms <= now_ms
        || server_expires_at_ms.saturating_sub(now_ms) > HARDENING_MAX_SERVER_LIFETIME_MS
    {
        return Err(HardeningFailure);
    }
    let aggregate = runtime_payload
        .len()
        .checked_add(authorization_tag.len())
        .and_then(|value| value.checked_add(verification_proof.len()))
        .and_then(|value| value.checked_add(transcript_sha256.len()))
        .ok_or(HardeningFailure)?;
    if aggregate > HARDENING_MAX_RESULT_BYTES {
        return Err(HardeningFailure);
    }
    Ok(())
}

/// Validates the protected bundle boundary without decoding bundle contents.
fn validate_hardening_protected_bundle(bundle: &[u8]) -> HardeningResult<()> {
    if bundle.is_empty() || bundle.len() > HARDENING_MAX_PROTECTED_BUNDLE_BYTES {
        return Err(HardeningFailure);
    }
    Ok(())
}

fn validate_hardening_protected_result(
    bundle: &[u8],
    receipt: &[u8],
    next_voucher: &[u8],
    transcript_sha256: &[u8],
    server_expires_at_ms: i64,
    now_ms: i64,
) -> HardeningResult<()> {
    validate_hardening_protected_bundle(bundle)?;
    if receipt.is_empty()
        || receipt.len() > HARDENING_MAX_TOKEN_BYTES
        || next_voucher.is_empty()
        || next_voucher.len() > HARDENING_MAX_TOKEN_BYTES
        || transcript_sha256.len() != HARDENING_TRANSCRIPT_BYTES
        || transcript_sha256.iter().all(|byte| *byte == 0)
        || server_expires_at_ms <= now_ms
        || server_expires_at_ms.saturating_sub(now_ms) > HARDENING_MAX_SERVER_LIFETIME_MS
    {
        return Err(HardeningFailure);
    }
    let aggregate = bundle
        .len()
        .checked_add(receipt.len())
        .and_then(|value| value.checked_add(next_voucher.len()))
        .and_then(|value| value.checked_add(transcript_sha256.len()))
        .ok_or(HardeningFailure)?;
    if aggregate
        > HARDENING_MAX_PROTECTED_BUNDLE_BYTES
            + HARDENING_MAX_TOKEN_BYTES * 2
            + HARDENING_TRANSCRIPT_BYTES
    {
        return Err(HardeningFailure);
    }
    Ok(())
}

/// Returns the server proof without inspecting its signed fields.
///
/// Call this only after the Consume transition passes all common checks.
fn take_hardening_protected_proof(proof: &mut Vec<u8>) -> HardeningResult<Vec<u8>> {
    validate_hardening_verification_proof(proof)?;
    Ok(std::mem::take(proof))
}

/// Returns the B6 result extension without inspecting its opaque contents.
///
/// Call this only after the authorization tag and verification proof validate.
/// Keep this field opaque in the processor. Mystic owns its keyed capsule
/// handling.
fn take_hardening_opaque_result_extension(
    opaque_result_extension: &mut Vec<u8>,
) -> HardeningResult<Vec<u8>> {
    if opaque_result_extension.len() != HARDENING_OPAQUE_RESULT_EXTENSION_BYTES
        || opaque_result_extension.iter().all(|byte| *byte == 0)
    {
        return Err(HardeningFailure);
    }
    Ok(std::mem::take(opaque_result_extension))
}

fn hardening_apply_descriptor_digest(
    runtime_payload: &[u8],
    identity: HardeningApplyIdentity,
) -> HardeningResult<[u8; 32]> {
    if runtime_payload.len() != HARDENING_APPLY_DESCRIPTOR_BYTES {
        return Err(HardeningFailure);
    }
    let spec = hardening_apply_route_spec(identity.purpose, identity.route_id, identity.stage_id)
        .ok_or(HardeningFailure)?;
    let value = |offset: usize| -> HardeningResult<u32> {
        Ok(u32::from_be_bytes(
            runtime_payload[offset..offset + 4].try_into().map_err(|_| HardeningFailure)?,
        ))
    };
    let instruction_count = value(20)?;
    if value(0)? != HARDENING_APPLY_DESCRIPTOR_VERSION
        || value(4)? != identity.vm_schema_version
        || value(8)? != spec.purpose
        || value(12)? != spec.route_id
        || value(16)? != spec.stage_id
        || instruction_count != spec.instruction_count
        || runtime_payload[24..32] != spec.program_domain
        || runtime_payload[32..40].iter().all(|byte| *byte == 0)
    {
        return Err(HardeningFailure);
    }
    Ok(sha256(runtime_payload))
}

fn hardening_context_digest(value: &HardeningContextV1) -> HardeningResult<[u8; 32]> {
    let mut canonical = CanonicalWriter::new();
    canonical.field(HARDENING_CONTEXT_DOMAIN).map_err(|_| HardeningFailure)?;
    canonical.u32(value.schema_version);
    canonical.u32(value.protocol_major);
    canonical.u32(value.protocol_minor);
    canonical.text(&value.build_id).map_err(|_| HardeningFailure)?;
    canonical.field(&value.payload_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&value.processor_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&value.profile_config_sha256).map_err(|_| HardeningFailure)?;
    canonical.u32(value.vm_schema_version);
    canonical.field(&value.device_identity_spki_sha256).map_err(|_| HardeningFailure)?;
    canonical.u32(value.caller_uid);
    canonical.text(&value.security_level).map_err(|_| HardeningFailure)?;
    canonical.u64(value.runtime_epoch);
    canonical.u32(value.purpose);
    canonical.u32(value.route_id);
    canonical.u32(value.stage_id);
    canonical.field(&value.request_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&value.response_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&value.attestation_challenge_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&value.attestation_key_spki_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&value.previous_receipt).map_err(|_| HardeningFailure)?;
    canonical.field(&value.voucher).map_err(|_| HardeningFailure)?;
    canonical.text(&value.idempotency_key).map_err(|_| HardeningFailure)?;
    canonical.text(&value.wrapping_key_id).map_err(|_| HardeningFailure)?;
    canonical.field(&value.latent_binding).map_err(|_| HardeningFailure)?;
    canonical.field(&value.recovery_selector).map_err(|_| HardeningFailure)?;
    Ok(sha256(canonical.bytes()))
}

fn hardening_recovery_scope_digest(value: &HardeningContextV1) -> HardeningResult<[u8; 32]> {
    if value.purpose != HARDENING_PURPOSE_PROTECTED
        || value.route_id != HARDENING_PROTECTED_ROUTE
        || value.stage_id < HARDENING_PROTECTED_INITIAL_STAGE
        || value.stage_id > HARDENING_PROTECTED_FINAL_STAGE
        || value.latent_binding.len() != HARDENING_LATENT_BINDING_BYTES
        || value.latent_binding.iter().all(|byte| *byte == 0)
        || !value.recovery_selector.is_empty()
    {
        return Err(HardeningFailure);
    }
    let mut canonical = CanonicalWriter::new();
    canonical.field(HARDENING_RECOVERY_SCOPE_DOMAIN).map_err(|_| HardeningFailure)?;
    canonical.u32(value.schema_version);
    canonical.u32(value.protocol_major);
    canonical.u32(value.protocol_minor);
    canonical.text(&value.build_id).map_err(|_| HardeningFailure)?;
    canonical.field(&value.payload_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&value.processor_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&value.profile_config_sha256).map_err(|_| HardeningFailure)?;
    canonical.u32(value.vm_schema_version);
    canonical.field(&value.device_identity_spki_sha256).map_err(|_| HardeningFailure)?;
    canonical.u32(value.caller_uid);
    canonical.text(&value.security_level).map_err(|_| HardeningFailure)?;
    canonical.u64(value.runtime_epoch);
    canonical.u32(value.purpose);
    canonical.u32(value.route_id);
    canonical.u32(value.stage_id);
    canonical.field(&value.previous_receipt).map_err(|_| HardeningFailure)?;
    canonical.field(&value.voucher).map_err(|_| HardeningFailure)?;
    canonical.field(&value.latent_binding).map_err(|_| HardeningFailure)?;
    Ok(sha256(canonical.bytes()))
}

fn hardening_pool_scope_binding_digest(
    scope: &WrappingKeyPoolScopeV1,
) -> HardeningResult<[u8; 32]> {
    if scope.schema_version != HARDENING_SCHEMA_VERSION
        || scope.protocol_major != HARDENING_PROTOCOL_MAJOR
        || scope.build_id.is_empty()
        || scope.build_id.len() > HARDENING_MAX_ID_BYTES
        || !bounded_identifier(&scope.build_id)
        || scope.vm_schema_version == 0
        || scope.runtime_epoch == 0
        || scope.security_level != "TEE"
        || (!scope.idempotency_key.is_empty() && !canonical_v4_uuid(&scope.idempotency_key))
        || array32(&scope.payload_sha256)? == [0u8; 32]
        || array32(&scope.processor_sha256)? == [0u8; 32]
        || array32(&scope.profile_config_sha256)? == [0u8; 32]
        || array32(&scope.device_identity_spki_sha256)? == [0u8; 32]
    {
        return Err(HardeningFailure);
    }
    let namespace = hardening_namespace(&scope.crypto_namespace)?;
    let mut canonical = CanonicalWriter::new();
    canonical.field(HARDENING_POOL_SCOPE_DOMAIN).map_err(|_| HardeningFailure)?;
    canonical.u32(scope.schema_version);
    canonical.u32(scope.protocol_major);
    canonical.u32(scope.protocol_minor);
    canonical.text(&scope.build_id).map_err(|_| HardeningFailure)?;
    canonical.field(&scope.payload_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&scope.processor_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(&scope.profile_config_sha256).map_err(|_| HardeningFailure)?;
    canonical.u32(scope.vm_schema_version);
    canonical.field(&scope.device_identity_spki_sha256).map_err(|_| HardeningFailure)?;
    canonical.text(&scope.security_level).map_err(|_| HardeningFailure)?;
    canonical.u64(scope.runtime_epoch);
    canonical.u32(namespace.wire_value());
    Ok(sha256(canonical.bytes()))
}

fn hardening_pool_preparation_digest(
    binding_sha256: &[u8; 32],
    idempotency_key: &str,
    identity_spki: &[u8],
) -> HardeningResult<[u8; 32]> {
    if !canonical_v4_uuid(idempotency_key)
        || identity_spki.is_empty()
        || identity_spki.len() > 4_096
    {
        return Err(HardeningFailure);
    }
    let mut canonical = CanonicalWriter::new();
    canonical.field(HARDENING_POOL_PREPARE_DOMAIN).map_err(|_| HardeningFailure)?;
    canonical.field(binding_sha256).map_err(|_| HardeningFailure)?;
    canonical.text(idempotency_key).map_err(|_| HardeningFailure)?;
    canonical.field(identity_spki).map_err(|_| HardeningFailure)?;
    Ok(sha256(canonical.bytes()))
}

fn hardening_pool_target(
    context: &HardeningContextV1,
    identity: &DeviceIdentityKey,
    namespace: HardeningCryptoNamespace,
) -> HardeningResult<HardeningWrappingPoolTarget> {
    let mut scope = WrappingKeyPoolScopeV1::new();
    scope.schema_version = context.schema_version;
    scope.protocol_major = context.protocol_major;
    scope.protocol_minor = context.protocol_minor;
    scope.build_id = context.build_id.clone();
    scope.payload_sha256 = context.payload_sha256.clone();
    scope.processor_sha256 = context.processor_sha256.clone();
    scope.profile_config_sha256 = context.profile_config_sha256.clone();
    scope.vm_schema_version = context.vm_schema_version;
    scope.device_identity_spki_sha256 = context.device_identity_spki_sha256.clone();
    scope.security_level = context.security_level.clone();
    scope.runtime_epoch = context.runtime_epoch;
    scope.crypto_namespace = protobuf::EnumOrUnknown::new(namespace.wire_enum());
    let binding_sha256 = hardening_pool_scope_binding_digest(&scope)?;
    Ok(HardeningWrappingPoolTarget { scope, binding_sha256, device_identity: identity.clone() })
}

fn hardening_begin_digest(
    context_sha256: &[u8; 32],
    identity_spki: &[u8],
) -> HardeningResult<[u8; 32]> {
    if identity_spki.is_empty() || identity_spki.len() > 2048 {
        return Err(HardeningFailure);
    }
    let mut canonical = CanonicalWriter::new();
    canonical.field(HARDENING_BEGIN_DOMAIN).map_err(|_| HardeningFailure)?;
    canonical.field(context_sha256).map_err(|_| HardeningFailure)?;
    canonical.field(identity_spki).map_err(|_| HardeningFailure)?;
    Ok(sha256(canonical.bytes()))
}

fn hardening_transcript_digest(value: &HardeningTranscriptV1<'_>) -> Result<[u8; 32], String> {
    let mut canonical = CanonicalWriter::new();
    canonical.field(HARDENING_TRANSCRIPT_DOMAIN)?;
    canonical.u32(HARDENING_PROTOCOL_MAJOR);
    canonical.u32(value.protocol_minor);
    canonical.field(value.context_sha256)?;
    canonical.text(value.build_id)?;
    canonical.field(value.payload_sha256)?;
    canonical.text(value.session_id)?;
    canonical.text(value.grant_id)?;
    canonical.u64(value.grant_generation);
    canonical.u32(value.crypto_namespace.wire_value());
    canonical.u32(HARDENING_CRYPTO_SUITE_V1);
    canonical.field(value.server_nonce)?;
    canonical.u32(value.purpose);
    canonical.u32(value.route_id);
    canonical.u32(value.stage_id);
    canonical.field(value.device_identity_spki_sha256)?;
    canonical.text(value.wrapping_key_id)?;
    canonical.field(value.latent_binding)?;
    canonical.field(value.wrapping_spki_sha256)?;
    canonical.field(value.wrapping_attestation_sha256)?;
    canonical.field(value.request_sha256)?;
    canonical.field(value.response_sha256)?;
    canonical.field(&sha256(value.previous_receipt))?;
    canonical.field(&sha256(value.voucher))?;
    canonical.u64(value.server_expires_at_ms);
    canonical.u64(value.policy_epoch);
    Ok(sha256(canonical.bytes()))
}

#[cfg(test)]
fn software_capability_derivation(
    capability: &[u8],
    namespace: HardeningCryptoNamespace,
    transcript_sha256: &[u8; 32],
) -> Result<SensitiveKey, String> {
    if capability.len() != 32 {
        return Err("hardening capability has the wrong size".to_owned());
    }
    let mut input = SensitiveBytes::new(Vec::with_capacity(
        namespace.capability_domain().len() + transcript_sha256.len(),
    ));
    input.0.extend_from_slice(namespace.capability_domain());
    input.0.extend_from_slice(transcript_sha256);
    hmac_sha256(capability, &input)
}

fn derive_hardening_keys(
    derivation: &[u8; 32],
    binding: &HardeningGrantBinding<'_>,
) -> Result<(SensitiveKey, SensitiveKey, SensitiveKey), String> {
    let mut outer_info = SensitiveBytes::new(Vec::with_capacity(
        binding.crypto_namespace.outer_domain().len() + binding.transcript_sha256.len(),
    ));
    outer_info.0.extend_from_slice(binding.crypto_namespace.outer_domain());
    outer_info.0.extend_from_slice(binding.transcript_sha256);
    let mut outer = [0u8; 32];
    hkdf(&mut outer, Md::sha256(), derivation, binding.server_nonce, &outer_info)
        .map_err(|err| format!("hardening outer key derivation failed: {err:?}"))?;

    let mut runtime_info = SensitiveBytes::new(Vec::with_capacity(
        binding.crypto_namespace.runtime_domain().len() + binding.transcript_sha256.len(),
    ));
    runtime_info.0.extend_from_slice(binding.crypto_namespace.runtime_domain());
    runtime_info.0.extend_from_slice(binding.transcript_sha256);
    let mut runtime = [0u8; 32];
    if let Err(err) =
        hkdf(&mut runtime, Md::sha256(), derivation, binding.build_id.as_bytes(), &runtime_info)
    {
        secure_wipe(&mut outer);
        return Err(format!("hardening runtime key derivation failed: {err:?}"));
    }

    let mut apply_info = SensitiveBytes::new(Vec::with_capacity(
        binding.crypto_namespace.apply_key_domain().len() + binding.transcript_sha256.len(),
    ));
    apply_info.0.extend_from_slice(binding.crypto_namespace.apply_key_domain());
    apply_info.0.extend_from_slice(binding.transcript_sha256);
    let mut apply = [0u8; 32];
    if let Err(err) = hkdf(&mut apply, Md::sha256(), derivation, binding.server_nonce, &apply_info)
    {
        secure_wipe(&mut outer);
        secure_wipe(&mut runtime);
        return Err(format!("hardening apply key derivation failed: {err:?}"));
    }
    Ok((SensitiveKey(outer), SensitiveKey(runtime), SensitiveKey(apply)))
}

fn hardening_consume_proof(
    runtime_key: &[u8; 32],
    binding: &HardeningGrantBinding<'_>,
    next_transition_sha256: &[u8; 32],
) -> Result<SensitiveKey, String> {
    let mut canonical = CanonicalWriter::new();
    canonical.field(binding.crypto_namespace.consume_domain())?;
    canonical.text(binding.grant_id)?;
    canonical.field(binding.transcript_sha256)?;
    canonical.field(next_transition_sha256)?;
    hmac_sha256(runtime_key, canonical.bytes())
}

fn hardening_apply_authorization(
    apply_key: &[u8; 32],
    binding: &HardeningGrantBinding<'_>,
    action_sha256: &[u8; 32],
    runtime_payload_sha256: &[u8; 32],
    consumed_receipt_sha256: &[u8; 32],
    server_expires_at_ms: u64,
) -> Result<SensitiveKey, String> {
    let mut canonical = CanonicalWriter::new();
    canonical.field(binding.crypto_namespace.apply_authorization_domain())?;
    canonical.field(binding.transcript_sha256)?;
    canonical.field(action_sha256)?;
    canonical.field(runtime_payload_sha256)?;
    canonical.field(consumed_receipt_sha256)?;
    canonical.u64(binding.policy_epoch);
    canonical.u64(server_expires_at_ms);
    hmac_sha256(apply_key, canonical.bytes())
}

fn hardening_apply_authorization_matches(actual: &[u8], expected: &[u8]) -> bool {
    actual.len() == HARDENING_AUTHORIZATION_TAG_BYTES
        && expected.len() == HARDENING_AUTHORIZATION_TAG_BYTES
        && memcmp::eq(actual, expected)
}

fn validate_hardening_verification_proof(proof: &[u8]) -> HardeningResult<()> {
    if proof.len() != HARDENING_VERIFICATION_PROOF_BYTES || proof.iter().all(|byte| *byte == 0) {
        return Err(HardeningFailure);
    }
    Ok(())
}

fn verify_hardening_authorization_and_take_proof(
    actual_authorization_tag: &[u8],
    expected_authorization_tag: &[u8],
    verification_proof: &mut Vec<u8>,
) -> HardeningResult<Vec<u8>> {
    if !hardening_apply_authorization_matches(actual_authorization_tag, expected_authorization_tag)
    {
        return Err(HardeningFailure);
    }
    validate_hardening_verification_proof(verification_proof)?;
    Ok(std::mem::take(verification_proof))
}

fn open_hardening_payload(
    outer_key: &[u8; 32],
    binding: &HardeningGrantBinding<'_>,
    sealed_payload: &[u8],
) -> Result<SensitiveBytes, String> {
    let (nonce, encrypted) = parse_hardening_payload_envelope(sealed_payload)?;
    let mut aad = CanonicalWriter::new();
    aad.field(binding.crypto_namespace.sealed_payload_domain())?;
    aad.text(binding.session_id)?;
    aad.text(binding.grant_id)?;
    aad.u64(binding.grant_generation);
    aad.u32(binding.crypto_namespace.wire_value());
    aad.u32(HARDENING_CRYPTO_SUITE_V1);
    aad.field(binding.transcript_sha256)?;
    aad.u64(binding.policy_epoch);
    aes_gcm_decrypt(outer_key, nonce, encrypted, aad.bytes())
}

fn parse_hardening_payload_envelope(sealed_payload: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if sealed_payload.len() < HARDENING_PAYLOAD_HEADER_BYTES + AES_GCM_TAG_BYTES {
        return Err("hardening sealed payload is incomplete".to_owned());
    }
    if sealed_payload.len() > MAX_HARDENING_SEALED_PAYLOAD_BYTES {
        return Err("hardening sealed payload is too large".to_owned());
    }
    let version = u32::from_be_bytes(
        sealed_payload[..4]
            .try_into()
            .map_err(|_| "hardening sealed payload version is invalid".to_owned())?,
    );
    if version != HARDENING_SCHEMA_VERSION {
        return Err("hardening sealed payload version is unsupported".to_owned());
    }
    Ok((
        &sealed_payload[4..HARDENING_PAYLOAD_HEADER_BYTES],
        &sealed_payload[HARDENING_PAYLOAD_HEADER_BYTES..],
    ))
}

fn hmac_sha256(key: &[u8], value: &[u8]) -> Result<SensitiveKey, String> {
    let mut output = SensitiveBytes::new(vec![0u8; 32]);
    let output_size = hmac(Md::sha256(), key, value, &mut output)
        .map_err(|err| format!("HMAC failed: {err:?}"))?
        .len();
    if output_size != 32 {
        return Err("HMAC returned the wrong output size".to_owned());
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&output);
    secure_wipe(&mut output);
    Ok(SensitiveKey(result))
}

fn derive_response_aes_key(
    request_id: &str,
    secret: &[u8],
    hkdf_info: &[u8],
) -> Result<SensitiveKey, String> {
    let mut key = [0u8; 32];
    let salt = sha256(&response_key_challenge(request_id));
    hkdf(&mut key, Md::sha256(), secret, &salt, hkdf_info)
        .map_err(|err| format!("response key derivation failed: {err:?}"))?;
    Ok(SensitiveKey(key))
}

fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    encrypted: &[u8],
    aad: &[u8],
) -> Result<SensitiveBytes, String> {
    const GCM_TAG_LEN: usize = 16;
    if encrypted.len() < GCM_TAG_LEN {
        return Err("encrypted response is too short".to_owned());
    }
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - GCM_TAG_LEN);
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, key, Some(nonce))
        .map_err(|err| format!("response decrypt init failed: {err:?}"))?;
    crypter.pad(false);
    crypter.aad_update(aad).map_err(|err| format!("response decrypt aad failed: {err:?}"))?;
    crypter.set_tag(tag).map_err(|err| format!("response decrypt tag failed: {err:?}"))?;
    let mut out =
        SensitiveBytes::new(vec![0u8; ciphertext.len() + Cipher::aes_256_gcm().block_size()]);
    let count = crypter
        .update(ciphertext, &mut out)
        .map_err(|err| format!("response decrypt update failed: {err:?}"))?;
    let rest = crypter
        .finalize(&mut out[count..])
        .map_err(|err| format!("response decrypt verify failed: {err:?}"))?;
    out.0.truncate(count + rest);
    Ok(out)
}

fn keystore_service() -> Result<binder::Strong<dyn IKeystoreService>, Status> {
    raw_keystore_service().map_err(|err| {
        service_error(ERROR_SERVER_REQUEST, &format!("keystore connect failed: {err:?}"))
    })
}

fn raw_keystore_service() -> binder::Result<binder::Strong<dyn IKeystoreService>> {
    Ok(binder::get_interface(KEYSTORE2_SERVICE)?)
}

/// Removes keys left by an interrupted optional runtime stage.
///
/// Call this once before the Binder service is registered. A failed cleanup
/// disables only the optional runtime stage for this process.
pub fn initialize_hardening_stage_key_recovery() -> bool {
    initialize_hardening_stage_key_recovery_with(&HARDENING_KEY_RECOVERY, || {
        let recovered = match recover_hardening_stage_keys() {
            Ok(recovered) => recovered,
            Err(_) => return false,
        };
        let pool = hardening_wrapping_pool();
        let Ok(mut state) = pool.state.lock() else {
            return false;
        };
        state.ready = recovered;
        true
    })
}

fn initialize_hardening_stage_key_recovery_with(
    state: &OnceLock<bool>,
    cleanup: impl FnOnce() -> bool,
) -> bool {
    *state.get_or_init(cleanup)
}

fn recover_hardening_stage_keys() -> HardeningResult<Vec<PooledHardeningWrappingKey>> {
    let now_ms = unix_time_ms()?;
    let keystore = raw_keystore_service().map_err(|_| HardeningFailure)?;
    let mut starting_past = None::<String>;
    let mut recovered = Vec::new();
    let mut key_ids = HashSet::new();
    loop {
        let entries = keystore
            .listEntriesBatched(Domain::APP, -1, starting_past.as_deref())
            .map_err(|_| HardeningFailure)?;
        if entries.is_empty() {
            break;
        }
        let next = entries
            .last()
            .and_then(|descriptor| descriptor.alias.as_deref())
            .filter(|alias| match starting_past.as_deref() {
                Some(previous) => *alias > previous,
                None => true,
            })
            .ok_or(HardeningFailure)?
            .to_owned();
        for descriptor in entries {
            if descriptor_is_temporary_hardening_alias(&descriptor) {
                keystore.deleteKey(&descriptor).map_err(|_| HardeningFailure)?;
                continue;
            }
            let Some(alias) = descriptor.alias.as_deref() else {
                continue;
            };
            let Some(parsed) = parse_hardening_pool_alias(alias) else {
                if alias
                    .strip_prefix(HARDENING_ALIAS_PREFIX)
                    .is_some_and(|suffix| suffix.starts_with(HARDENING_POOL_ALIAS_KIND))
                {
                    keystore.deleteKey(&descriptor).map_err(|_| HardeningFailure)?;
                }
                continue;
            };
            if parsed.server_expires_at_ms <= now_ms
                || parsed.server_expires_at_ms.saturating_sub(now_ms)
                    > HARDENING_POOL_MAX_SERVER_LIFETIME_MS
                || !key_ids.insert(parsed.wrapping_key_id.clone())
            {
                keystore.deleteKey(&descriptor).map_err(|_| HardeningFailure)?;
                continue;
            }
            let recovered_key = (|| -> HardeningResult<_> {
                let entry = keystore.getKeyEntry(&descriptor).map_err(|_| HardeningFailure)?;
                verify_hardening_wrapping_key_characteristics(
                    &entry.metadata,
                    parsed.server_expires_at_ms,
                )?;
                let chain = certificate_chain_from_metadata(
                    entry.metadata.certificate,
                    entry.metadata.certificateChain,
                    "prepared wrapping key",
                )
                .map_err(|_| HardeningFailure)?;
                let certificates = hardening_chain_certificates(&chain)?;
                let leaf = X509::from_der(certificates.first().ok_or(HardeningFailure)?)
                    .map_err(|_| HardeningFailure)?;
                let spki = leaf
                    .public_key()
                    .and_then(|key| key.public_key_to_der())
                    .map_err(|_| HardeningFailure)?;
                Ok(PooledHardeningWrappingKey {
                    descriptor: descriptor.clone(),
                    wrapping_key_id: parsed.wrapping_key_id,
                    binding_sha256: parsed.binding_sha256,
                    wrapping_spki_sha256: sha256(&spki),
                    wrapping_attestation_sha256: hardening_chain_digest(&certificates),
                    server_expires_at_ms: parsed.server_expires_at_ms,
                    namespace: None,
                    recovering: true,
                })
            })();
            match recovered_key {
                Ok(key) => recovered.push(key),
                Err(_) => {
                    keystore.deleteKey(&descriptor).map_err(|_| HardeningFailure)?;
                }
            }
        }
        starting_past = Some(next);
    }
    recovered.sort_by_key(|key| key.server_expires_at_ms);
    if recovered.len() > HARDENING_POOL_CAPACITY {
        recovered.truncate(HARDENING_POOL_CAPACITY);
    }
    Ok(recovered)
}

#[cfg(test)]
fn cleanup_stale_hardening_aliases_with(
    mut list_batch: impl FnMut(Option<&str>) -> HardeningResult<Vec<KeyDescriptor>>,
    mut delete: impl FnMut(&KeyDescriptor) -> HardeningResult<()>,
) -> HardeningResult<()> {
    let mut starting_past = None::<String>;
    loop {
        let entries = list_batch(starting_past.as_deref())?;
        if entries.is_empty() {
            return Ok(());
        }
        let next = entries
            .last()
            .and_then(|descriptor| descriptor.alias.as_deref())
            .filter(|alias| match starting_past.as_deref() {
                Some(previous) => *alias > previous,
                None => true,
            })
            .ok_or(HardeningFailure)?
            .to_owned();
        for descriptor in &entries {
            if descriptor_is_temporary_hardening_alias(descriptor) {
                delete(descriptor)?;
            }
        }
        starting_past = Some(next);
    }
}

fn descriptor_is_temporary_hardening_alias(descriptor: &KeyDescriptor) -> bool {
    if descriptor.domain != Domain::APP {
        return false;
    }
    let Some(alias) = descriptor.alias.as_deref() else {
        return false;
    };
    let Some(suffix) = alias.strip_prefix(HARDENING_ALIAS_PREFIX) else {
        return false;
    };
    let uuid = suffix
        .strip_prefix(HARDENING_WRAPPING_ALIAS_KIND)
        .or_else(|| suffix.strip_prefix(HARDENING_CAPABILITY_ALIAS_KIND));
    uuid.is_some_and(|value| Uuid::parse_str(value).is_ok())
}

struct ParsedHardeningPoolAlias {
    binding_sha256: [u8; 32],
    server_expires_at_ms: i64,
    wrapping_key_id: String,
}

fn parse_hardening_pool_alias(alias: &str) -> Option<ParsedHardeningPoolAlias> {
    let suffix =
        alias.strip_prefix(HARDENING_ALIAS_PREFIX)?.strip_prefix(HARDENING_POOL_ALIAS_KIND)?;
    let mut parts = suffix.split('_');
    let binding_sha256 = parse_lower_hex_32(parts.next()?).ok()?;
    let expiry = parts.next()?;
    if expiry.len() != 16
        || expiry.bytes().any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return None;
    }
    let server_expires_at_ms = i64::try_from(u64::from_str_radix(expiry, 16).ok()?).ok()?;
    let wrapping_key_id = parts.next()?.to_owned();
    if parts.next().is_some() || !canonical_v4_uuid(&wrapping_key_id) {
        return None;
    }
    Some(ParsedHardeningPoolAlias { binding_sha256, server_expires_at_ms, wrapping_key_id })
}

fn wipe_key_descriptor(descriptor: &mut KeyDescriptor) {
    if let Some(alias) = descriptor.alias.take() {
        let mut alias = alias.into_bytes();
        secure_wipe(&mut alias);
    }
    if let Some(blob) = descriptor.blob.as_mut() {
        secure_wipe(blob);
    }
}

fn wipe_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    secure_wipe(&mut bytes);
}

fn delete_key(key: &KeyDescriptor) {
    match raw_keystore_service().and_then(|keystore| keystore.deleteKey(key)) {
        Ok(()) => intensive_log!("deleted response key"),
        Err(err) => error!("failed to delete response key: {err:?}"),
    }
}

fn key_param(tag: Tag, value: KeyParameterValue) -> KeyParameter {
    KeyParameter { tag, value }
}

fn device_attestation_params(identity: ResponseIdentity) -> Vec<KeyParameter> {
    let ids = match identity {
        ResponseIdentity::Full => &[
            (Tag::ATTESTATION_ID_BRAND, "brand"),
            (Tag::ATTESTATION_ID_DEVICE, "device"),
            (Tag::ATTESTATION_ID_PRODUCT, "name"),
            (Tag::ATTESTATION_ID_SERIAL, "serialno"),
            (Tag::ATTESTATION_ID_MANUFACTURER, "manufacturer"),
            (Tag::ATTESTATION_ID_MODEL, "model"),
        ][..],
        ResponseIdentity::Serial => &[(Tag::ATTESTATION_ID_SERIAL, "serialno")][..],
        ResponseIdentity::None => &[],
    };
    ids.iter()
        .filter_map(|&(tag, property)| {
            let value = get_attest_id_value(tag, property);
            if value.is_empty() {
                None
            } else {
                Some(key_param(tag, KeyParameterValue::Blob(value)))
            }
        })
        .collect()
}

fn get_attest_id_value(attest_id: Tag, prop_name: &str) -> Vec<u8> {
    if attest_id == Tag::ATTESTATION_ID_SERIAL {
        return get_system_prop(&format!("ro.{prop_name}"));
    }

    let attestation_prop = get_system_prop(&format!("ro.product.{prop_name}_for_attestation"));
    if !attestation_prop.is_empty() {
        return attestation_prop;
    }
    let vendor_prop = get_system_prop(&format!("ro.product.vendor.{prop_name}"));
    if !vendor_prop.is_empty() {
        return vendor_prop;
    }
    get_system_prop(&format!("ro.product.{prop_name}"))
}

fn get_system_prop(name: &str) -> Vec<u8> {
    match system_properties::read(name) {
        Ok(Some(value)) => value.as_bytes().to_vec(),
        _ => vec![],
    }
}

fn response_key_challenge(request_id: &str) -> Vec<u8> {
    format!("{RESPONSE_KEY_CHALLENGE_PREFIX}{request_id}").into_bytes()
}

fn device_identity_challenge() -> Vec<u8> {
    sha256(DEVICE_IDENTITY_CHALLENGE_DOMAIN).to_vec()
}

fn response_aad(prefix: &str, request_id: &str) -> String {
    format!("{prefix}{request_id}")
}

fn service_error(code: i32, message: &str) -> Status {
    Status::new_service_specific_error_str(code, Some(message))
}

fn hardening_service_error() -> Status {
    service_error(ERROR_HARDENING_UNAVAILABLE, "Hardening runtime is unavailable.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;

    #[derive(Clone)]
    struct TestHardeningKeyDeleter {
        outcomes: Rc<RefCell<VecDeque<bool>>>,
        calls: Rc<Cell<usize>>,
    }

    impl HardeningKeyDeleter for TestHardeningKeyDeleter {
        fn delete(&self, _descriptor: &KeyDescriptor) -> HardeningResult<()> {
            self.calls.set(self.calls.get() + 1);
            if self.outcomes.borrow_mut().pop_front().unwrap_or(true) {
                Ok(())
            } else {
                Err(HardeningFailure)
            }
        }
    }

    #[test]
    fn secure_wipe_clears_all_bytes() {
        let mut bytes = [0x5au8; 32];
        secure_wipe(&mut bytes);
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn provisioner_transactions_remain_compatible() {
        use mystic_attestation_provisioner::aidl::mystic::attestation::provisioner::IBackendAttestationKeyProvisioner::transactions;

        assert_eq!(
            transactions::provisionAttestationKey,
            binder::binder_impl::FIRST_CALL_TRANSACTION
        );
        assert_eq!(
            transactions::authorizeHardeningStage,
            binder::binder_impl::FIRST_CALL_TRANSACTION + 1
        );
        assert_eq!(
            transactions::completeProtectedStage,
            binder::binder_impl::FIRST_CALL_TRANSACTION + 2
        );
    }

    #[test]
    fn protected_stage_completion_digest_matches_backend_golden() {
        let mut request = ProtectedStageCompletionV1::new();
        request.schema_version = 1;
        request.protocol_major = HARDENING_PROTOCOL_MAJOR;
        request.protocol_minor = 0;
        request.session_id = "hs_00112233445566778899aabbccddeeff".to_owned();
        request.grant_id = "hgr_ffeeddccbbaa99887766554433221100".to_owned();
        request.context_sha256 = (1u8..=32).collect();
        request.receipt = vec![0x31, 0x32, 0x33];
        request.next_voucher = vec![0x41, 0x42, 0x43, 0x44];
        request.completion_token = (0x80u8..=0x9f).collect();
        assert_eq!(
            lower_hex(&protected_stage_completion_digest(&request).unwrap()),
            "271a9b7ff97cc227dc9881e10bfeda6d8792b33f87d2c90510972d38d4c512fb"
        );
    }

    #[test]
    fn protected_stage_completion_ids_are_canonical() {
        assert!(valid_prefixed_lower_hex_16("hs_00112233445566778899aabbccddeeff", "hs_"));
        assert!(!valid_prefixed_lower_hex_16("hs_00112233445566778899AABBCCDDEEFF", "hs_"));
        assert!(!valid_prefixed_lower_hex_16("hgr_00112233445566778899aabbccddeeff", "hs_"));
    }

    #[test]
    fn protected_stage_completion_status_mapping_is_closed() {
        assert_eq!(
            hardening_completion_service_code(HardeningCompletionError::Rpc(
                HardeningRpcError::Transient
            )),
            ERROR_HARDENING_UNAVAILABLE
        );
        assert_eq!(
            hardening_completion_service_code(HardeningCompletionError::Rpc(
                HardeningRpcError::Status(Code::DeadlineExceeded)
            )),
            ERROR_HARDENING_UNAVAILABLE
        );
        assert_eq!(
            hardening_completion_service_code(HardeningCompletionError::Rpc(
                HardeningRpcError::Status(Code::InvalidArgument)
            )),
            ERROR_HARDENING_TERMINAL
        );
        assert_eq!(
            hardening_completion_service_code(HardeningCompletionError::Rpc(
                HardeningRpcError::Status(Code::Unknown)
            )),
            ERROR_HARDENING_TERMINAL
        );
        assert_eq!(
            hardening_completion_service_code(HardeningCompletionError::Terminal),
            ERROR_HARDENING_TERMINAL
        );
    }

    #[test]
    fn certificate_input_rejects_incomplete_or_oversized_data() {
        assert!(validate_certificate_input(&[], &[1]).is_err());
        assert!(validate_certificate_input(&[1], &[]).is_err());

        let oversized = vec![0u8; MAX_CERTIFICATE_INPUT_BYTES];
        assert!(validate_certificate_input(&[1], &oversized).is_err());
    }

    #[test]
    fn concatenated_der_parser_rejects_noncanonical_lengths() {
        assert!(split_concatenated_der_certificates(&[0x30, 0x81, 0x01, 0]).is_err());
        assert!(split_concatenated_der_certificates(&[0x30, 0x82, 0x01]).is_err());
    }

    #[test]
    fn concatenated_der_parser_accepts_separate_records() {
        let encoded = [0x30, 0x01, 0, 0x30, 0x02, 1, 2];
        let records = split_concatenated_der_certificates(&encoded).unwrap();
        assert_eq!(records, vec![&encoded[..3], &encoded[3..]]);
    }

    #[test]
    fn zero_certificate_expiration_remains_compatible() {
        assert!(certificate_validity_range_is_valid(1_000, 0));
        assert!(certificate_validity_range_is_valid(1_000, 2_000));
        assert!(!certificate_validity_range_is_valid(1_000, 1_000));
        assert!(!certificate_validity_range_is_valid(1_000, 999));
    }

    #[test]
    fn hardening_transcript_matches_backend_golden_vector() {
        let context = [0x10; 32];
        let payload = [0x11; 32];
        let identity = [0x12; 32];
        let request = [0x13; 32];
        let response = [0x14; 32];
        let wrapping_spki = [0x15; 32];
        let wrapping_attestation = [0x16; 32];
        let server_nonce = [0x44; 32];
        let previous_receipt = [0xa1, 0xa2, 0xa3];
        let voucher = [0xb1, 0xb2, 0xb3, 0xb4];
        let latent_binding = [0x19; HARDENING_LATENT_BINDING_BYTES];
        let transcript = hardening_transcript_digest(&HardeningTranscriptV1 {
            protocol_minor: 0,
            context_sha256: &context,
            build_id: "release-vector-1",
            payload_sha256: &payload,
            session_id: "hs_ffeeddccbbaa99887766554433221100",
            grant_id: "hgr_00112233445566778899aabbccddeeff",
            grant_generation: 7,
            crypto_namespace: HardeningCryptoNamespace::Release,
            server_nonce: &server_nonce,
            purpose: HARDENING_PURPOSE_PROTECTED,
            route_id: HARDENING_PROTECTED_ROUTE,
            stage_id: 2,
            device_identity_spki_sha256: &identity,
            wrapping_key_id: "",
            latent_binding: &latent_binding,
            wrapping_spki_sha256: &wrapping_spki,
            wrapping_attestation_sha256: &wrapping_attestation,
            request_sha256: &request,
            response_sha256: &response,
            previous_receipt: &previous_receipt,
            voucher: &voucher,
            server_expires_at_ms: 1_800_000_000_000,
            policy_epoch: 42,
        })
        .unwrap();
        assert_eq!(
            transcript.as_slice(),
            decode_hex("863a257ab89682eda95000f94289f8245d6cbfdabde1b308b903d3bd72fe5d56")
        );
    }

    #[test]
    fn pooled_hardening_context_and_transcript_match_backend_golden_vectors() {
        let wrapping_key_id = "01234567-89ab-4cde-8fab-0123456789ab";
        let mut context = HardeningContextV1::new();
        context.schema_version = HARDENING_SCHEMA_VERSION;
        context.protocol_major = HARDENING_PROTOCOL_MAJOR;
        context.protocol_minor = 4;
        context.build_id = "release-vector-all-fields-1".to_owned();
        context.payload_sha256 = vec![0x11; 32];
        context.processor_sha256 = vec![0x12; 32];
        context.profile_config_sha256 = vec![0x13; 32];
        context.vm_schema_version = 7;
        context.device_identity_spki_sha256 = vec![0x14; 32];
        context.caller_uid = AID_KEYSTORE;
        context.security_level = "TEE".to_owned();
        context.runtime_epoch = 0x0102_0304_0506_0708;
        context.purpose = HARDENING_PURPOSE_FUNCTIONAL;
        context.route_id = HARDENING_PROCESSED_REPLY_ROUTE;
        context.stage_id = HARDENING_INITIAL_STAGE;
        context.request_sha256 = vec![0x15; 32];
        context.response_sha256 = vec![0x16; 32];
        context.attestation_challenge_sha256 = vec![0x17; 32];
        context.attestation_key_spki_sha256 = vec![0x18; 32];
        context.idempotency_key = "pooled-begin-vector-1".to_owned();
        context.wrapping_key_id = wrapping_key_id.to_owned();

        let context_sha256 = hardening_context_digest(&context).unwrap();
        assert_eq!(
            context_sha256.as_slice(),
            decode_hex("6d396a603988a858a07e8625b1155c1428ad777a133c077fb93835c27fd47129")
        );
        let payload_sha256 = array32(&context.payload_sha256).unwrap();
        let device_identity_spki_sha256 = array32(&context.device_identity_spki_sha256).unwrap();
        let request_sha256 = array32(&context.request_sha256).unwrap();
        let response_sha256 = array32(&context.response_sha256).unwrap();
        let server_nonce = [0x44; 32];
        let wrapping_spki_sha256 = [0x19; 32];
        let wrapping_attestation_sha256 = [0x1a; 32];
        let transcript = hardening_transcript_digest(&HardeningTranscriptV1 {
            protocol_minor: context.protocol_minor,
            context_sha256: &context_sha256,
            build_id: &context.build_id,
            payload_sha256: &payload_sha256,
            session_id: "hs_ffeeddccbbaa99887766554433221100",
            grant_id: "hgr_00112233445566778899aabbccddeeff",
            grant_generation: 7,
            crypto_namespace: HardeningCryptoNamespace::Release,
            server_nonce: &server_nonce,
            purpose: context.purpose,
            route_id: context.route_id,
            stage_id: context.stage_id,
            device_identity_spki_sha256: &device_identity_spki_sha256,
            wrapping_key_id,
            latent_binding: &[],
            wrapping_spki_sha256: &wrapping_spki_sha256,
            wrapping_attestation_sha256: &wrapping_attestation_sha256,
            request_sha256: &request_sha256,
            response_sha256: &response_sha256,
            previous_receipt: &[],
            voucher: &[],
            server_expires_at_ms: 1_800_000_000_000,
            policy_epoch: 42,
        })
        .unwrap();
        assert_eq!(
            transcript.as_slice(),
            decode_hex("363bd2edf5e6bcd72784fbfb3f6c3e57bdd77255cbb538aed48ca544c760a61a")
        );
    }

    #[test]
    fn wrapping_key_pool_preparation_matches_backend_golden_vectors() {
        let mut scope = WrappingKeyPoolScopeV1::new();
        scope.schema_version = HARDENING_SCHEMA_VERSION;
        scope.protocol_major = HARDENING_PROTOCOL_MAJOR;
        scope.protocol_minor = 4;
        scope.build_id = "release-vector-all-fields-1".to_owned();
        scope.payload_sha256 = vec![0x11; 32];
        scope.processor_sha256 = vec![0x12; 32];
        scope.profile_config_sha256 = vec![0x13; 32];
        scope.vm_schema_version = 7;
        scope.device_identity_spki_sha256 = vec![0x14; 32];
        scope.security_level = "TEE".to_owned();
        scope.runtime_epoch = 0x0102_0304_0506_0708;
        scope.crypto_namespace = protobuf::EnumOrUnknown::new(
            HardeningCryptoNamespaceV1::HARDENING_CRYPTO_NAMESPACE_RELEASE,
        );
        scope.idempotency_key = "01234567-89ab-4cde-8fab-0123456789ab".to_owned();

        let binding_sha256 = hardening_pool_scope_binding_digest(&scope).unwrap();
        assert_eq!(
            binding_sha256.as_slice(),
            decode_hex("d21a81d2eeefae2e3b4a196c0e01ddd6015bc77d42f1f6863f6fbcaeebc778b1")
        );
        let mut second_candidate = scope.clone();
        second_candidate.idempotency_key = "fedcba98-7654-4321-8fed-cba987654321".to_owned();
        assert_eq!(hardening_pool_scope_binding_digest(&second_candidate).unwrap(), binding_sha256);
        let preparation_sha256 = hardening_pool_preparation_digest(
            &binding_sha256,
            &scope.idempotency_key,
            &[0x30, 0x03, 0x01, 0x02, 0x03],
        )
        .unwrap();
        assert_eq!(
            preparation_sha256.as_slice(),
            decode_hex("1f724d617a772afab6b79b60fc58d755a327a68dcbeaf57d49cf03f4070bbeaa")
        );
    }

    #[test]
    fn hardening_context_and_begin_match_backend_golden_vectors() {
        let mut context = HardeningContextV1::new();
        context.schema_version = HARDENING_SCHEMA_VERSION;
        context.protocol_major = HARDENING_PROTOCOL_MAJOR;
        context.protocol_minor = 4;
        context.build_id = "release-vector-all-fields-1".to_owned();
        context.payload_sha256 = vec![0x11; 32];
        context.processor_sha256 = vec![0x12; 32];
        context.profile_config_sha256 = vec![0x13; 32];
        context.vm_schema_version = 7;
        context.device_identity_spki_sha256 = vec![0x14; 32];
        context.caller_uid = AID_KEYSTORE;
        context.security_level = "StrongBox".to_owned();
        context.runtime_epoch = 0x0102_0304_0506_0708;
        context.purpose = HARDENING_PURPOSE_PROTECTED;
        context.route_id = HARDENING_PROTECTED_ROUTE;
        context.stage_id = 2;
        context.request_sha256 = vec![0x15; 32];
        context.response_sha256 = vec![0x16; 32];
        context.attestation_challenge_sha256 = vec![0x17; 32];
        context.attestation_key_spki_sha256 = vec![0x18; 32];
        context.previous_receipt = vec![0xa1, 0xa2, 0xa3];
        context.voucher = vec![0xb1, 0xb2, 0xb3, 0xb4];
        context.idempotency_key = "begin-vector-all-fields-1".to_owned();
        context.latent_binding = vec![0x19; HARDENING_LATENT_BINDING_BYTES];

        let context_sha256 = hardening_context_digest(&context).unwrap();
        assert_eq!(
            context_sha256.as_slice(),
            decode_hex("68b2a3c483df224b79489976cbfe8bece34c1b69f8ac22ca9d686eb03b1c83ad")
        );
        let begin_sha256 =
            hardening_begin_digest(&context_sha256, &[0x30, 0x03, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(
            begin_sha256.as_slice(),
            decode_hex("a29ddc8da237a89bdf265cc2247b6d548b1c44b870ef52e465817a5c9da45944")
        );
    }

    #[test]
    fn hardening_context_binds_each_functional_apply_identity() {
        let mut context = HardeningContextV1::new();
        context.schema_version = HARDENING_SCHEMA_VERSION;
        context.protocol_major = HARDENING_PROTOCOL_MAJOR;
        context.build_id = "build-1".to_owned();
        context.payload_sha256 = vec![0x11; 32];
        context.processor_sha256 = vec![0x12; 32];
        context.profile_config_sha256 = vec![0x13; 32];
        context.vm_schema_version = 1;
        context.device_identity_spki_sha256 = vec![0x14; 32];
        context.caller_uid = AID_KEYSTORE;
        context.security_level = "TEE".to_owned();
        context.runtime_epoch = 1;
        context.purpose = HARDENING_PURPOSE_FUNCTIONAL;
        context.route_id = HARDENING_ATTESTATION_KEY_IMPORT_ROUTE;
        context.stage_id = HARDENING_INITIAL_STAGE;
        context.request_sha256 = vec![0x15; 32];
        context.response_sha256 = vec![0x16; 32];
        context.attestation_challenge_sha256 = vec![0x17; 32];
        context.attestation_key_spki_sha256 = vec![0x18; 32];
        context.idempotency_key = "apply-1".to_owned();
        let expected = hardening_context_digest(&context).unwrap();

        let mut changed_values = Vec::new();
        let mut changed = context.clone();
        changed.build_id = "build-2".to_owned();
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.caller_uid += 1;
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.security_level = "StrongBox".to_owned();
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.runtime_epoch += 1;
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.purpose += 1;
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.route_id += 1;
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.stage_id += 1;
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.request_sha256[0] ^= 1;
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.response_sha256[0] ^= 1;
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.attestation_challenge_sha256[0] ^= 1;
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.wrapping_key_id = "01234567-89ab-4cde-8fab-0123456789ab".to_owned();
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.latent_binding = vec![0x19; HARDENING_LATENT_BINDING_BYTES];
        changed_values.push(changed);
        let mut changed = context.clone();
        changed.recovery_selector = vec![0x1a; HARDENING_RECOVERY_SELECTOR_BYTES];
        changed_values.push(changed);
        let mut changed = context;
        changed.attestation_key_spki_sha256[0] ^= 1;
        changed_values.push(changed);

        for changed in changed_values {
            assert_ne!(hardening_context_digest(&changed).unwrap(), expected);
        }
    }

    #[test]
    fn hardening_functional_apply_stage_is_fixed() {
        assert!(is_functional_apply_stage(
            HARDENING_PURPOSE_FUNCTIONAL,
            HARDENING_ATTESTATION_KEY_IMPORT_ROUTE,
            HARDENING_INITIAL_STAGE,
            &[],
            &[],
            &[],
        ));
        assert!(is_functional_apply_stage(
            HARDENING_PURPOSE_FUNCTIONAL,
            HARDENING_PROCESSED_REPLY_ROUTE,
            HARDENING_INITIAL_STAGE,
            &[],
            &[],
            &[],
        ));
        assert!(!is_functional_apply_stage(2, 1, 0, &[], &[], &[]));
        assert!(!is_functional_apply_stage(1, 3, 0, &[], &[], &[]));
        assert!(!is_functional_apply_stage(1, 1, 1, &[], &[], &[]));
        assert!(!is_functional_apply_stage(1, 1, 0, &[1], &[], &[]));
        assert!(!is_functional_apply_stage(1, 1, 0, &[], &[1], &[]));
        assert!(!is_functional_apply_stage(1, 1, 0, &[], &[], &[1]));
    }

    #[test]
    fn hardening_protected_stage_accepts_only_the_fixed_tuple_shape() {
        let predecessor = [0x21; 32];
        let voucher = [0x22; 32];
        let latent_binding = [0x23; HARDENING_LATENT_BINDING_BYTES];
        assert!(is_protected_bundle_stage(
            HARDENING_PURPOSE_PROTECTED,
            HARDENING_PROTECTED_ROUTE,
            HARDENING_PROTECTED_INITIAL_STAGE,
            &[],
            &[],
            &latent_binding,
        ));
        assert!(matches!(
            hardening_stage_kind(
                1,
                HARDENING_PURPOSE_PROTECTED,
                HARDENING_PROTECTED_ROUTE,
                HARDENING_PROTECTED_INITIAL_STAGE,
                &[],
                &[],
                &latent_binding,
            ),
            Ok(HardeningStageKind::ProtectedBundle)
        ));
        for stage_id in 2..=HARDENING_PROTECTED_FINAL_STAGE {
            assert!(is_protected_bundle_stage(
                HARDENING_PURPOSE_PROTECTED,
                HARDENING_PROTECTED_ROUTE,
                stage_id,
                &predecessor,
                &voucher,
                &latent_binding,
            ));
        }
        assert!(!is_protected_bundle_stage(
            HARDENING_PURPOSE_PROTECTED,
            2,
            HARDENING_PROTECTED_INITIAL_STAGE,
            &[],
            &[],
            &latent_binding,
        ));
        assert!(!is_protected_bundle_stage(
            HARDENING_PURPOSE_PROTECTED,
            HARDENING_PROTECTED_ROUTE,
            0,
            &[],
            &[],
            &latent_binding,
        ));
        assert!(!is_protected_bundle_stage(
            HARDENING_PURPOSE_PROTECTED,
            HARDENING_PROTECTED_ROUTE,
            HARDENING_PROTECTED_FINAL_STAGE + 1,
            &predecessor,
            &voucher,
            &latent_binding,
        ));
        assert!(!is_protected_bundle_stage(
            HARDENING_PURPOSE_PROTECTED,
            HARDENING_PROTECTED_ROUTE,
            HARDENING_PROTECTED_INITIAL_STAGE,
            &predecessor,
            &voucher,
            &latent_binding,
        ));
        assert!(!is_protected_bundle_stage(
            HARDENING_PURPOSE_PROTECTED,
            HARDENING_PROTECTED_ROUTE,
            2,
            &[],
            &voucher,
            &latent_binding,
        ));
        assert!(!is_protected_bundle_stage(
            HARDENING_PURPOSE_PROTECTED,
            HARDENING_PROTECTED_ROUTE,
            2,
            &predecessor,
            &[],
            &latent_binding,
        ));
        assert!(!is_protected_bundle_stage(
            HARDENING_PURPOSE_PROTECTED,
            HARDENING_PROTECTED_ROUTE,
            HARDENING_PROTECTED_INITIAL_STAGE,
            &[],
            &[],
            &latent_binding[..HARDENING_LATENT_BINDING_BYTES - 1],
        ));
        assert!(!is_protected_bundle_stage(
            HARDENING_PURPOSE_PROTECTED,
            HARDENING_PROTECTED_ROUTE,
            HARDENING_PROTECTED_INITIAL_STAGE,
            &[],
            &[],
            &[0; HARDENING_LATENT_BINDING_BYTES],
        ));
        assert!(hardening_stage_kind(
            0,
            HARDENING_PURPOSE_PROTECTED,
            HARDENING_PROTECTED_ROUTE,
            HARDENING_PROTECTED_INITIAL_STAGE,
            &[],
            &[],
            &latent_binding,
        )
        .is_err());
    }

    #[test]
    fn hardening_crypto_suite_matches_backend_golden_vector() {
        let transcript = [0x33; 32];
        let server_nonce = [0x44; 32];
        let capability = [0x22; 32];
        let transition = [0x55; 32];
        let binding = HardeningGrantBinding {
            build_id: "release-vector-1",
            session_id: "hs_ffeeddccbbaa99887766554433221100",
            grant_id: "hgr_00112233445566778899aabbccddeeff",
            grant_generation: 7,
            crypto_namespace: HardeningCryptoNamespace::Release,
            server_nonce: &server_nonce,
            transcript_sha256: &transcript,
            policy_epoch: 42,
        };
        let derivation = software_capability_derivation(
            &capability,
            HardeningCryptoNamespace::Release,
            &transcript,
        )
        .unwrap();
        assert_eq!(
            derivation.as_slice(),
            decode_hex("6e9de33fe30d2d942066b38dc0fe8938e455ea8884d7c28f4660e4cd5e626dd5")
        );
        let (outer, runtime, apply) = derive_hardening_keys(&derivation, &binding).unwrap();
        assert_eq!(
            outer.as_slice(),
            decode_hex("d5d5695d82c460b0f7d7a5b1c1d4d473437e308bf91ec650a50ae646c2a61c83")
        );
        assert_eq!(
            runtime.as_slice(),
            decode_hex("7bad52693777790e93988db870384820b87202852b74aa6f1b7f7c6c939b6d27")
        );
        assert_eq!(
            apply.as_slice(),
            decode_hex("242ee63ac1307ef755ff6a2c487af61199a54a557bef5adea7dcd94379749e2f")
        );
        let proof = hardening_consume_proof(&runtime, &binding, &transition).unwrap();
        assert_eq!(
            proof.as_slice(),
            decode_hex("6de7a4366f76218541b8e91a52f2f29dfa280b28a8910e3a92fdae4bac8e1e78")
        );

        let sealed = decode_hex(
            "000000016666666666666666666666668743cd9072f0e1d3f5ff4d3820210eeccf78bbf75c58817ac16da351109695",
        );
        let plaintext = open_hardening_payload(&outer, &binding, &sealed).unwrap();
        assert_eq!(&*plaintext, b"bounded payload");
        let descriptor = golden_apply_descriptor();
        let descriptor_sha256 = hardening_apply_descriptor_digest(
            &descriptor,
            hardening_apply_identity(
                1,
                HARDENING_PURPOSE_FUNCTIONAL,
                HARDENING_ATTESTATION_KEY_IMPORT_ROUTE,
                HARDENING_INITIAL_STAGE,
            ),
        )
        .unwrap();
        assert_eq!(
            descriptor_sha256.as_slice(),
            decode_hex("ee871817863376bb5061de95cdf33250a99e53ad2c726944479b600ed2d552a2")
        );
        let authorization = hardening_apply_authorization(
            &apply,
            &binding,
            &transition,
            &descriptor_sha256,
            &sha256(&[0x66; 32]),
            1_800_000_000_000,
        )
        .unwrap();
        assert_eq!(
            authorization.as_slice(),
            decode_hex("51708064229dd913fcdc3339a0bf7bd8fcfecb8fd4b13f3fde48db5669c9517c")
        );
    }

    #[test]
    fn hardening_namespace_and_payload_authentication_are_bound() {
        let transcript = [0x33; 32];
        let server_nonce = [0x44; 32];
        let capability = [0x22; 32];
        let release = software_capability_derivation(
            &capability,
            HardeningCryptoNamespace::Release,
            &transcript,
        )
        .unwrap();
        let debug = software_capability_derivation(
            &capability,
            HardeningCryptoNamespace::Debug,
            &transcript,
        )
        .unwrap();
        assert_ne!(&*release, &*debug);

        let binding = HardeningGrantBinding {
            build_id: "release-vector-1",
            session_id: "hs_ffeeddccbbaa99887766554433221100",
            grant_id: "hgr_00112233445566778899aabbccddeeff",
            grant_generation: 7,
            crypto_namespace: HardeningCryptoNamespace::Release,
            server_nonce: &server_nonce,
            transcript_sha256: &transcript,
            policy_epoch: 42,
        };
        let (outer, _, _) = derive_hardening_keys(&release, &binding).unwrap();
        let mut sealed = decode_hex(
            "000000016666666666666666666666668743cd9072f0e1d3f5ff4d3820210eeccf78bbf75c58817ac16da351109695",
        );
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open_hardening_payload(&outer, &binding, &sealed).is_err());
    }

    #[test]
    fn hardening_apply_authorization_binds_each_input() {
        let transcript = [0x33; 32];
        let server_nonce = [0x44; 32];
        let action = [0x55; 32];
        let program = hardening_apply_descriptor_digest(
            &golden_apply_descriptor(),
            hardening_apply_identity(
                1,
                HARDENING_PURPOSE_FUNCTIONAL,
                HARDENING_ATTESTATION_KEY_IMPORT_ROUTE,
                HARDENING_INITIAL_STAGE,
            ),
        )
        .unwrap();
        let receipt = sha256(&[0x66; 32]);
        let binding = HardeningGrantBinding {
            build_id: "release-vector-1",
            session_id: "hs_ffeeddccbbaa99887766554433221100",
            grant_id: "hgr_00112233445566778899aabbccddeeff",
            grant_generation: 7,
            crypto_namespace: HardeningCryptoNamespace::Release,
            server_nonce: &server_nonce,
            transcript_sha256: &transcript,
            policy_epoch: 42,
        };
        let derivation = software_capability_derivation(
            &[0x22; 32],
            HardeningCryptoNamespace::Release,
            &transcript,
        )
        .unwrap();
        let (_, _, apply) = derive_hardening_keys(&derivation, &binding).unwrap();
        let expected = hardening_apply_authorization(
            &apply,
            &binding,
            &action,
            &program,
            &receipt,
            1_800_000_000_000,
        )
        .unwrap();

        let mut changed = transcript;
        changed[0] ^= 1;
        let changed_binding = HardeningGrantBinding { transcript_sha256: &changed, ..binding };
        assert_ne!(
            hardening_apply_authorization(
                &apply,
                &changed_binding,
                &action,
                &program,
                &receipt,
                1_800_000_000_000,
            )
            .unwrap()
            .as_slice(),
            expected.as_slice()
        );
        let mut changed = action;
        changed[0] ^= 1;
        assert_ne!(
            hardening_apply_authorization(
                &apply,
                &binding,
                &changed,
                &program,
                &receipt,
                1_800_000_000_000,
            )
            .unwrap()
            .as_slice(),
            expected.as_slice()
        );
        let mut changed = program;
        changed[0] ^= 1;
        assert_ne!(
            hardening_apply_authorization(
                &apply,
                &binding,
                &action,
                &changed,
                &receipt,
                1_800_000_000_000,
            )
            .unwrap()
            .as_slice(),
            expected.as_slice()
        );
        let mut changed = receipt;
        changed[0] ^= 1;
        assert_ne!(
            hardening_apply_authorization(
                &apply,
                &binding,
                &action,
                &program,
                &changed,
                1_800_000_000_000,
            )
            .unwrap()
            .as_slice(),
            expected.as_slice()
        );
        let changed_binding = HardeningGrantBinding { policy_epoch: 43, ..binding };
        assert_ne!(
            hardening_apply_authorization(
                &apply,
                &changed_binding,
                &action,
                &program,
                &receipt,
                1_800_000_000_000,
            )
            .unwrap()
            .as_slice(),
            expected.as_slice()
        );
        assert_ne!(
            hardening_apply_authorization(
                &apply,
                &binding,
                &action,
                &program,
                &receipt,
                1_800_000_000_001,
            )
            .unwrap()
            .as_slice(),
            expected.as_slice()
        );

        let debug_binding =
            HardeningGrantBinding { crypto_namespace: HardeningCryptoNamespace::Debug, ..binding };
        let debug_derivation = software_capability_derivation(
            &[0x22; 32],
            HardeningCryptoNamespace::Debug,
            &transcript,
        )
        .unwrap();
        let (_, _, debug_apply) = derive_hardening_keys(&debug_derivation, &debug_binding).unwrap();
        assert_ne!(
            hardening_apply_authorization(
                &debug_apply,
                &debug_binding,
                &action,
                &program,
                &receipt,
                1_800_000_000_000,
            )
            .unwrap()
            .as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn hardening_payload_envelope_accepts_the_exact_plaintext_limit() {
        let mut sealed = vec![0u8; MAX_HARDENING_SEALED_PAYLOAD_BYTES];
        sealed[..4].copy_from_slice(&HARDENING_SCHEMA_VERSION.to_be_bytes());
        let (nonce, encrypted) = parse_hardening_payload_envelope(&sealed).unwrap();
        assert_eq!(nonce.len(), AES_GCM_NONCE_BYTES);
        assert_eq!(encrypted.len(), MAX_HARDENING_PLAINTEXT_BYTES + AES_GCM_TAG_BYTES);
    }

    #[test]
    fn hardening_payload_envelope_rejects_one_byte_over_the_limit() {
        let mut sealed = vec![0u8; MAX_HARDENING_SEALED_PAYLOAD_BYTES + 1];
        sealed[..4].copy_from_slice(&HARDENING_SCHEMA_VERSION.to_be_bytes());
        assert!(parse_hardening_payload_envelope(&sealed).is_err());
    }

    #[test]
    fn hardening_empty_plaintext_is_valid() {
        let transcript = [0x33; 32];
        let server_nonce = [0x44; 32];
        let capability = [0x22; 32];
        let binding = HardeningGrantBinding {
            build_id: "release-vector-1",
            session_id: "hs_ffeeddccbbaa99887766554433221100",
            grant_id: "hgr_00112233445566778899aabbccddeeff",
            grant_generation: 7,
            crypto_namespace: HardeningCryptoNamespace::Release,
            server_nonce: &server_nonce,
            transcript_sha256: &transcript,
            policy_epoch: 42,
        };
        let derivation = software_capability_derivation(
            &capability,
            HardeningCryptoNamespace::Release,
            &transcript,
        )
        .unwrap();
        let (outer, _, _) = derive_hardening_keys(&derivation, &binding).unwrap();
        let sealed = seal_empty_hardening_payload_for_test(&outer, &binding);
        assert_eq!(sealed.len(), HARDENING_PAYLOAD_HEADER_BYTES + AES_GCM_TAG_BYTES);
        assert!(open_hardening_payload(&outer, &binding, &sealed).unwrap().is_empty());
    }

    #[test]
    fn hardening_apply_descriptor_matches_backend_and_rejects_invalid_fields() {
        let descriptor = golden_apply_descriptor();
        assert_eq!(
            hardening_apply_descriptor_digest(
                &descriptor,
                hardening_apply_identity(
                    1,
                    HARDENING_PURPOSE_FUNCTIONAL,
                    HARDENING_ATTESTATION_KEY_IMPORT_ROUTE,
                    HARDENING_INITIAL_STAGE,
                ),
            )
            .unwrap()
            .as_slice(),
            decode_hex("ee871817863376bb5061de95cdf33250a99e53ad2c726944479b600ed2d552a2")
        );
        let processed_reply_descriptor =
            processed_reply_apply_descriptor([0xa6, 0xab, 0x53, 0x87, 0x5d, 0x63, 0xc5, 0x56]);
        assert_eq!(
            hardening_apply_descriptor_digest(
                &processed_reply_descriptor,
                hardening_apply_identity(
                    1,
                    HARDENING_PURPOSE_FUNCTIONAL,
                    HARDENING_PROCESSED_REPLY_ROUTE,
                    HARDENING_INITIAL_STAGE,
                ),
            )
            .unwrap()
            .as_slice(),
            decode_hex("958d6b6e6bd459b4af656fb816c53634d5ea71bcf612b6f822be844d2b74bd08")
        );

        let mut wrong_instruction_count = descriptor.clone();
        wrong_instruction_count[20..24].copy_from_slice(&1u32.to_be_bytes());
        assert!(hardening_apply_descriptor_digest(
            &wrong_instruction_count,
            hardening_apply_identity(
                1,
                HARDENING_PURPOSE_FUNCTIONAL,
                HARDENING_ATTESTATION_KEY_IMPORT_ROUTE,
                HARDENING_INITIAL_STAGE,
            ),
        )
        .is_err());
        assert!(hardening_apply_descriptor_digest(
            &processed_reply_descriptor,
            hardening_apply_identity(
                1,
                HARDENING_PURPOSE_FUNCTIONAL,
                HARDENING_ATTESTATION_KEY_IMPORT_ROUTE,
                HARDENING_INITIAL_STAGE,
            ),
        )
        .is_err());
        assert!(hardening_apply_descriptor_digest(
            &descriptor,
            hardening_apply_identity(
                1,
                HARDENING_PURPOSE_FUNCTIONAL,
                HARDENING_PROCESSED_REPLY_ROUTE,
                HARDENING_INITIAL_STAGE,
            ),
        )
        .is_err());

        let mut invalid_values = Vec::new();
        invalid_values.push((descriptor[..HARDENING_APPLY_DESCRIPTOR_BYTES - 1].to_vec(), 1));
        let mut invalid = descriptor.clone();
        invalid.push(0);
        invalid_values.push((invalid, 1));
        let mut invalid = descriptor.clone();
        invalid[3] = 2;
        invalid_values.push((invalid, 1));
        invalid_values.push((descriptor.clone(), 2));
        let mut invalid = descriptor.clone();
        invalid[7] = 2;
        invalid_values.push((invalid, 1));
        let mut invalid = descriptor.clone();
        invalid[11] = 2;
        invalid_values.push((invalid, 1));
        let mut invalid = descriptor.clone();
        invalid[15] = 2;
        invalid_values.push((invalid, 1));
        let mut invalid = descriptor.clone();
        invalid[19] = 1;
        invalid_values.push((invalid, 1));
        let mut invalid = descriptor.clone();
        invalid[20..24].fill(0);
        invalid_values.push((invalid, 1));
        let mut invalid = descriptor.clone();
        invalid[20] = 1;
        invalid[21..24].fill(0);
        invalid_values.push((invalid, 1));
        let mut invalid = descriptor.clone();
        invalid[24] ^= 1;
        invalid_values.push((invalid, 1));
        let mut invalid = descriptor;
        invalid[32..40].fill(0);
        invalid_values.push((invalid, 1));

        for (invalid, vm_schema_version) in invalid_values {
            assert!(hardening_apply_descriptor_digest(
                &invalid,
                hardening_apply_identity(
                    vm_schema_version,
                    HARDENING_PURPOSE_FUNCTIONAL,
                    HARDENING_ATTESTATION_KEY_IMPORT_ROUTE,
                    HARDENING_INITIAL_STAGE,
                ),
            )
            .is_err());
        }
    }

    #[test]
    fn hardening_apply_authorization_comparison_rejects_changed_tags() {
        let expected =
            decode_hex("51708064229dd913fcdc3339a0bf7bd8fcfecb8fd4b13f3fde48db5669c9517c");
        assert!(hardening_apply_authorization_matches(&expected, &expected));
        let mut changed = expected.clone();
        changed[0] ^= 1;
        assert!(!hardening_apply_authorization_matches(&changed, &expected));
        assert!(!hardening_apply_authorization_matches(&expected[..31], &expected));
    }

    #[test]
    fn hardening_verification_proof_requires_exact_nonzero_size() {
        assert!(validate_hardening_verification_proof(&[0x55; HARDENING_VERIFICATION_PROOF_BYTES])
            .is_ok());
        assert!(validate_hardening_verification_proof(
            &[0x55; HARDENING_VERIFICATION_PROOF_BYTES - 1]
        )
        .is_err());
        assert!(validate_hardening_verification_proof(
            &[0x55; HARDENING_VERIFICATION_PROOF_BYTES + 1]
        )
        .is_err());
        assert!(validate_hardening_verification_proof(&[0; HARDENING_VERIFICATION_PROOF_BYTES])
            .is_err());
    }

    #[test]
    fn hardening_verification_proof_passes_changed_bytes_unchanged() {
        let authorization_tag = [0x44; HARDENING_AUTHORIZATION_TAG_BYTES];
        let mut verification_proof = vec![0x55; HARDENING_VERIFICATION_PROOF_BYTES];
        verification_proof[17] ^= 0x80;
        let expected = verification_proof.clone();

        let returned = verify_hardening_authorization_and_take_proof(
            &authorization_tag,
            &authorization_tag,
            &mut verification_proof,
        )
        .unwrap();

        assert_eq!(returned, expected);
        assert!(verification_proof.is_empty());
    }

    #[test]
    fn hardening_authorization_failure_does_not_release_proof() {
        let expected_tag = [0x44; HARDENING_AUTHORIZATION_TAG_BYTES];
        let mut actual_tag = expected_tag;
        actual_tag[0] ^= 1;
        let mut verification_proof = vec![0x55; HARDENING_VERIFICATION_PROOF_BYTES];
        let original = verification_proof.clone();

        assert!(verify_hardening_authorization_and_take_proof(
            &actual_tag,
            &expected_tag,
            &mut verification_proof,
        )
        .is_err());
        assert_eq!(verification_proof, original);
    }

    #[test]
    fn hardening_opaque_result_extension_requires_exact_nonzero_fixed_shape() {
        let extension = vec![0x5a; HARDENING_OPAQUE_RESULT_EXTENSION_BYTES];
        let mut accepted = extension.clone();
        assert_eq!(take_hardening_opaque_result_extension(&mut accepted).unwrap(), extension);
        assert!(accepted.is_empty());

        let mut short = vec![0x5a; HARDENING_OPAQUE_RESULT_EXTENSION_BYTES - 1];
        assert!(take_hardening_opaque_result_extension(&mut short).is_err());
        assert_eq!(short.len(), HARDENING_OPAQUE_RESULT_EXTENSION_BYTES - 1);

        let mut long = vec![0x5a; HARDENING_OPAQUE_RESULT_EXTENSION_BYTES + 1];
        assert!(take_hardening_opaque_result_extension(&mut long).is_err());
        assert_eq!(long.len(), HARDENING_OPAQUE_RESULT_EXTENSION_BYTES + 1);

        let mut zero = vec![0; HARDENING_OPAQUE_RESULT_EXTENSION_BYTES];
        assert!(take_hardening_opaque_result_extension(&mut zero).is_err());
        assert_eq!(zero.len(), HARDENING_OPAQUE_RESULT_EXTENSION_BYTES);
    }

    #[test]
    fn hardening_result_enforces_exact_functional_bounds_and_expiry() {
        let now_ms = 1_800_000_000_000;
        let runtime_payload = golden_apply_descriptor();
        let authorization_tag = [0x22; HARDENING_AUTHORIZATION_TAG_BYTES];
        let verification_proof = [0x44; HARDENING_VERIFICATION_PROOF_BYTES];
        let transcript_sha256 = [0x33; HARDENING_TRANSCRIPT_BYTES];
        let identity = hardening_apply_identity(
            1,
            HARDENING_PURPOSE_FUNCTIONAL,
            HARDENING_ATTESTATION_KEY_IMPORT_ROUTE,
            HARDENING_INITIAL_STAGE,
        );
        assert!(validate_hardening_result(
            &runtime_payload,
            identity,
            &authorization_tag,
            &verification_proof,
            &transcript_sha256,
            now_ms + HARDENING_MAX_SERVER_LIFETIME_MS,
            now_ms,
        )
        .is_ok());
        assert!(validate_hardening_result(
            &runtime_payload[..HARDENING_APPLY_DESCRIPTOR_BYTES - 1],
            identity,
            &authorization_tag,
            &verification_proof,
            &transcript_sha256,
            now_ms + 1,
            now_ms,
        )
        .is_err());
        let mut oversized_runtime_payload = runtime_payload.clone();
        oversized_runtime_payload.push(0);
        assert!(validate_hardening_result(
            &oversized_runtime_payload,
            identity,
            &authorization_tag,
            &verification_proof,
            &transcript_sha256,
            now_ms + 1,
            now_ms,
        )
        .is_err());
        assert!(validate_hardening_result(
            &runtime_payload,
            identity,
            &[0x22; HARDENING_AUTHORIZATION_TAG_BYTES - 1],
            &verification_proof,
            &transcript_sha256,
            now_ms + 1,
            now_ms,
        )
        .is_err());
        assert!(validate_hardening_result(
            &runtime_payload,
            identity,
            &[0x22; HARDENING_AUTHORIZATION_TAG_BYTES + 1],
            &verification_proof,
            &transcript_sha256,
            now_ms + 1,
            now_ms,
        )
        .is_err());
        assert!(validate_hardening_result(
            &runtime_payload,
            identity,
            &[0; HARDENING_AUTHORIZATION_TAG_BYTES],
            &verification_proof,
            &transcript_sha256,
            now_ms + 1,
            now_ms,
        )
        .is_err());
        assert!(validate_hardening_result(
            &runtime_payload,
            identity,
            &authorization_tag,
            &verification_proof,
            &[0x33; HARDENING_TRANSCRIPT_BYTES - 1],
            now_ms + 1,
            now_ms,
        )
        .is_err());
        assert!(validate_hardening_result(
            &runtime_payload,
            identity,
            &authorization_tag,
            &verification_proof,
            &[0; HARDENING_TRANSCRIPT_BYTES],
            now_ms + 1,
            now_ms,
        )
        .is_err());
        assert!(validate_hardening_result(
            &runtime_payload,
            identity,
            &authorization_tag,
            &verification_proof,
            &transcript_sha256,
            now_ms,
            now_ms,
        )
        .is_err());
        assert!(validate_hardening_result(
            &runtime_payload,
            identity,
            &authorization_tag,
            &verification_proof,
            &transcript_sha256,
            now_ms + HARDENING_MAX_SERVER_LIFETIME_MS + 1,
            now_ms,
        )
        .is_err());
    }

    #[test]
    fn hardening_protected_bundle_is_opaque_and_bounded() {
        let now_ms = 1_800_000_000_000;
        let bundle = vec![0x7a; HARDENING_MAX_PROTECTED_BUNDLE_BYTES];
        let receipt = [0x51; 32];
        let voucher = [0x52; 32];
        let transcript_sha256 = [0x53; HARDENING_TRANSCRIPT_BYTES];
        assert!(validate_hardening_protected_result(
            &bundle,
            &receipt,
            &voucher,
            &transcript_sha256,
            now_ms + HARDENING_MAX_SERVER_LIFETIME_MS,
            now_ms,
        )
        .is_ok());
        assert!(validate_hardening_protected_bundle(&[]).is_err());
        assert!(validate_hardening_protected_bundle(&vec![
            0x7a;
            HARDENING_MAX_PROTECTED_BUNDLE_BYTES + 1
        ],)
        .is_err());
        assert!(validate_hardening_protected_result(
            &bundle,
            &[],
            &voucher,
            &transcript_sha256,
            now_ms + 1,
            now_ms,
        )
        .is_err());
        assert!(validate_hardening_protected_result(
            &bundle,
            &receipt,
            &voucher,
            &[0; HARDENING_TRANSCRIPT_BYTES],
            now_ms + 1,
            now_ms,
        )
        .is_err());
        let mut proof = vec![0x54; HARDENING_VERIFICATION_PROOF_BYTES];
        assert_eq!(
            take_hardening_protected_proof(&mut proof).unwrap().len(),
            HARDENING_VERIFICATION_PROOF_BYTES
        );
        assert!(proof.is_empty());
        let mut zero_proof = vec![0; HARDENING_VERIFICATION_PROOF_BYTES];
        assert!(take_hardening_protected_proof(&mut zero_proof).is_err());
        assert_eq!(zero_proof.len(), HARDENING_VERIFICATION_PROOF_BYTES);
    }

    #[test]
    fn hardening_redeem_wire_accepts_empty_receipt() {
        let now_ms = 1_800_000_000_000;
        let expires_at_ms = now_ms + 30_000;
        let transcript_sha256 = [0x31; 32];
        let namespace = protobuf::EnumOrUnknown::new(
            HardeningCryptoNamespaceV1::HARDENING_CRYPTO_NAMESPACE_RELEASE,
        );
        let mut challenge = HardeningChallengeV1::new();
        challenge.schema_version = HARDENING_SCHEMA_VERSION;
        challenge.protocol_major = HARDENING_PROTOCOL_MAJOR;
        challenge.protocol_minor = 0;
        challenge.session_id = "hs_wire_regression".to_owned();
        challenge.grant_id = "hgr_wire_regression".to_owned();
        challenge.server_nonce = vec![0x11; 32];
        challenge.wrapping_attestation_challenge = vec![0x12; 32];
        challenge.server_expires_at_ms = expires_at_ms;
        challenge.policy_epoch = 7;
        challenge.grant_generation = 1;
        challenge.crypto_namespace = namespace;
        challenge.crypto_suite = HARDENING_CRYPTO_SUITE_V1;

        let mut grant = HardeningGrantV1::new();
        grant.schema_version = HARDENING_SCHEMA_VERSION;
        grant.protocol_major = HARDENING_PROTOCOL_MAJOR;
        grant.protocol_minor = challenge.protocol_minor;
        grant.session_id = challenge.session_id.clone();
        grant.grant_id = challenge.grant_id.clone();
        grant.secure_key_wrapper = vec![0x21];
        grant.sealed_payload = vec![0; HARDENING_PAYLOAD_HEADER_BYTES + AES_GCM_TAG_BYTES];
        grant.sealed_payload[..4].copy_from_slice(&HARDENING_SCHEMA_VERSION.to_be_bytes());
        grant.receipt = Vec::new();
        grant.receipt_metadata = vec![0x22];
        grant.server_expires_at_ms = expires_at_ms;
        grant.policy_epoch = challenge.policy_epoch;
        grant.transcript_sha256 = transcript_sha256.to_vec();
        grant.grant_generation = challenge.grant_generation;
        grant.crypto_namespace = namespace;
        grant.crypto_suite = HARDENING_CRYPTO_SUITE_V1;

        assert!(validate_hardening_grant(&grant, &challenge, &transcript_sha256, now_ms,).is_ok());
        grant.receipt = vec![0; HARDENING_MAX_TOKEN_BYTES + 1];
        assert!(validate_hardening_grant(&grant, &challenge, &transcript_sha256, now_ms,).is_err());

        grant.receipt = Vec::new();
        let mut transition = GrantTransitionV1::new();
        transition.schema_version = HARDENING_SCHEMA_VERSION;
        transition.protocol_major = HARDENING_PROTOCOL_MAJOR;
        transition.protocol_minor = grant.protocol_minor;
        transition.session_id = grant.session_id.clone();
        transition.grant_id = grant.grant_id.clone();
        transition.next_voucher = vec![0x41];
        transition.server_expires_at_ms = grant.server_expires_at_ms;
        transition.policy_epoch = grant.policy_epoch;
        transition.crypto_namespace = namespace;
        transition.crypto_suite = HARDENING_CRYPTO_SUITE_V1;
        assert!(validate_hardening_transition(&transition, &grant, now_ms).is_err());
        transition.receipt = vec![0x42];
        transition.authorized_payload = vec![0x43; HARDENING_AUTHORIZATION_TAG_BYTES];
        transition.opaque_continuation = vec![0x44; HARDENING_VERIFICATION_PROOF_BYTES];
        transition.auxiliary_capsule = vec![0x45; HARDENING_OPAQUE_RESULT_EXTENSION_BYTES];
        assert!(validate_hardening_transition(&transition, &grant, now_ms).is_ok());
        transition.auxiliary_capsule = vec![0x45; HARDENING_OPAQUE_RESULT_EXTENSION_BYTES - 1];
        assert!(validate_hardening_transition(&transition, &grant, now_ms).is_ok());
        assert!(take_hardening_opaque_result_extension(&mut transition.auxiliary_capsule).is_err());
        transition.auxiliary_capsule = vec![0; HARDENING_OPAQUE_RESULT_EXTENSION_BYTES];
        assert!(validate_hardening_transition(&transition, &grant, now_ms).is_ok());
        assert!(take_hardening_opaque_result_extension(&mut transition.auxiliary_capsule).is_err());
        transition.auxiliary_capsule = vec![0x45; HARDENING_OPAQUE_RESULT_EXTENSION_BYTES];
        transition.authorized_payload = vec![0x43; HARDENING_AUTHORIZATION_TAG_BYTES - 1];
        assert!(validate_hardening_transition(&transition, &grant, now_ms).is_err());
        transition.authorized_payload = vec![0x43; HARDENING_AUTHORIZATION_TAG_BYTES + 1];
        assert!(validate_hardening_transition(&transition, &grant, now_ms).is_err());
        transition.authorized_payload = vec![0; HARDENING_AUTHORIZATION_TAG_BYTES];
        assert!(validate_hardening_transition(&transition, &grant, now_ms).is_err());

        transition.authorized_payload.clear();
        transition.opaque_continuation = vec![0x44; HARDENING_VERIFICATION_PROOF_BYTES];
        transition.auxiliary_capsule.clear();
        assert!(validate_hardening_protected_transition(&transition, &grant, now_ms).is_ok());
        assert!(validate_hardening_transition_for_stage(
            &transition,
            &grant,
            HardeningStageKind::ProtectedBundle,
            now_ms,
        )
        .is_ok());
        transition.opaque_continuation.clear();
        assert!(validate_hardening_protected_transition(&transition, &grant, now_ms).is_err());
        transition.opaque_continuation = vec![0x44; HARDENING_VERIFICATION_PROOF_BYTES];
        transition.auxiliary_capsule = vec![0x45; HARDENING_OPAQUE_RESULT_EXTENSION_BYTES];
        assert!(validate_hardening_protected_transition(&transition, &grant, now_ms).is_err());
    }

    #[test]
    fn hardening_rpc_budget_preserves_retry_and_expiry_margin() {
        let window = HardeningRpcWindow::Grant { expires_at_ms: 3_000 };
        assert_eq!(
            hardening_rpc_attempt_timeout(window, 0, 0).unwrap(),
            Duration::from_millis(2_000)
        );
        assert_eq!(hardening_rpc_retry_delay(window, 2_000).unwrap(), Duration::from_millis(250));
        assert_eq!(
            hardening_rpc_attempt_timeout(window, 2_250, 1).unwrap(),
            Duration::from_millis(250)
        );
        assert!(hardening_rpc_attempt_timeout(window, 2_251, 1).is_err());

        assert_eq!(
            hardening_rpc_attempt_timeout(HardeningRpcWindow::Begin, i64::MAX, 0).unwrap(),
            Duration::from_millis(HARDENING_BEGIN_RPC_TIMEOUT_MS as u64)
        );
        assert_eq!(
            hardening_rpc_attempt_timeout(HardeningRpcWindow::Completion, i64::MAX, 0).unwrap(),
            Duration::from_millis(HARDENING_BEGIN_RPC_TIMEOUT_MS as u64)
        );
    }

    #[test]
    fn hardening_rpc_retry_delay_clamps_to_remaining_budget() {
        let window = HardeningRpcWindow::Grant { expires_at_ms: 2_000 };
        assert_eq!(hardening_rpc_retry_delay(window, 1_100).unwrap(), Duration::from_millis(150));
        assert!(hardening_rpc_retry_delay(window, 1_250).is_err());
    }

    #[test]
    fn hardening_pool_capacity_counts_ready_claimed_and_in_flight_keys() {
        assert_eq!(
            hardening_pool_live_count(HARDENING_POOL_CAPACITY, 0, false),
            Some(HARDENING_POOL_CAPACITY)
        );
        assert!(hardening_pool_can_prepare(HARDENING_POOL_CAPACITY - 1, 0));
        assert!(!hardening_pool_can_prepare(HARDENING_POOL_CAPACITY, 0));
        assert!(!hardening_pool_can_prepare(1, HARDENING_POOL_CAPACITY - 1));

        let mut ready = HARDENING_POOL_CAPACITY;
        let mut claimed = 0usize;
        for _ in 0..HARDENING_POOL_CAPACITY {
            ready -= 1;
            claimed += 1;
            assert_eq!(
                hardening_pool_live_count(ready, claimed, false),
                Some(HARDENING_POOL_CAPACITY)
            );
        }
        assert_eq!(ready, 0);
        assert_eq!(claimed, HARDENING_POOL_CAPACITY);
        assert!(!hardening_pool_can_prepare(ready, claimed));
    }

    #[test]
    fn hardening_pool_refill_opens_only_at_threshold_or_for_an_exact_retry() {
        assert!(!hardening_pool_should_start_refill(2, 0, false, false));
        assert!(hardening_pool_should_start_refill(1, 0, false, false));
        assert!(hardening_pool_should_start_refill(0, 0, false, false));
        assert!(!hardening_pool_should_start_refill(1, HARDENING_POOL_CAPACITY - 1, false, false,));
        assert!(hardening_pool_should_start_refill(HARDENING_POOL_CAPACITY - 1, 0, true, false,));
        assert!(!hardening_pool_should_start_refill(1, 0, false, true));
    }

    #[test]
    fn hardening_pool_waiters_enforce_fifo_and_timeout_to_fresh_fallback() {
        let mut state = HardeningWrappingPoolState::default();
        state.serving_waiter_ticket = 7;
        state.next_waiter_ticket = 11;
        state.cancelled_waiter_tickets.extend([8, 9]);
        assert!(hardening_pool_waiter_can_claim(&state, Some(7)));
        assert!(!hardening_pool_waiter_can_claim(&state, Some(10)));
        assert!(!hardening_pool_waiter_can_claim(&state, None));
        advance_hardening_pool_waiter(&mut state);
        assert_eq!(state.serving_waiter_ticket, 10);
        assert!(state.cancelled_waiter_tickets.is_empty());
        assert!(hardening_pool_waiter_can_claim(&state, Some(10)));
        let fallback: HardeningResult<Option<()>> = hardening_pool_timeout_fallback(&mut state, 10);
        assert!(matches!(fallback, Ok(None)));
        assert_eq!(state.serving_waiter_ticket, 11);
        assert!(hardening_pool_waiter_can_claim(&state, None));
        assert_eq!(HARDENING_POOL_FOREGROUND_WAIT_MS, 1_000);
        assert!(HARDENING_POOL_FOREGROUND_WAIT_MS < HARDENING_BEGIN_RPC_TIMEOUT_MS as u64);
    }

    #[test]
    fn hardening_pool_rpc_failures_have_fixed_dispositions() {
        assert!(HardeningRpcError::Status(Code::Cancelled).is_transient());
        assert_eq!(
            classify_pooled_begin_failure(HardeningRpcError::Status(Code::Unavailable)),
            PooledBeginFailureClass::Transient
        );
        assert_eq!(
            classify_pooled_begin_failure(HardeningRpcError::Status(Code::NotFound)),
            PooledBeginFailureClass::KeyRejected
        );
        assert_eq!(
            classify_pooled_begin_failure(HardeningRpcError::Status(Code::InvalidArgument)),
            PooledBeginFailureClass::KeyRejected
        );
        assert_eq!(
            classify_pooled_begin_failure(HardeningRpcError::Status(Code::FailedPrecondition)),
            PooledBeginFailureClass::KeyRejected
        );
        assert_eq!(
            classify_pooled_begin_failure(HardeningRpcError::Status(Code::PermissionDenied)),
            PooledBeginFailureClass::ScopeRejected
        );
        assert_eq!(
            classify_pooled_grant_failure(HardeningRpcError::Status(Code::Unavailable)),
            PooledGrantFailureClass::Transient
        );
        assert_eq!(
            classify_pooled_grant_failure(HardeningRpcError::Status(Code::NotFound)),
            PooledGrantFailureClass::KeyRejected
        );
        assert_eq!(
            classify_pooled_grant_failure(HardeningRpcError::Status(Code::FailedPrecondition)),
            PooledGrantFailureClass::KeyRejected
        );
        assert_eq!(
            classify_pooled_grant_failure(HardeningRpcError::Status(Code::PermissionDenied)),
            PooledGrantFailureClass::ScopeRejected
        );
        assert_eq!(
            classify_pooled_grant_failure(HardeningRpcError::Status(Code::InvalidArgument)),
            PooledGrantFailureClass::ScopeRejected
        );
        assert_eq!(
            classify_pool_prepare_rpc_failure(
                HardeningRpcError::Status(Code::ResourceExhausted),
                false,
            ),
            HardeningPoolPreparationError::RefillClosed
        );
        assert_eq!(
            classify_pool_prepare_rpc_failure(
                HardeningRpcError::Status(Code::FailedPrecondition),
                true,
            ),
            HardeningPoolPreparationError::CandidateRejected
        );
        assert_eq!(
            classify_pool_prepare_rpc_failure(
                HardeningRpcError::Status(Code::PermissionDenied),
                true,
            ),
            HardeningPoolPreparationError::ScopeRejected
        );
    }

    #[test]
    fn hardening_challenge_separates_fresh_and_pooled_wrapping_keys() {
        let now_ms = 1_800_000_000_000;
        let mut context = HardeningContextV1::new();
        context.protocol_minor = 4;
        let mut challenge = HardeningChallengeV1::new();
        challenge.schema_version = HARDENING_SCHEMA_VERSION;
        challenge.protocol_major = HARDENING_PROTOCOL_MAJOR;
        challenge.protocol_minor = context.protocol_minor;
        challenge.session_id = "hs_pool_mode".to_owned();
        challenge.grant_id = "hgr_pool_mode".to_owned();
        challenge.server_nonce = vec![0x11; 32];
        challenge.server_expires_at_ms = now_ms + 15_000;
        challenge.policy_epoch = 1;
        challenge.grant_generation = 1;
        challenge.crypto_namespace = protobuf::EnumOrUnknown::new(
            HardeningCryptoNamespaceV1::HARDENING_CRYPTO_NAMESPACE_RELEASE,
        );
        challenge.crypto_suite = HARDENING_CRYPTO_SUITE_V1;

        challenge.wrapping_attestation_challenge = vec![0x22; 32];
        assert!(validate_hardening_challenge(&challenge, &context, "", None, now_ms).is_ok());
        challenge.wrapping_key_id = "01234567-89ab-4cde-8fab-0123456789ab".to_owned();
        assert!(validate_hardening_challenge(&challenge, &context, "", None, now_ms).is_err());

        challenge.wrapping_attestation_challenge.clear();
        assert!(validate_hardening_challenge(
            &challenge,
            &context,
            "01234567-89ab-4cde-8fab-0123456789ab",
            None,
            now_ms,
        )
        .is_ok());
        challenge.wrapping_attestation_challenge.push(1);
        assert!(validate_hardening_challenge(
            &challenge,
            &context,
            "01234567-89ab-4cde-8fab-0123456789ab",
            None,
            now_ms,
        )
        .is_err());
    }

    #[test]
    fn hardening_recovery_scope_has_stable_kat_and_excludes_fresh_event_fields() {
        let mut context = HardeningContextV1::new();
        context.schema_version = HARDENING_SCHEMA_VERSION;
        context.protocol_major = HARDENING_PROTOCOL_MAJOR;
        context.protocol_minor = 4;
        context.build_id = "build-a".to_owned();
        context.payload_sha256 = vec![1; 32];
        context.processor_sha256 = vec![2; 32];
        context.profile_config_sha256 = vec![3; 32];
        context.vm_schema_version = 1;
        context.device_identity_spki_sha256 = vec![4; 32];
        context.caller_uid = AID_KEYSTORE;
        context.security_level = "TEE".to_owned();
        context.runtime_epoch = 7;
        context.purpose = HARDENING_PURPOSE_PROTECTED;
        context.route_id = HARDENING_PROTECTED_ROUTE;
        context.stage_id = HARDENING_PROTECTED_FINAL_STAGE;
        context.request_sha256 = vec![10; 32];
        context.response_sha256 = vec![11; 32];
        context.attestation_challenge_sha256 = vec![12; 32];
        context.attestation_key_spki_sha256 = vec![13; 32];
        context.previous_receipt = vec![5, 6];
        context.voucher = vec![7, 8];
        context.idempotency_key = "fresh-event-a".to_owned();
        context.wrapping_key_id = "wrapping-a".to_owned();
        context.latent_binding = vec![9; HARDENING_LATENT_BINDING_BYTES];
        let expected = [
            0x58, 0xd5, 0xc1, 0x35, 0x75, 0x6f, 0xba, 0xe4, 0x8e, 0xc8, 0x14, 0x04, 0xeb, 0xe7,
            0x9f, 0xd7, 0x26, 0xe0, 0x45, 0x61, 0xf1, 0x6f, 0xa3, 0x48, 0xfc, 0x72, 0x2c, 0x54,
            0xf2, 0x78, 0x05, 0x70,
        ];
        assert_eq!(hardening_recovery_scope_digest(&context).unwrap(), expected);

        let mut fresh = context.clone();
        fresh.request_sha256 = vec![20; 32];
        fresh.response_sha256 = vec![21; 32];
        fresh.attestation_challenge_sha256 = vec![22; 32];
        fresh.attestation_key_spki_sha256 = vec![23; 32];
        fresh.idempotency_key = "fresh-event-b".to_owned();
        fresh.wrapping_key_id = "wrapping-b".to_owned();
        assert_eq!(hardening_recovery_scope_digest(&fresh).unwrap(), expected);
        fresh.previous_receipt[0] ^= 1;
        assert_ne!(hardening_recovery_scope_digest(&fresh).unwrap(), expected);
    }

    #[test]
    fn hardening_recovery_cache_survives_lost_delivery_responses() {
        let mut cache = HardeningRecoveryCacheState::default();
        let scope = [0x31; 32];
        let selector = [0x42; HARDENING_RECOVERY_SELECTOR_BYTES];
        let now_ms = 1_000;
        let expires_at_ms = 10_000;
        cache.remember(scope, selector, expires_at_ms, now_ms).unwrap();

        for _lost_phase in
            ["initial_consume", "recovery_begin", "recovery_redeem", "recovery_consume"]
        {
            assert_eq!(
                cache.claim(&scope, now_ms + 1).unwrap(),
                Some(HardeningRecoveryUse { selector, expires_at_ms })
            );
        }
        cache.remember(scope, selector, expires_at_ms, now_ms + 2).unwrap();
        assert!(cache.remember(scope, [0x43; 32], expires_at_ms, now_ms + 2).is_err());
        cache.remove(&scope);
        assert_eq!(cache.claim(&scope, now_ms + 3).unwrap(), None);
    }

    #[test]
    fn hardening_recovery_retention_starts_only_at_ambiguous_consume() {
        let mut initial = HardeningRecoveryGuard::new(None, false);
        assert!(!initial.retains_for_disposition(HardeningFailureDisposition::Transient));
        initial.retain_for_fresh_retry();
        assert!(!initial.retains_for_disposition(HardeningFailureDisposition::Transient));
        initial.retain_after_ambiguous_consume();
        assert!(initial.retains_for_disposition(HardeningFailureDisposition::Transient));

        let mut recovery = HardeningRecoveryGuard::new(None, true);
        assert!(recovery.retains_for_disposition(HardeningFailureDisposition::Transient));
        assert!(!recovery.retains_for_disposition(HardeningFailureDisposition::Terminal));
        recovery.retain_for_fresh_retry();
        assert!(recovery.retains_for_disposition(HardeningFailureDisposition::Terminal));
    }

    #[test]
    fn hardening_recovery_cache_bounds_capacity_and_expiry() {
        let mut cache = HardeningRecoveryCacheState::default();
        let now_ms = 1_000;
        for index in 0..HARDENING_RECOVERY_CACHE_CAPACITY {
            cache
                .remember(
                    [u8::try_from(index + 1).unwrap(); 32],
                    [u8::try_from(index + 10).unwrap(); 32],
                    now_ms + 1_000,
                    now_ms,
                )
                .unwrap();
        }
        assert!(cache.remember([0x70; 32], [0x71; 32], now_ms + 1_000, now_ms).is_err());
        let scope = [1; 32];
        for _ in 0..8 {
            assert!(cache.claim(&scope, now_ms + 1).unwrap().is_some());
        }

        let mut expiry_cache = HardeningRecoveryCacheState::default();
        let expired_scope = [0x72; 32];
        expiry_cache.remember(expired_scope, [0x73; 32], now_ms + 10, now_ms).unwrap();
        assert_eq!(expiry_cache.claim(&expired_scope, now_ms + 10).unwrap(), None);
        assert_eq!(expiry_cache.claim(&expired_scope, now_ms + 11).unwrap(), None);
    }

    #[test]
    fn hardening_protected_challenge_binds_recovery_selector_and_expiry() {
        let now_ms = 1_800_000_000_000;
        let selector = [0x55; HARDENING_RECOVERY_SELECTOR_BYTES];
        let mut context = HardeningContextV1::new();
        context.protocol_minor = 4;
        context.purpose = HARDENING_PURPOSE_PROTECTED;
        let mut challenge = HardeningChallengeV1::new();
        challenge.schema_version = HARDENING_SCHEMA_VERSION;
        challenge.protocol_major = HARDENING_PROTOCOL_MAJOR;
        challenge.protocol_minor = context.protocol_minor;
        challenge.session_id = "hs_recovery".to_owned();
        challenge.grant_id = "hgr_recovery".to_owned();
        challenge.server_nonce = vec![0x11; 32];
        challenge.wrapping_attestation_challenge = vec![0x22; 32];
        challenge.server_expires_at_ms = now_ms + 15_000;
        challenge.policy_epoch = 1;
        challenge.grant_generation = 1;
        challenge.crypto_namespace = protobuf::EnumOrUnknown::new(
            HardeningCryptoNamespaceV1::HARDENING_CRYPTO_NAMESPACE_RELEASE,
        );
        challenge.crypto_suite = HARDENING_CRYPTO_SUITE_V1;
        challenge.recovery_selector = selector.to_vec();
        challenge.recovery_expires_at_ms = now_ms + 60_000;
        assert!(validate_hardening_challenge(&challenge, &context, "", None, now_ms).is_ok());

        let recovery =
            HardeningRecoveryUse { selector, expires_at_ms: challenge.recovery_expires_at_ms };
        context.recovery_selector = selector.to_vec();
        assert!(
            validate_hardening_challenge(&challenge, &context, "", Some(recovery), now_ms).is_ok()
        );
        challenge.recovery_selector[0] ^= 1;
        assert!(
            validate_hardening_challenge(&challenge, &context, "", Some(recovery), now_ms).is_err()
        );
        challenge.recovery_selector = selector.to_vec();
        challenge.recovery_expires_at_ms += 1;
        assert!(
            validate_hardening_challenge(&challenge, &context, "", Some(recovery), now_ms).is_err()
        );
        context.recovery_selector.clear();
        challenge.recovery_expires_at_ms = now_ms + HARDENING_RECOVERY_MAX_SERVER_LIFETIME_MS;
        assert!(validate_hardening_challenge(&challenge, &context, "", None, now_ms).is_ok());
        challenge.recovery_expires_at_ms = now_ms + HARDENING_RECOVERY_MAX_SERVER_LIFETIME_MS + 1;
        assert!(validate_hardening_challenge(&challenge, &context, "", None, now_ms).is_err());
    }

    #[test]
    fn hardening_wrapping_key_params_bind_challenge_and_serial() {
        let challenge = [0x5a; 32];
        let serial = b"device-serial";
        let expires_at_ms = 12_345;
        let params = hardening_wrapping_key_params(&challenge, expires_at_ms, serial).unwrap();
        assert!(has_key_parameter(&params, Tag::ATTESTATION_CHALLENGE, |value| {
            matches!(value, KeyParameterValue::Blob(value) if value == &challenge)
        }));
        assert!(has_key_parameter(&params, Tag::ATTESTATION_ID_SERIAL, |value| {
            matches!(value, KeyParameterValue::Blob(value) if value == serial)
        }));
        assert!(has_key_parameter(&params, Tag::USAGE_EXPIRE_DATETIME, |value| {
            matches!(value, KeyParameterValue::DateTime(value) if *value == expires_at_ms)
        }));
        assert!(hardening_wrapping_key_params(&challenge, 12_345, &[]).is_err());
    }

    #[test]
    fn hardening_wrapping_key_requires_exact_usage_expiry() {
        let expires_at_ms = 12_345;
        let mut metadata = KeyMetadata {
            authorizations: vec![Authorization {
                securityLevel: SecurityLevel::SOFTWARE,
                keyParameter: key_param(
                    Tag::USAGE_EXPIRE_DATETIME,
                    KeyParameterValue::DateTime(expires_at_ms),
                ),
            }],
            ..Default::default()
        };
        assert!(verify_hardening_wrapping_key_expiry(&metadata, expires_at_ms).is_ok());
        set_hardening_authorization_datetime(
            &mut metadata,
            Tag::USAGE_EXPIRE_DATETIME,
            expires_at_ms + 1,
        );
        assert!(verify_hardening_wrapping_key_expiry(&metadata, expires_at_ms).is_err());
        metadata.authorizations.clear();
        assert!(verify_hardening_wrapping_key_expiry(&metadata, expires_at_ms).is_err());
    }

    #[test]
    fn hardening_checked_deletion_reports_failure_and_retries_on_drop() {
        let calls = Rc::new(Cell::new(0));
        let key = TemporaryHardeningKey {
            descriptor: Some(test_key_descriptor(&format!(
                "{HARDENING_ALIAS_PREFIX}{HARDENING_WRAPPING_ALIAS_KIND}{}",
                "00112233-4455-6677-8899-aabbccddeeff"
            ))),
            deleter: TestHardeningKeyDeleter {
                outcomes: Rc::new(RefCell::new(VecDeque::from([false, true]))),
                calls: calls.clone(),
            },
        };

        assert!(key.delete_checked().is_err());
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn hardening_startup_cleanup_is_prefix_isolated() {
        let wrapping = format!(
            "{HARDENING_ALIAS_PREFIX}{HARDENING_WRAPPING_ALIAS_KIND}{}",
            "00112233-4455-6677-8899-aabbccddeeff"
        );
        let capability = format!(
            "{HARDENING_ALIAS_PREFIX}{HARDENING_CAPABILITY_ALIAS_KIND}{}",
            "ffeeddcc-bbaa-9988-7766-554433221100"
        );
        let invalid_suffix = format!("{HARDENING_ALIAS_PREFIX}wrapping_not-a-uuid");
        let mut batches = VecDeque::from([
            vec![
                test_key_descriptor("legacy-user-key"),
                test_key_descriptor(&wrapping),
                test_key_descriptor(&capability),
                test_key_descriptor(&invalid_suffix),
            ],
            Vec::new(),
        ]);
        let deleted = RefCell::new(Vec::new());

        cleanup_stale_hardening_aliases_with(
            |_| Ok(batches.pop_front().unwrap()),
            |descriptor| {
                deleted.borrow_mut().push(descriptor.alias.clone().unwrap());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(deleted.into_inner(), vec![wrapping, capability]);
    }

    #[test]
    fn prepared_pool_alias_round_trips_and_is_not_temporary() {
        let binding_sha256 = [0x5a; 32];
        let wrapping_key_id = "01234567-89ab-4cde-8fab-0123456789ab";
        let expires_at_ms = 1_800_000_000_000;
        let alias = hardening_pool_alias(&binding_sha256, expires_at_ms, wrapping_key_id).unwrap();
        let parsed = parse_hardening_pool_alias(&alias).unwrap();
        assert_eq!(parsed.binding_sha256, binding_sha256);
        assert_eq!(parsed.server_expires_at_ms, expires_at_ms);
        assert_eq!(parsed.wrapping_key_id, wrapping_key_id);
        assert!(!descriptor_is_temporary_hardening_alias(&test_key_descriptor(&alias)));
    }

    #[test]
    fn prepared_pool_alias_rejects_noncanonical_key_ids_and_metadata() {
        assert!(!canonical_v4_uuid("01234567-89AB-4CDE-8FAB-0123456789AB"));
        assert!(!canonical_v4_uuid("01234567-89ab-3cde-8fab-0123456789ab"));
        assert!(!canonical_v4_uuid("01234567-89ab-4cde-7fab-0123456789ab"));
        assert!(hardening_pool_alias(
            &[0x5a; 32],
            1_800_000_000_000,
            "01234567-89AB-4CDE-8FAB-0123456789AB",
        )
        .is_err());

        let valid = hardening_pool_alias(
            &[0x5a; 32],
            1_800_000_000_000,
            "01234567-89ab-4cde-8fab-0123456789ab",
        )
        .unwrap();
        assert!(parse_hardening_pool_alias(&valid.replace("5a5a", "5A5a")).is_none());
        assert!(parse_hardening_pool_alias(&format!("{valid}_extra")).is_none());
    }

    #[test]
    fn hardening_startup_cleanup_failure_is_bounded() {
        let alias = format!(
            "{HARDENING_ALIAS_PREFIX}{HARDENING_CAPABILITY_ALIAS_KIND}{}",
            "00112233-4455-6677-8899-aabbccddeeff"
        );
        let mut batches = VecDeque::from([vec![test_key_descriptor(&alias)], Vec::new()]);

        assert!(cleanup_stale_hardening_aliases_with(
            |_| Ok(batches.pop_front().unwrap()),
            |_| Err(HardeningFailure),
        )
        .is_err());
    }

    #[test]
    fn hardening_recovery_does_not_rerun_during_live_stage_work() {
        let state = OnceLock::new();
        let calls = Cell::new(0);
        assert!(initialize_hardening_stage_key_recovery_with(&state, || {
            calls.set(calls.get() + 1);
            true
        }));
        assert!(initialize_hardening_stage_key_recovery_with(&state, || {
            calls.set(calls.get() + 1);
            false
        }));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn hardening_capability_requires_hardware_authorizations() {
        let mut metadata = valid_hardening_capability_metadata(12_345);
        assert!(verify_hardening_capability_characteristics(&metadata, 12_345).is_ok());
        metadata.authorizations[0].securityLevel = SecurityLevel::SOFTWARE;
        assert!(verify_hardening_capability_characteristics(&metadata, 12_345).is_err());
    }

    #[test]
    fn hardening_capability_requires_exact_expiry() {
        let expires_at_ms = 12_345;
        let mut metadata = valid_hardening_capability_metadata(expires_at_ms);
        assert!(verify_hardening_capability_characteristics(&metadata, expires_at_ms).is_ok());

        metadata
            .authorizations
            .iter_mut()
            .find(|authorization| {
                authorization.keyParameter.tag == Tag::ORIGINATION_EXPIRE_DATETIME
            })
            .unwrap()
            .securityLevel = SecurityLevel::SOFTWARE;
        assert!(verify_hardening_capability_characteristics(&metadata, expires_at_ms).is_ok());

        set_hardening_authorization_datetime(
            &mut metadata,
            Tag::ORIGINATION_EXPIRE_DATETIME,
            expires_at_ms - 1,
        );
        assert!(verify_hardening_capability_characteristics(&metadata, expires_at_ms).is_err());

        set_hardening_authorization_datetime(
            &mut metadata,
            Tag::ORIGINATION_EXPIRE_DATETIME,
            expires_at_ms + 1,
        );
        assert!(verify_hardening_capability_characteristics(&metadata, expires_at_ms).is_err());
    }

    #[test]
    fn hardening_capability_rejects_user_auth_tags() {
        let mut metadata = valid_hardening_capability_metadata(12_345);
        metadata.authorizations.push(Authorization {
            securityLevel: SecurityLevel::TRUSTED_ENVIRONMENT,
            keyParameter: key_param(Tag::USER_SECURE_ID, KeyParameterValue::LongInteger(7)),
        });
        assert!(verify_hardening_capability_characteristics(&metadata, 12_345).is_err());
    }

    fn seal_empty_hardening_payload_for_test(
        outer_key: &[u8; 32],
        binding: &HardeningGrantBinding<'_>,
    ) -> Vec<u8> {
        let nonce = [0x66; AES_GCM_NONCE_BYTES];
        let mut aad = CanonicalWriter::new();
        aad.field(binding.crypto_namespace.sealed_payload_domain()).unwrap();
        aad.text(binding.session_id).unwrap();
        aad.text(binding.grant_id).unwrap();
        aad.u64(binding.grant_generation);
        aad.u32(binding.crypto_namespace.wire_value());
        aad.u32(HARDENING_CRYPTO_SUITE_V1);
        aad.field(binding.transcript_sha256).unwrap();
        aad.u64(binding.policy_epoch);

        let mut crypter =
            Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, outer_key, Some(&nonce)).unwrap();
        crypter.pad(false);
        crypter.aad_update(aad.bytes()).unwrap();
        let mut ciphertext = vec![0u8; Cipher::aes_256_gcm().block_size()];
        let count = crypter.update(&[], &mut ciphertext).unwrap();
        let rest = crypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count + rest);
        let mut tag = [0u8; AES_GCM_TAG_BYTES];
        crypter.get_tag(&mut tag).unwrap();

        let mut sealed = Vec::new();
        sealed.extend_from_slice(&HARDENING_SCHEMA_VERSION.to_be_bytes());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        sealed.extend_from_slice(&tag);
        sealed
    }

    fn has_key_parameter(
        params: &[KeyParameter],
        tag: Tag,
        expected: impl Fn(&KeyParameterValue) -> bool,
    ) -> bool {
        params.iter().any(|param| param.tag == tag && expected(&param.value))
    }

    fn test_key_descriptor(alias: &str) -> KeyDescriptor {
        KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias.to_owned()), blob: None }
    }

    fn valid_hardening_capability_metadata(expires_at_ms: i64) -> KeyMetadata {
        let values = [
            (Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::HMAC)),
            (Tag::KEY_SIZE, KeyParameterValue::Integer(256)),
            (Tag::PURPOSE, KeyParameterValue::KeyPurpose(KeyPurpose::SIGN)),
            (Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
            (Tag::MIN_MAC_LENGTH, KeyParameterValue::Integer(256)),
            (Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
            (Tag::ORIGINATION_EXPIRE_DATETIME, KeyParameterValue::DateTime(expires_at_ms)),
        ];
        KeyMetadata {
            keySecurityLevel: SecurityLevel::TRUSTED_ENVIRONMENT,
            authorizations: values
                .into_iter()
                .map(|(tag, value)| Authorization {
                    securityLevel: SecurityLevel::TRUSTED_ENVIRONMENT,
                    keyParameter: key_param(tag, value),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn set_hardening_authorization_datetime(metadata: &mut KeyMetadata, tag: Tag, value: i64) {
        metadata
            .authorizations
            .iter_mut()
            .find(|authorization| authorization.keyParameter.tag == tag)
            .unwrap()
            .keyParameter
            .value = KeyParameterValue::DateTime(value);
    }

    fn golden_apply_descriptor() -> Vec<u8> {
        decode_hex(
            "000000010000000100000001000000010000000000000002c4e7612b9d3805af28023e7bd707ad7c",
        )
    }

    fn processed_reply_apply_descriptor(envelope: [u8; 8]) -> Vec<u8> {
        let mut descriptor = Vec::with_capacity(HARDENING_APPLY_DESCRIPTOR_BYTES);
        descriptor.extend_from_slice(&HARDENING_APPLY_DESCRIPTOR_VERSION.to_be_bytes());
        descriptor.extend_from_slice(&1u32.to_be_bytes());
        descriptor.extend_from_slice(&HARDENING_PURPOSE_FUNCTIONAL.to_be_bytes());
        descriptor.extend_from_slice(&HARDENING_PROCESSED_REPLY_ROUTE.to_be_bytes());
        descriptor.extend_from_slice(&HARDENING_INITIAL_STAGE.to_be_bytes());
        descriptor.extend_from_slice(&1u32.to_be_bytes());
        descriptor.extend_from_slice(&HARDENING_PROCESSED_REPLY_PROGRAM_DOMAIN);
        descriptor.extend_from_slice(&envelope);
        descriptor
    }

    fn decode_hex(encoded: &str) -> Vec<u8> {
        assert_eq!(encoded.len() % 2, 0);
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = decode_nibble(pair[0]);
                let low = decode_nibble(pair[1]);
                (high << 4) | low
            })
            .collect()
    }

    fn decode_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }
}
