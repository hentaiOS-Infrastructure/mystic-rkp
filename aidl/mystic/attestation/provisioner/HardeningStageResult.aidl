// SPDX-License-Identifier: Apache-2.0
package mystic.attestation.provisioner;

/** Returns bounded data for one completed runtime operation. */
parcelable HardeningStageResult {
    int schemaVersion;
    int protocolMajor;
    int protocolMinor;
    /**
     * Contains the exact authenticated 40-byte functional runtime descriptor. It contains
     * the version, VM schema, purpose, route, stage, and instruction count as
     * big-endian 32-bit values. An 8-byte program domain and an 8-byte per-build
     * envelope commitment follow those values.
     */
    byte[] runtimePayload;
    /** Contains one verified nonzero 32-byte authorization tag for this result. */
    byte[] authorizedPayload;
    /** Contains one nonzero 64-byte proof for a functional or protected result. */
    byte[] opaqueContinuation;
    /** Contains one nonzero 96-byte opaque result extension passed through unchanged. */
    byte[] opaqueResultExtension;
    /** Contains one opaque protected bundle after a successful protected stage. */
    byte[] protectedBundle;
    /** Contains the protected-stage receipt. It is empty for a functional result. */
    byte[] receipt;
    /** Contains the protected-stage voucher. It is empty for a functional result. */
    byte[] nextVoucher;
    /** Contains the exact protected context SHA-256 value. It is empty for a functional result. */
    byte[] contextSha256;
    byte[] transcriptSha256;
    long policyEpoch;
    long serverExpiresAtMs;
}
