// SPDX-License-Identifier: Apache-2.0
package mystic.attestation.provisioner;

/** Binds one functional or protected runtime operation to its exact local request and response. */
parcelable HardeningStageContext {
    int schemaVersion;
    int protocolMajor;
    int protocolMinor;
    String buildId;
    byte[] payloadSha256;
    byte[] profileConfigSha256;
    int vmSchemaVersion;
    long runtimeEpoch;
    /** Must be functional value 1 or protected value 2. */
    int purpose;
    /** Functional accepts routes 1 and 2. Protected accepts only route 1. */
    int routeId;
    /** Functional uses stage 0. Protected uses stages 1 through 3. */
    int stageId;
    byte[] requestSha256;
    byte[] responseSha256;
    byte[] attestationChallengeSha256;
    byte[] attestationKeySpkiSha256;
    /** Functional and protected stage 1 require empty data. Protected stages 2 and 3 require data. */
    byte[] previousReceipt;
    /** Functional and protected stage 1 require empty data. Protected stages 2 and 3 require data. */
    byte[] voucher;
    String idempotencyKey;
    /** Commits the exact local transition. Must contain 32 nonzero bytes. */
    byte[] nextTransitionSha256;
    /** Functional requires empty data. Protected requires exactly 32 opaque nonzero bytes. */
    byte[] latentBinding;
}
