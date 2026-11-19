// SPDX-License-Identifier: Apache-2.0
package mystic.attestation.provisioner;

/** Carries one successful protected stage-three completion. */
parcelable ProtectedStageCompletion {
    int schemaVersion;
    int protocolMajor;
    int protocolMinor;
    String sessionId;
    String grantId;
    byte[] contextSha256;
    byte[] receipt;
    byte[] nextVoucher;
    byte[] completionToken;
}
