// SPDX-License-Identifier: Apache-2.0
package mystic.attestation.provisioner;

import mystic.attestation.provisioner.AttestationKeyCertificateProfile;
import mystic.attestation.provisioner.HardeningStageContext;
import mystic.attestation.provisioner.HardeningStageResult;
import mystic.attestation.provisioner.ProvisionedAttestationKey;
import mystic.attestation.provisioner.ProtectedStageCompletion;

/** Supplies a backend-owned attestation key for immediate hardware import. */
@SensitiveData
interface IBackendAttestationKeyProvisioner {
    ProvisionedAttestationKey provisionAttestationKey(
            in AttestationKeyCertificateProfile certificateProfile,
            in byte[] wrappingKeyLeafCertificate,
            in byte[] wrappingKeyRemainingChain);

    /** Authorizes one server-bound backend attestation-key import Apply operation. */
    HardeningStageResult authorizeHardeningStage(in HardeningStageContext context);

    /** Records one successful protected stage-three completion. */
    void completeProtectedStage(in ProtectedStageCompletion completion);
}
