package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot
import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.data.verification.boot.BootConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.CertificateTrustResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult
import com.eltavine.duckdetector.features.tee.data.verification.crl.CrlStatusResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState

data class TeeScanArtifacts(
    val snapshot: AttestationSnapshot,
    val trust: CertificateTrustResult,
    val chainStructure: ChainStructureResult,
    val rkp: TeeRkpState,
    val crl: CrlStatusResult,
    val pairConsistency: KeyPairConsistencyResult,
    val aesGcm: AesGcmRoundTripResult,
    val lifecycle: KeyLifecycleResult,
    val timing: TimingAnomalyResult,
    val oversizedChallenge: OversizedChallengeResult,
    val keyboxImport: KeyboxImportResult,
    val keystore2Hook: Keystore2HookResult,
    val pureCertificate: PureCertificateResult,
    val updateSubcomponent: UpdateSubcomponentResult,
    val pruning: OperationPruningResult,
    val dualAlgorithm: DualAlgorithmChainResult,
    val idAttestation: IdAttestationResult,
    val strongBox: StrongBoxBehaviorResult,
    val native: NativeTeeSnapshot,
    val soter: TeeSoterState,
    val bootConsistency: BootConsistencyResult,
)
