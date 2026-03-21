package com.eltavine.duckdetector.features.tee.data.repository

import android.content.Context
import com.eltavine.duckdetector.features.tee.data.attestation.AndroidAttestationCollector
import com.eltavine.duckdetector.features.tee.data.native.TeeNativeBridge
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkConsentStore
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefsStore
import com.eltavine.duckdetector.features.tee.data.report.TeeReportReducer
import com.eltavine.duckdetector.features.tee.data.report.TeeScanArtifacts
import com.eltavine.duckdetector.features.tee.data.soter.SoterCapabilityProbe
import com.eltavine.duckdetector.features.tee.data.verification.boot.BootConsistencyProbe
import com.eltavine.duckdetector.features.tee.data.verification.certificate.CertificateTrustAnalyzer
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureAnalyzer
import com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainProbe
import com.eltavine.duckdetector.features.tee.data.verification.certificate.GoogleAttestationRootStore
import com.eltavine.duckdetector.features.tee.data.verification.crl.CrlStatusService
import com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentProbe
import com.eltavine.duckdetector.features.tee.data.verification.rkp.RkpExtensionAnalyzer
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorProbeSuite
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext

class TeeRepository(
    context: Context,
    private val collector: AndroidAttestationCollector = AndroidAttestationCollector(),
    private val nativeBridge: TeeNativeBridge = TeeNativeBridge(),
    private val reducer: TeeReportReducer = TeeReportReducer(),
) {

    private val appContext = context.applicationContext
    private val consentStore: TeeNetworkPrefsStore = TeeNetworkConsentStore.getInstance(appContext)
    private val bootConsistencyProbe = BootConsistencyProbe()
    private val trustAnalyzer = CertificateTrustAnalyzer(GoogleAttestationRootStore(appContext))
    private val chainStructureAnalyzer = ChainStructureAnalyzer()
    private val rkpAnalyzer = RkpExtensionAnalyzer()
    private val crlStatusService = CrlStatusService(appContext, consentStore)
    private val pairConsistencyProbe = KeyPairConsistencyProbe()
    private val aesGcmProbe = AesGcmRoundTripProbe()
    private val lifecycleProbe = KeyLifecycleProbe()
    private val timingProbe = TimingAnomalyProbe()
    private val oversizedChallengeProbe = OversizedChallengeProbe()
    private val keyboxImportProbe = KeyboxImportProbe(appContext)
    private val keystore2HookProbe = Keystore2HookProbe()
    private val pureCertificateProbe = PureCertificateProbe()
    private val updateSubcomponentProbe = UpdateSubcomponentProbe()
    private val operationPruningProbe = OperationPruningProbe()
    private val dualAlgorithmProbe = DualAlgorithmChainProbe(trustAnalyzer)
    private val idAttestationProbe = IdAttestationProbe()
    private val strongBoxProbe = StrongBoxBehaviorProbeSuite(appContext, collector)
    private val soterProbe = SoterCapabilityProbe(appContext)

    suspend fun scan(): TeeReport = withContext(Dispatchers.Default) {
        runCatching {
            val snapshot = collector.collect(useStrongBox = false)
            val trust = trustAnalyzer.inspect(snapshot.rawCertificates)
            val chainStructure = chainStructureAnalyzer.inspect(snapshot.rawCertificates)
            val rkp = rkpAnalyzer.analyze(
                snapshot.rawCertificates,
                chainStructure,
                trust.googleRootMatched
            )
            val crl = crlStatusService.inspect(snapshot.rawCertificates)
            val native =
                nativeBridge.collectSnapshot(snapshot.rawCertificates.firstOrNull()?.encoded)
            val soter = runCatching { soterProbe.inspect() }.getOrDefault(TeeSoterState())
            val bootConsistency = bootConsistencyProbe.inspect(snapshot)
            val deepChecks =
                if (snapshot.tier == TeeTier.TEE || snapshot.tier == TeeTier.STRONGBOX) {
                    collectDeepChecks(snapshot.tier == TeeTier.STRONGBOX, snapshot)
                } else {
                    DeferredChecks.skipped(snapshot)
                }

            reducer.reduce(
                TeeScanArtifacts(
                    snapshot = snapshot,
                    trust = trust,
                    chainStructure = chainStructure,
                    rkp = rkp,
                    crl = crl,
                    pairConsistency = deepChecks.pairConsistency,
                    aesGcm = deepChecks.aesGcm,
                    lifecycle = deepChecks.lifecycle,
                    timing = deepChecks.timing,
                    oversizedChallenge = deepChecks.oversizedChallenge,
                    keyboxImport = deepChecks.keyboxImport,
                    keystore2Hook = deepChecks.keystore2Hook,
                    pureCertificate = deepChecks.pureCertificate,
                    updateSubcomponent = deepChecks.updateSubcomponent,
                    pruning = deepChecks.pruning,
                    dualAlgorithm = deepChecks.dualAlgorithm,
                    idAttestation = deepChecks.idAttestation,
                    strongBox = deepChecks.strongBox,
                    native = native,
                    soter = soter,
                    bootConsistency = bootConsistency,
                ),
            )
        }.getOrElse { throwable ->
            TeeReport.failed(throwable.message ?: "TEE scan failed.")
        }
    }

    private suspend fun collectDeepChecks(
        useStrongBox: Boolean,
        snapshot: com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot,
    ): DeferredChecks = coroutineScope {
        val pairConsistency = async { pairConsistencyProbe.inspect(useStrongBox = useStrongBox) }
        val aesGcm = async { aesGcmProbe.inspect(useStrongBox = useStrongBox) }
        val lifecycle = async { lifecycleProbe.inspect(useStrongBox = useStrongBox) }
        val timing = async { timingProbe.inspect(useStrongBox = useStrongBox) }
        val oversizedChallenge =
            async { oversizedChallengeProbe.inspect(useStrongBox = useStrongBox) }
        val keyboxImport = async { keyboxImportProbe.inspect() }
        val keystore2Hook = async { keystore2HookProbe.inspect() }
        val pureCertificate = async { pureCertificateProbe.inspect() }
        val updateSubcomponent =
            async { updateSubcomponentProbe.inspect(useStrongBox = useStrongBox) }
        val pruning = async { operationPruningProbe.inspect(useStrongBox = useStrongBox) }
        val dualAlgorithm = async {
            val comparison = collector.collectComparisonChains(useStrongBox = useStrongBox)
            dualAlgorithmProbe.inspect(comparison.first, comparison.second)
        }
        val idAttestation = async { idAttestationProbe.inspect(snapshot) }
        val strongBox = async { strongBoxProbe.inspect() }

        DeferredChecks(
            pairConsistency = pairConsistency.await(),
            aesGcm = aesGcm.await(),
            lifecycle = lifecycle.await(),
            timing = timing.await(),
            oversizedChallenge = oversizedChallenge.await(),
            keyboxImport = keyboxImport.await(),
            keystore2Hook = keystore2Hook.await(),
            pureCertificate = pureCertificate.await(),
            updateSubcomponent = updateSubcomponent.await(),
            pruning = pruning.await(),
            dualAlgorithm = dualAlgorithm.await(),
            idAttestation = idAttestation.await(),
            strongBox = strongBox.await(),
        )
    }
}

private data class DeferredChecks(
    val pairConsistency: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult,
    val aesGcm: com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult,
    val lifecycle: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult,
    val timing: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult,
    val oversizedChallenge: com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult,
    val keyboxImport: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult,
    val keystore2Hook: com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult,
    val pureCertificate: com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult,
    val updateSubcomponent: com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult,
    val pruning: com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult,
    val dualAlgorithm: com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult,
    val idAttestation: com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult,
    val strongBox: com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult,
) {
    companion object {
        fun skipped(
            snapshot: com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot,
        ) = DeferredChecks(
            pairConsistency = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult(
                keyMatchesCertificate = true,
                detail = "Deep checks were skipped because hardware-backed attestation was not established.",
            ),
            aesGcm = com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult(
                executed = false,
                detail = "AES-GCM round-trip probe skipped.",
            ),
            lifecycle = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult(
                created = false,
                deleteRemovedAlias = true,
                regeneratedFreshMaterial = true,
                detail = "Lifecycle probe skipped.",
            ),
            timing = com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult(
                suspicious = false,
                detail = "Timing probe skipped.",
            ),
            oversizedChallenge = com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult(
                acceptedOversizedChallenge = false,
                acceptedSizes = emptyList(),
                attemptedSizes = com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeProbe.CHALLENGE_SIZES,
                detail = "Oversized challenge probe skipped.",
            ),
            keyboxImport = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult(
                executed = false,
                markerPreserved = true,
                marker = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe.FIXTURE_MARKER,
                detail = "Keybox import probe skipped.",
            ),
            keystore2Hook = com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult(
                available = false,
                detail = "Keystore2 hook probe skipped.",
            ),
            pureCertificate = com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult(
                pureCertificateReturnsNullKey = true,
                detail = "Pure certificate probe skipped.",
            ),
            updateSubcomponent = com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult(
                updateSucceeded = true,
                keyNotFoundStyleFailure = false,
                detail = "Update subcomponent probe skipped.",
            ),
            pruning = com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult(
                suspicious = false,
                operationsCreated = 0,
                invalidatedOperations = 0,
                detail = "Pruning probe skipped.",
            ),
            dualAlgorithm = com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult(
                mismatchDetected = false,
                detail = "Dual algorithm comparison skipped.",
            ),
            idAttestation = com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult(
                mismatches = emptyList(),
                unavailableFields = emptyList(),
                detail = "ID attestation probe skipped.",
                probeRan = false,
            ),
            strongBox = com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult(
                requested = false,
                advertised = false,
                available = false,
                detail = "StrongBox probe skipped.",
            ),
        )
    }
}
