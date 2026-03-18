package com.eltavine.duckdetector.features.nativeroot.data.repository

import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeBridge
import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeFinding
import com.eltavine.duckdetector.features.nativeroot.data.probes.RootProcessAuditProbe
import com.eltavine.duckdetector.features.nativeroot.data.probes.ShellTmpMetadataProbe
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class NativeRootRepository(
    private val nativeBridge: NativeRootNativeBridge = NativeRootNativeBridge(),
    private val shellTmpMetadataProbe: ShellTmpMetadataProbe = ShellTmpMetadataProbe(),
    private val rootProcessAuditProbe: RootProcessAuditProbe = RootProcessAuditProbe(),
) {

    suspend fun scan(): NativeRootReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                NativeRootReport.failed(throwable.message ?: "Native Root scan failed.")
            }
    }

    private fun scanInternal(): NativeRootReport {
        val snapshot = nativeBridge.collectSnapshot()
        val nativeFindings = snapshot.findings.mapIndexed { index, finding ->
            finding.toDomainFinding(index)
        }
        val shellTmpResult = shellTmpMetadataProbe.run()
        val rootProcessResult = rootProcessAuditProbe.run()
        val findings = nativeFindings + shellTmpResult.findings + rootProcessResult.findings

        return NativeRootReport(
            stage = NativeRootStage.READY,
            findings = findings,
            kernelSuDetected = snapshot.kernelSuDetected,
            aPatchDetected = snapshot.aPatchDetected,
            magiskDetected = snapshot.magiskDetected,
            susfsDetected = snapshot.susfsDetected,
            kernelSuVersion = snapshot.kernelSuVersion,
            nativeAvailable = snapshot.available,
            prctlProbeHit = snapshot.prctlProbeHit,
            susfsProbeHit = snapshot.susfsProbeHit,
            pathHitCount = snapshot.pathHitCount + shellTmpResult.hitCount,
            pathCheckCount = snapshot.pathCheckCount + shellTmpResult.checkedCount,
            processHitCount = snapshot.processHitCount + rootProcessResult.hitCount,
            processCheckedCount = snapshot.processCheckedCount + rootProcessResult.checkedCount,
            processDeniedCount = snapshot.processDeniedCount + rootProcessResult.deniedCount,
            kernelHitCount = snapshot.kernelHitCount,
            kernelSourceCount = snapshot.kernelSourceCount,
            propertyHitCount = snapshot.propertyHitCount,
            propertyCheckCount = snapshot.propertyCheckCount,
            methods = buildMethods(
                snapshot = snapshot,
                findings = findings,
                shellTmpDetail = shellTmpResult.detail,
                rootProcessDetail = rootProcessResult.detail,
            ),
        )
    }

    private fun buildMethods(
        snapshot: com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeSnapshot,
        findings: List<NativeRootFinding>,
        shellTmpDetail: String,
        rootProcessDetail: String,
    ): List<NativeRootMethodResult> {
        val directFindings =
            findings.filter { it.group == NativeRootGroup.SYSCALL || it.group == NativeRootGroup.SIDE_CHANNEL }
        val runtimeFindings =
            findings.filter { it.group == NativeRootGroup.PATH || it.group == NativeRootGroup.PROCESS }
        val kernelFindings = findings.filter { it.group == NativeRootGroup.KERNEL }
        val propertyFindings = findings.filter { it.group == NativeRootGroup.PROPERTY }

        return listOf(
            NativeRootMethodResult(
                label = "prctlProbe",
                summary = when {
                    snapshot.prctlProbeHit && snapshot.kernelSuVersion > 0L -> "v${snapshot.kernelSuVersion}"
                    snapshot.prctlProbeHit -> "Detected"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    snapshot.prctlProbeHit -> NativeRootMethodOutcome.DETECTED
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "KernelSU magic prctl probe using option 0xDEADBEEF.",
            ),
            NativeRootMethodResult(
                label = "susfsSideChannel",
                summary = when {
                    snapshot.susfsProbeHit -> "SIGKILL"
                    snapshot.available -> "Normal"
                    else -> "Unavailable"
                },
                outcome = when {
                    snapshot.susfsProbeHit -> NativeRootMethodOutcome.DETECTED
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "Fork child and attempt setresuid to a lower UID. Old SUSFS/KSU hooks can kill the child instead of returning EPERM.",
            ),
            NativeRootMethodResult(
                label = "runtimeArtifacts",
                summary = when {
                    runtimeFindings.isNotEmpty() -> "${runtimeFindings.size} hit(s)"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    runtimeFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                    runtimeFindings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = buildString {
                    append("Scan /data/adb manager paths, /data/local/tmp metadata, and /proc process state for KernelSU, APatch, KernelPatch, Magisk, and unexpected root-process traces.")
                    if (shellTmpDetail.isNotBlank()) {
                        append("\nShell tmp: ")
                        append(shellTmpDetail)
                    }
                    if (rootProcessDetail.isNotBlank()) {
                        append("\nProcess audit: ")
                        append(rootProcessDetail)
                    }
                },
            ),
            NativeRootMethodResult(
                label = "kernelTraces",
                summary = when {
                    kernelFindings.isNotEmpty() -> "${kernelFindings.size} source(s)"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    kernelFindings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "Check /proc/kallsyms, /proc/modules, and uname strings for KernelSU, APatch, KernelPatch, SuperCall, or Magisk tokens.",
            ),
            NativeRootMethodResult(
                label = "propertyResidue",
                summary = when {
                    propertyFindings.isNotEmpty() -> "${propertyFindings.size} hit(s)"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    propertyFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                    propertyFindings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "Read a small catalog of root-specific properties such as ro.kernel.ksu and APatch/KernelPatch variants.",
            ),
            NativeRootMethodResult(
                label = "nativeLibrary",
                summary = if (snapshot.available) "Loaded" else "Unavailable",
                outcome = if (snapshot.available) NativeRootMethodOutcome.CLEAN else NativeRootMethodOutcome.SUPPORT,
                detail = "JNI-backed native root detection module.",
            ),
            NativeRootMethodResult(
                label = "signalSummary",
                summary = when {
                    directFindings.isNotEmpty() -> "${directFindings.size} direct"
                    findings.isNotEmpty() -> "${findings.size} indirect"
                    snapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    directFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> NativeRootMethodOutcome.DETECTED
                    findings.isNotEmpty() -> NativeRootMethodOutcome.WARNING
                    snapshot.available -> NativeRootMethodOutcome.CLEAN
                    else -> NativeRootMethodOutcome.SUPPORT
                },
                detail = "Direct probes are syscall and side-channel results; indirect probes are kernel strings, paths, processes, and properties.",
            ),
        )
    }

    private fun NativeRootNativeFinding.toDomainFinding(
        index: Int,
    ): NativeRootFinding {
        return NativeRootFinding(
            id = "${group.lowercase()}_$index",
            label = label,
            value = value,
            detail = detail,
            group = groupFromRaw(group),
            severity = severityFromRaw(severity),
            detailMonospace = true,
        )
    }

    private fun groupFromRaw(
        raw: String,
    ): NativeRootGroup {
        return when (raw) {
            "SYSCALL" -> NativeRootGroup.SYSCALL
            "SIDE_CHANNEL" -> NativeRootGroup.SIDE_CHANNEL
            "PATH" -> NativeRootGroup.PATH
            "PROCESS" -> NativeRootGroup.PROCESS
            "KERNEL" -> NativeRootGroup.KERNEL
            "PROPERTY" -> NativeRootGroup.PROPERTY
            else -> NativeRootGroup.KERNEL
        }
    }

    private fun severityFromRaw(
        raw: String,
    ): NativeRootFindingSeverity {
        return when (raw) {
            "DANGER" -> NativeRootFindingSeverity.DANGER
            "WARNING" -> NativeRootFindingSeverity.WARNING
            else -> NativeRootFindingSeverity.INFO
        }
    }
}
