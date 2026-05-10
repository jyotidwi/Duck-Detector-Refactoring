/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot

enum class SelinuxContextValidityState {
    CLEAN,
    ROOT_PRESENT,
    BLOCKED_ORACLE,
    UNTRUSTED_ORACLE,
    UNSTABLE_RESULTS,
}

data class SelinuxContextValidityProbeResult(
    val state: SelinuxContextValidityState,
    val available: Boolean,
    val probeAttempted: Boolean,
    val carrierContext: String?,
    val carrierMatchesExpected: Boolean,
    val carrierControlValid: Boolean?,
    val negativeControlRejected: Boolean?,
    val fileControlValid: Boolean?,
    val fileNegativeControlRejected: Boolean?,
    val oracleControlsPassed: Boolean,
    val ksuResultsStable: Boolean,
    val queryMethod: String,
    val ksuDomainValid: Boolean?,
    val ksuFileValid: Boolean?,
    val magiskFileValid: Boolean?,
    val failureReason: String?,
    val notes: List<String>,
)

class SelinuxContextValidityProbe(
    private val nativeBridge: SelinuxContextValidityBridge = SelinuxContextValidityBridge(),
) {

    fun inspect(): SelinuxContextValidityProbeResult {
        return nativeBridge.collectSnapshot().toProbeResult()
    }

    fun interpret(snapshot: SelinuxContextValiditySnapshot): SelinuxContextValidityProbeResult {
        return snapshot.toProbeResult()
    }

    internal fun SelinuxContextValiditySnapshot.toProbeResult(): SelinuxContextValidityProbeResult {
        val trustedCarrier = available && probeAttempted && carrierMatchesExpected
        val hasRootContext = ksuDomainValid == true || ksuFileValid == true || magiskFileValid == true
        val oracleBlockedByPolicy = trustedCarrier &&
            !oracleControlsPassed &&
            hasPolicyDeniedEvidence()
        val state = when {
            oracleBlockedByPolicy -> SelinuxContextValidityState.BLOCKED_ORACLE
            trustedCarrier && !oracleControlsPassed -> SelinuxContextValidityState.UNTRUSTED_ORACLE
            trustedCarrier && oracleControlsPassed && !ksuResultsStable -> SelinuxContextValidityState.UNSTABLE_RESULTS
            trustedCarrier && hasRootContext -> SelinuxContextValidityState.ROOT_PRESENT
            else -> SelinuxContextValidityState.CLEAN
        }

        val notes = buildList {
            addAll(this@toProbeResult.notes)
            when (state) {
                SelinuxContextValidityState.CLEAN ->
                    add("Root specific contexts were not found by live policy.")

                SelinuxContextValidityState.ROOT_PRESENT ->
                    add("Root contexts were found by live policy.")

                SelinuxContextValidityState.BLOCKED_ORACLE ->
                    add("app_zygote SELinux context queries were blocked by policy.")

                SelinuxContextValidityState.UNTRUSTED_ORACLE ->
                    add("Context validity oracle failed its self-test.")

                SelinuxContextValidityState.UNSTABLE_RESULTS ->
                    add("Context validity oracle repeated inconsistently.")
            }
        }.distinct()

        return SelinuxContextValidityProbeResult(
            state = state,
            available = available,
            probeAttempted = probeAttempted,
            carrierContext = carrierContext,
            carrierMatchesExpected = carrierMatchesExpected,
            carrierControlValid = carrierControlValid,
            negativeControlRejected = negativeControlRejected,
            fileControlValid = fileControlValid,
            fileNegativeControlRejected = fileNegativeControlRejected,
            oracleControlsPassed = oracleControlsPassed,
            ksuResultsStable = ksuResultsStable,
            queryMethod = queryMethod,
            ksuDomainValid = ksuDomainValid,
            ksuFileValid = ksuFileValid,
            magiskFileValid = magiskFileValid,
            failureReason = failureReason,
            notes = notes,
        )
    }

    companion object {
        const val METHOD_LABEL = "Context validity oracle"
        const val STATUS_ROOT_CONTEXT_FOUND = "Root Selinux Context found"
        const val STATUS_ORACLE_BLOCKED = "Context oracle blocked"
        const val STATUS_ORACLE_SELF_TEST_FAILED = "Context oracle self-test failed"
        const val STATUS_ORACLE_UNSTABLE = "Context oracle unstable"
    }

    private fun SelinuxContextValiditySnapshot.hasPolicyDeniedEvidence(): Boolean {
        return listOfNotNull(failureReason)
            .plus(notes)
            .any { note ->
                note.contains("Permission denied", ignoreCase = true) ||
                    note.contains("EACCES", ignoreCase = true)
            }
    }
}
