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
        val state = when {
            ksuDomainValid ?: false || ksuFileValid ?: false || magiskFileValid ?: false -> SelinuxContextValidityState.ROOT_PRESENT
            else -> SelinuxContextValidityState.CLEAN
        }

        val notes = buildList {
            addAll(this@toProbeResult.notes)
            when (state) {
                SelinuxContextValidityState.CLEAN ->
                    add("Root specific contexts were not found by live policy.")

                SelinuxContextValidityState.ROOT_PRESENT ->
                    add("Root contexts were found by live policy.")
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
    }
}
