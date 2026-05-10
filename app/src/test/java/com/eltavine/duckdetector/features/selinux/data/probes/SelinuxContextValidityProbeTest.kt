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

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot
import org.junit.Assert.assertEquals
import org.junit.Test

class SelinuxContextValidityProbeTest {

    private val probe = SelinuxContextValidityProbe()

    @Test
    fun `trusted stable root context maps to root present`() {
        val result = probe.interpret(
            trustedSnapshot(
                ksuDomainValid = true,
            ),
        )

        assertEquals(SelinuxContextValidityState.ROOT_PRESENT, result.state)
    }

    @Test
    fun `self test failure is not treated as clean or root present`() {
        val result = probe.interpret(
            trustedSnapshot(
                oracleControlsPassed = false,
                ksuDomainValid = true,
            ),
        )

        assertEquals(SelinuxContextValidityState.UNTRUSTED_ORACLE, result.state)
    }

    @Test
    fun `permission denied self test maps to blocked oracle`() {
        val result = probe.interpret(
            trustedSnapshot(
                oracleControlsPassed = false,
                ksuDomainValid = true,
            ).copy(
                notes = listOf(
                    "Unavailable: u:r:app_zygote:s0 errno=Permission denied",
                ),
            ),
        )

        assertEquals(SelinuxContextValidityState.BLOCKED_ORACLE, result.state)
    }

    @Test
    fun `unstable root result is not treated as clean or root present`() {
        val result = probe.interpret(
            trustedSnapshot(
                ksuResultsStable = false,
                ksuDomainValid = true,
            ),
        )

        assertEquals(SelinuxContextValidityState.UNSTABLE_RESULTS, result.state)
    }

    private fun trustedSnapshot(
        oracleControlsPassed: Boolean = true,
        ksuResultsStable: Boolean = true,
        ksuDomainValid: Boolean? = false,
    ): SelinuxContextValiditySnapshot {
        return SelinuxContextValiditySnapshot(
            available = true,
            probeAttempted = true,
            carrierContext = "u:r:app_zygote:s0:c1,c2",
            carrierMatchesExpected = true,
            oracleControlsPassed = oracleControlsPassed,
            ksuResultsStable = ksuResultsStable,
            ksuDomainValid = ksuDomainValid,
            ksuFileValid = false,
            magiskFileValid = false,
        )
    }
}
