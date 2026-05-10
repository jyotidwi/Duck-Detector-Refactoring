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

package com.eltavine.duckdetector.features.selinux.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxContextValidityBridgeTest {

    private val bridge = SelinuxContextValidityBridge()

    @Test
    fun `parse decodes context validity and dirty policy snapshot`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                PROBE_ATTEMPTED=1
                CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                CARRIER_MATCHES_EXPECTED=1
                CARRIER_CONTROL_VALID=1
                NEGATIVE_CONTROL_REJECTED=1
                FILE_CONTROL_VALID=1
                FILE_NEGATIVE_CONTROL_REJECTED=1
                ORACLE_CONTROLS_PASSED=1
                KSU_RESULTS_STABLE=1
                QUERY_METHOD=raw selinuxfs write
                KSU_DOMAIN_VALID=1
                KSU_FILE_VALID=0
                MAGISK_FILE_VALID=0
                DIRTY_POLICY_AVAILABLE=1
                DIRTY_POLICY_PROBE_ATTEMPTED=1
                DIRTY_POLICY_CARRIER_CONTEXT=u:r:app_zygote:s0:c1,c2
                DIRTY_POLICY_CARRIER_MATCHES_EXPECTED=1
                DIRTY_POLICY_CONTROLS_PASSED=1
                DIRTY_POLICY_STABLE=1
                DIRTY_POLICY_QUERY_METHOD=SELinux.checkSELinuxAccess
                DIRTY_POLICY_ACCESS_CONTROL_ALLOWED=1
                DIRTY_POLICY_NEGATIVE_CONTROL_REJECTED=1
                DIRTY_POLICY_SYSTEM_SERVER_EXECMEM_ALLOWED=0
                DIRTY_POLICY_MAGISK_BINDER_CALL_ALLOWED=0
                DIRTY_POLICY_KSU_BINDER_CALL_ALLOWED=0
                DIRTY_POLICY_LSPOSED_FILE_READ_ALLOWED=1
                DIRTY_POLICY_FAILURE_REASON=Dirty\npolicy unavailable
                DIRTY_POLICY_NOTE=Carrier\ncontext: u:r:app_zygote:s0
                DIRTY_POLICY_NOTE=LSPosed\tpolicy\nread
                NOTE=Carrier\ncontext: u:r:app_zygote:s0
                NOTE=Query\tmethod\nraw selinuxfs write
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.probeAttempted)
        assertEquals("u:r:app_zygote:s0:c1,c2", snapshot.carrierContext)
        assertTrue(snapshot.carrierMatchesExpected)
        assertTrue(snapshot.carrierControlValid == true)
        assertTrue(snapshot.negativeControlRejected == true)
        assertTrue(snapshot.fileControlValid == true)
        assertTrue(snapshot.fileNegativeControlRejected == true)
        assertTrue(snapshot.oracleControlsPassed)
        assertTrue(snapshot.ksuResultsStable)
        assertEquals("raw selinuxfs write", snapshot.queryMethod)
        assertEquals(true, snapshot.ksuDomainValid)
        assertEquals(false, snapshot.ksuFileValid)
        assertEquals(false, snapshot.magiskFileValid)
        assertTrue(snapshot.dirtyPolicyAvailable)
        assertTrue(snapshot.dirtyPolicyProbeAttempted)
        assertEquals("u:r:app_zygote:s0:c1,c2", snapshot.dirtyPolicyCarrierContext)
        assertTrue(snapshot.dirtyPolicyCarrierMatchesExpected)
        assertTrue(snapshot.dirtyPolicyControlsPassed)
        assertTrue(snapshot.dirtyPolicyStable)
        assertEquals("SELinux.checkSELinuxAccess", snapshot.dirtyPolicyQueryMethod)
        assertTrue(snapshot.dirtyPolicyAccessControlAllowed == true)
        assertTrue(snapshot.dirtyPolicyNegativeControlRejected == true)
        assertTrue(snapshot.dirtyPolicySystemServerExecmemAllowed == false)
        assertTrue(snapshot.dirtyPolicyMagiskBinderCallAllowed == false)
        assertTrue(snapshot.dirtyPolicyKsuBinderCallAllowed == false)
        assertTrue(snapshot.dirtyPolicyLsposedFileReadAllowed == true)
        assertEquals("Dirty\npolicy unavailable", snapshot.dirtyPolicyFailureReason)
        assertEquals(
            listOf(
                "Carrier\ncontext: u:r:app_zygote:s0",
                "LSPosed\tpolicy\nread",
            ),
            snapshot.dirtyPolicyNotes,
        )
        assertEquals(
            listOf(
                "Carrier\ncontext: u:r:app_zygote:s0",
                "Query\tmethod\nraw selinuxfs write",
            ),
            snapshot.notes,
        )
    }
}
