package com.eltavine.duckdetector.features.selinux.data.probes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AuditAvcSideChannelProbeTest {

    private val probe = AuditAvcSideChannelProbe()

    @Test
    fun `canonical avc denied line is reported as side channel`() {
        val result = probe.evaluate(
            """
                03-19 12:00:00.000  1234  1234 W auditd  : avc: denied { getattr } for path="/proc/1/maps" dev="proc" ino=1 scontext=u:r:untrusted_app:s0:c123,c456 tcontext=u:r:init:s0 tclass=file permissive=0
            """.trimIndent(),
        )

        assertEquals(1, result.hits.size)
        assertEquals("AVC denial leak", result.hits.single().label)
        assertTrue(result.hits.single().value.startsWith("scontext="))
    }

    @Test
    fun `plain app log mentioning avc is ignored`() {
        val result = probe.evaluate(
            """
                03-19 12:00:00.000  1234  1234 I DuckDetector: avc denied string used in docs only
            """.trimIndent(),
        )

        assertTrue(result.hits.isEmpty())
    }

    @Test
    fun `duplicate avc lines are deduplicated`() {
        val line =
            """03-19 12:00:00.000  1234  1234 W auditd  : type=1400 audit(0.0:123): avc: denied { open } for comm="su" path="/proc/1/mem" scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:r:init:s0 tclass=file permissive=0"""
        val result = probe.evaluate(
            """
                $line
                $line
            """.trimIndent(),
        )

        assertEquals(1, result.hits.size)
        assertEquals("comm=su", result.hits.single().value)
    }
}
