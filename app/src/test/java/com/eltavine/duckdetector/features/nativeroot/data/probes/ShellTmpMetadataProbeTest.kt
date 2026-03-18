package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ShellTmpMetadataProbeTest {

    private val probe = ShellTmpMetadataProbe()

    @Test
    fun `owner and mode drift produce danger findings`() {
        val result = probe.evaluate(
            ShellTmpMetadataSample(
                uid = 0,
                gid = 0,
                mode = 0x1FF,
                inode = 512,
            ),
        )

        assertTrue(result.available)
        assertEquals(2, result.findings.count { it.severity == NativeRootFindingSeverity.DANGER })
        assertTrue(result.findings.any { it.label == "Shell tmp ownership" })
        assertTrue(result.findings.any { it.label == "Shell tmp mode" })
    }

    @Test
    fun `high inode is warning only`() {
        val result = probe.evaluate(
            ShellTmpMetadataSample(
                uid = 2000,
                gid = 2000,
                mode = 0x1F9,
                inode = 15001,
            ),
        )

        assertEquals(1, result.findings.size)
        assertEquals(NativeRootFindingSeverity.WARNING, result.findings.single().severity)
        assertEquals("Shell tmp inode", result.findings.single().label)
    }

    @Test
    fun `expected metadata stays clean`() {
        val result = probe.evaluate(
            ShellTmpMetadataSample(
                uid = 2000,
                gid = 2000,
                mode = 0x41F9,
                inode = 1024,
            ),
        )

        assertTrue(result.available)
        assertTrue(result.findings.isEmpty())
    }
}
