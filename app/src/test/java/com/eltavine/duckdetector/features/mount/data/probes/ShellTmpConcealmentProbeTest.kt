package com.eltavine.duckdetector.features.mount.data.probes

import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ShellTmpConcealmentProbeTest {

    private val probe = ShellTmpConcealmentProbe()

    @Test
    fun `dedicated mount is danger`() {
        val result = probe.evaluate(
            ShellTmpObservation(
                parentAccessible = true,
                accessState = ShellTmpAccessState.ACCESSIBLE,
                javaExists = true,
                javaDirectory = true,
                javaCanRead = true,
                javaListable = true,
                dedicatedMounts = listOf(
                    ShellTmpMountEntry(
                        target = "/data/local/tmp",
                        fsType = "overlay",
                        source = "tmpfs",
                    ),
                ),
            ),
        )

        assertTrue(result.hasDanger)
        assertTrue(result.findings.any { it.label == "Shell tmp dedicated mount" })
    }

    @Test
    fun `missing tmp under visible parent is warning`() {
        val result = probe.evaluate(
            ShellTmpObservation(
                parentAccessible = true,
                accessState = ShellTmpAccessState.MISSING,
                javaExists = false,
                javaDirectory = false,
                javaCanRead = false,
                javaListable = false,
                dedicatedMounts = emptyList(),
            ),
        )

        assertTrue(result.hasWarning)
        assertEquals(
            MountFindingSeverity.WARNING,
            result.findings.single { it.label == "Shell tmp view" }.severity
        )
    }

    @Test
    fun `java hidden while stat accessible is danger`() {
        val result = probe.evaluate(
            ShellTmpObservation(
                parentAccessible = true,
                accessState = ShellTmpAccessState.ACCESSIBLE,
                javaExists = false,
                javaDirectory = false,
                javaCanRead = false,
                javaListable = false,
                dedicatedMounts = emptyList(),
            ),
        )

        assertTrue(result.hasDanger)
        assertTrue(result.findings.any { it.label == "Shell tmp API mismatch" })
    }

    @Test
    fun `clean observation stays clean`() {
        val result = probe.evaluate(
            ShellTmpObservation(
                parentAccessible = true,
                accessState = ShellTmpAccessState.ACCESSIBLE,
                javaExists = true,
                javaDirectory = true,
                javaCanRead = true,
                javaListable = true,
                dedicatedMounts = emptyList(),
            ),
        )

        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `java unreadable shell tmp stays clean on normal app baseline`() {
        val result = probe.evaluate(
            ShellTmpObservation(
                parentAccessible = true,
                accessState = ShellTmpAccessState.ACCESSIBLE,
                javaExists = true,
                javaDirectory = true,
                javaCanRead = false,
                javaListable = false,
                dedicatedMounts = emptyList(),
            ),
        )

        assertTrue(result.findings.isEmpty())
    }
}
