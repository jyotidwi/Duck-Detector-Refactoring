package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditEvidence
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxCardModelMapperTest {

    private val mapper = SelinuxCardModelMapper()

    @Test
    fun `audit exposure maps to warning instead of root claim`() {
        val model = mapper.map(
            SelinuxReport(
                stage = SelinuxStage.READY,
                mode = SelinuxMode.ENFORCING,
                resolvedStatusLabel = "Enforcing",
                filesystemMounted = true,
                paradoxDetected = false,
                methods = emptyList(),
                processContext = "u:r:untrusted_app:s0:c1,c2",
                contextType = "untrusted_app",
                policyAnalysis = null,
                auditIntegrity = SelinuxAuditIntegrityAnalysis(
                    state = SelinuxAuditIntegrityState.EXPOSED,
                    residueHits = emptyList(),
                    runtimeHits = emptyList(),
                    sideChannelHits = listOf(
                        SelinuxAuditEvidence(
                            label = "AVC denial leak",
                            value = "comm=su",
                            detail = "avc: denied ...",
                        ),
                    ),
                    logcatChecked = true,
                    notes = listOf(
                        "Recent log buffers exposed readable SELinux AVC denial lines. Treat this as audit side-channel leakage, not direct root-process proof.",
                    ),
                ),
                androidVersion = "15",
                apiLevel = 35,
            ),
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Enforcing with audit exposure", model.verdict)
        assertTrue(model.auditRows.any { it.label == "AVC side-channel" && it.value == "1 hit(s)" })
        assertTrue(model.auditNotes.any { it.text.contains("not direct root-process proof") })
    }
}
