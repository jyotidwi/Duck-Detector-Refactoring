package com.eltavine.duckdetector.features.selinux.domain

enum class SelinuxAuditIntegrityState {
    CLEAR,
    RESIDUE,
    EXPOSED,
    TAMPERED,
    INCONCLUSIVE,
}

data class SelinuxAuditEvidence(
    val label: String,
    val value: String,
    val detail: String? = null,
    val strongSignal: Boolean = false,
)

data class SelinuxAuditIntegrityAnalysis(
    val state: SelinuxAuditIntegrityState,
    val residueHits: List<SelinuxAuditEvidence>,
    val runtimeHits: List<SelinuxAuditEvidence>,
    val sideChannelHits: List<SelinuxAuditEvidence>,
    val logcatChecked: Boolean,
    val notes: List<String>,
)
