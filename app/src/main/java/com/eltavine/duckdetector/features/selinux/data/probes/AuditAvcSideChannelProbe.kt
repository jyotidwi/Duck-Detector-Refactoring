package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditEvidence

data class AuditAvcSideChannelProbeResult(
    val hits: List<SelinuxAuditEvidence>,
)

class AuditAvcSideChannelProbe {

    fun evaluate(
        output: String,
    ): AuditAvcSideChannelProbeResult {
        if (output.isBlank()) {
            return AuditAvcSideChannelProbeResult(hits = emptyList())
        }

        val hits = output.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .filter(::looksLikeForeignAvcLeak)
            .distinct()
            .take(MAX_HITS)
            .map { line ->
                SelinuxAuditEvidence(
                    label = "AVC denial leak",
                    value = extractValue(line),
                    detail = line.trimToPreview(),
                    strongSignal = false,
                )
            }
            .toList()

        return AuditAvcSideChannelProbeResult(hits = hits)
    }

    private fun looksLikeForeignAvcLeak(
        line: String,
    ): Boolean {
        val normalized = line.lowercase()
        if ("avc:" !in normalized || "denied" !in normalized) {
            return false
        }
        if (
            "scontext=" !in normalized &&
            "tcontext=" !in normalized &&
            "tclass=" !in normalized &&
            "permissive=" !in normalized &&
            "audit(" !in normalized
        ) {
            return false
        }
        if (
            normalized.contains("zn-auditpatch") ||
            normalized.contains("libauditpatch.so") ||
            normalized.contains("logd plt hook success")
        ) {
            return false
        }
        return true
    }

    private fun extractValue(
        line: String,
    ): String {
        extractGroup(line, COMM_REGEX)?.let { return "comm=$it" }
        extractGroup(line, SCONTEXT_REGEX)?.let { return "scontext=$it" }
        extractGroup(line, TCONTEXT_REGEX)?.let { return "tcontext=$it" }
        return "Readable"
    }

    private fun extractGroup(
        line: String,
        regex: Regex,
    ): String? = regex.find(line)?.groupValues?.getOrNull(1)

    private fun String.trimToPreview(
        maxLength: Int = 180,
    ): String {
        val normalized = replace(Regex("\\s+"), " ").trim()
        return if (normalized.length <= maxLength) {
            normalized
        } else {
            normalized.take(maxLength - 3).trimEnd() + "..."
        }
    }

    private companion object {
        private const val MAX_HITS = 3
        private val COMM_REGEX = Regex("comm=\"([^\"]+)\"", RegexOption.IGNORE_CASE)
        private val SCONTEXT_REGEX = Regex("""scontext=([^\s]+)""", RegexOption.IGNORE_CASE)
        private val TCONTEXT_REGEX = Regex("""tcontext=([^\s]+)""", RegexOption.IGNORE_CASE)
    }
}
