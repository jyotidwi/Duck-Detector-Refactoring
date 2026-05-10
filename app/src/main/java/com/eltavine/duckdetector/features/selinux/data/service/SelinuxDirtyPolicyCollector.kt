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

package com.eltavine.duckdetector.features.selinux.data.service

import android.system.Os
import org.lsposed.hiddenapibypass.HiddenApiBypass

private const val DIRTY_POLICY_QUERY_METHOD = "SELinux.checkSELinuxAccess"

internal data class SelinuxDirtyPolicySnapshot(
    val available: Boolean = false,
    val probeAttempted: Boolean = false,
    val carrierContext: String? = null,
    val carrierMatchesExpected: Boolean = false,
    val accessControlAllowed: Boolean? = null,
    val negativeControlRejected: Boolean? = null,
    val systemServerExecmemAllowed: Boolean? = null,
    val magiskBinderCallAllowed: Boolean? = null,
    val ksuBinderCallAllowed: Boolean? = null,
    val lsposedFileReadAllowed: Boolean? = null,
    val controlsPassed: Boolean = false,
    val stable: Boolean = false,
    val queryMethod: String = DIRTY_POLICY_QUERY_METHOD,
    val failureReason: String? = null,
    val notes: List<String> = emptyList(),
)

internal object SelinuxDirtyPolicyCollector {
    fun collect(expectedUid: Int? = null): SelinuxDirtyPolicySnapshot {
        return runCatching {
            collectInternal(expectedUid)
        }.getOrElse { throwable ->
            SelinuxDirtyPolicySnapshot(
                failureReason = throwable.message ?: "Dirty SELinux policy probe failed.",
            )
        }
    }

    private fun collectInternal(expectedUid: Int?): SelinuxDirtyPolicySnapshot {
        runCatching { HiddenApiBypass.addHiddenApiExemptions("") }

        val api = ReflectionSelinuxApi()
        if (!api.isEnabled()) {
            return failure("SELinux is disabled.")
        }
        if (!api.isEnforced()) {
            return failure("SELinux is permissive.")
        }

        val carrierContext = api.getContext()?.trim().orEmpty()
        if (carrierContext.isBlank()) {
            return failure("Current process SELinux context unreadable.")
        }

        if (expectedUid != null && Os.getuid() != expectedUid) {
            return failure("UID mismatch: ${Os.getuid()} != app uid $expectedUid")
        }

        val carrierMatchesExpected = carrierContext.startsWith(EXPECTED_CARRIER_PREFIX)
        if (!carrierMatchesExpected) {
            return failure("Carrier context is not app_zygote.")
        }

        val pidContext = api.getPidContext(Os.getpid())?.trim().orEmpty()
        if (pidContext != carrierContext) {
            return failure("PID context mismatch: $pidContext")
        }

        val procContext = api.getFileContext("/proc/self")?.trim().orEmpty()
        if (procContext != carrierContext) {
            return failure("/proc/self context mismatch: $procContext")
        }

        val accessControl = repeatCheck(
            api = api,
            sourceContext = APP_ZYGOTE_CONTEXT,
            targetContext = ISOLATED_APP_CONTEXT,
            className = "process",
            permission = "dyntransition",
        )
        val negativeControl = repeatCheck(
            api = api,
            sourceContext = "u:r:untrusted_app:s0",
            targetContext = "u:object_r:duckdetector_dirty_policy_sentinel:s0",
            className = "file",
            permission = "read",
        )

        if (!accessControl.stable || !negativeControl.stable) {
            return SelinuxDirtyPolicySnapshot(
                available = true,
                probeAttempted = true,
                carrierContext = carrierContext,
                carrierMatchesExpected = carrierMatchesExpected,
                accessControlAllowed = accessControl.value,
                negativeControlRejected = negativeControl.value?.not(),
                controlsPassed = false,
                stable = false,
                queryMethod = DIRTY_POLICY_QUERY_METHOD,
                failureReason = "Dirty policy oracle self-test failed.",
                notes = buildList {
                    add("Carrier context: $carrierContext")
                    add("Expected carrier type: app_zygote")
                    add("Positive control stable=${accessControl.stable} value=${accessControl.value}")
                    add("Negative control stable=${negativeControl.stable} value=${negativeControl.value}")
                    add("The SELinux access oracle was not trusted because its controls were unstable.")
                },
            )
        }

        if (accessControl.value != true || negativeControl.value == true) {
            return SelinuxDirtyPolicySnapshot(
                available = true,
                probeAttempted = true,
                carrierContext = carrierContext,
                carrierMatchesExpected = carrierMatchesExpected,
                accessControlAllowed = accessControl.value,
                negativeControlRejected = negativeControl.value?.not(),
                controlsPassed = false,
                stable = true,
                queryMethod = DIRTY_POLICY_QUERY_METHOD,
                failureReason = "Dirty policy oracle self-test failed.",
                notes = buildList {
                    add("Carrier context: $carrierContext")
                    add("Expected carrier type: app_zygote")
                    add("Positive control accepted=${accessControl.value}")
                    add("Negative control rejected=${negativeControl.value?.not()}")
                    add("The SELinux access oracle did not pass its self-test.")
                },
            )
        }

        val systemServerExecmem = repeatCheck(
            api = api,
            sourceContext = "u:r:system_server:s0",
            targetContext = "u:r:system_server:s0",
            className = "process",
            permission = "execmem",
        )
        val magiskBinderCall = repeatCheck(
            api = api,
            sourceContext = "u:r:untrusted_app:s0",
            targetContext = "u:r:magisk:s0",
            className = "binder",
            permission = "call",
        )
        val ksuBinderCall = repeatCheck(
            api = api,
            sourceContext = "u:r:untrusted_app:s0",
            targetContext = "u:r:ksu:s0",
            className = "binder",
            permission = "call",
        )
        val lsposedFileRead = repeatCheck(
            api = api,
            sourceContext = "u:r:untrusted_app:s0",
            targetContext = "u:object_r:lsposed_file:s0",
            className = "file",
            permission = "read",
        )

        val controlsPassed = true
        val stable = systemServerExecmem.stable &&
            magiskBinderCall.stable &&
            ksuBinderCall.stable &&
            lsposedFileRead.stable

        val notes = buildList {
            add("Carrier context: $carrierContext")
            add("Expected carrier type: app_zygote")
            add("Query method: $DIRTY_POLICY_QUERY_METHOD")
            add("Positive control accepted=${accessControl.value}")
            add("Negative control rejected=${negativeControl.value?.not()}")
            add("system_server execmem=${systemServerExecmem.value}")
            add("Magisk binder call=${magiskBinderCall.value}")
            add("KernelSU binder call=${ksuBinderCall.value}")
            add("LSPosed file read=${lsposedFileRead.value}")
            if (!stable) {
                add("One or more dirty policy queries were unstable across repeated checks.")
            }
        }

        if (!stable) {
            return SelinuxDirtyPolicySnapshot(
                available = true,
                probeAttempted = true,
                carrierContext = carrierContext,
                carrierMatchesExpected = carrierMatchesExpected,
                accessControlAllowed = accessControl.value,
                negativeControlRejected = negativeControl.value?.not(),
                controlsPassed = controlsPassed,
                stable = false,
                queryMethod = DIRTY_POLICY_QUERY_METHOD,
                failureReason = "Dirty policy oracle repeatability failed.",
                notes = notes,
            )
        }

        return SelinuxDirtyPolicySnapshot(
            available = true,
            probeAttempted = true,
            carrierContext = carrierContext,
            carrierMatchesExpected = carrierMatchesExpected,
            accessControlAllowed = accessControl.value,
            negativeControlRejected = negativeControl.value?.not(),
            systemServerExecmemAllowed = systemServerExecmem.value,
            magiskBinderCallAllowed = magiskBinderCall.value,
            ksuBinderCallAllowed = ksuBinderCall.value,
            lsposedFileReadAllowed = lsposedFileRead.value,
            controlsPassed = controlsPassed,
            stable = stable,
            queryMethod = DIRTY_POLICY_QUERY_METHOD,
            notes = notes,
        )
    }

    private fun failure(message: String): SelinuxDirtyPolicySnapshot {
        return SelinuxDirtyPolicySnapshot(
            failureReason = message,
            notes = listOf(message),
        )
    }

    private fun repeatCheck(
        api: ReflectionSelinuxApi,
        sourceContext: String,
        targetContext: String,
        className: String,
        permission: String,
    ): StableAccessCheck {
        val first = api.checkAccess(sourceContext, targetContext, className, permission)
        val second = api.checkAccess(sourceContext, targetContext, className, permission)
        return StableAccessCheck(
            value = if (first == second) first else null,
            stable = first == second,
        )
    }

    private data class StableAccessCheck(
        val value: Boolean?,
        val stable: Boolean,
    )

    private class ReflectionSelinuxApi {
        private val selinuxClass: Class<*> = Class.forName("android.os.SELinux")

        fun isEnabled(): Boolean {
            return invokeBoolean("isSELinuxEnabled")
        }

        fun isEnforced(): Boolean {
            return invokeBoolean("isSELinuxEnforced")
        }

        fun getContext(): String? {
            return invokeString("getContext")
        }

        fun getPidContext(pid: Int): String? {
            return invokeString(
                methodName = "getPidContext",
                parameterTypes = arrayOf(Int::class.javaPrimitiveType!!),
                args = arrayOf<Any?>(pid),
            )
        }

        fun getFileContext(path: String): String? {
            return invokeString(
                methodName = "getFileContext",
                parameterTypes = arrayOf(String::class.java),
                args = arrayOf<Any?>(path),
            )
        }

        fun checkAccess(
            sourceContext: String,
            targetContext: String,
            className: String,
            permission: String,
        ): Boolean {
            return invokeBoolean(
                methodName = "checkSELinuxAccess",
                parameterTypes = arrayOf(
                    String::class.java,
                    String::class.java,
                    String::class.java,
                    String::class.java,
                ),
                args = arrayOf<Any?>(sourceContext, targetContext, className, permission),
            )
        }

        private fun invokeBoolean(methodName: String): Boolean {
            return selinuxClass.getMethod(methodName).invoke(null) as Boolean
        }

        private fun invokeBoolean(
            methodName: String,
            parameterTypes: Array<out Class<*>>,
            args: Array<out Any?>,
        ): Boolean {
            return selinuxClass.getMethod(methodName, *parameterTypes).invoke(null, *args) as Boolean
        }

        private fun invokeString(methodName: String): String? {
            return selinuxClass.getMethod(methodName).invoke(null) as? String
        }

        private fun invokeString(
            methodName: String,
            parameterTypes: Array<out Class<*>>,
            args: Array<out Any?>,
        ): String? {
            return selinuxClass.getMethod(methodName, *parameterTypes).invoke(null, *args) as? String
        }
    }

    private const val EXPECTED_CARRIER_PREFIX = "u:r:app_zygote:s0"
    private const val APP_ZYGOTE_CONTEXT = "u:r:app_zygote:s0"
    private const val ISOLATED_APP_CONTEXT = "u:r:isolated_app:s0"
}
