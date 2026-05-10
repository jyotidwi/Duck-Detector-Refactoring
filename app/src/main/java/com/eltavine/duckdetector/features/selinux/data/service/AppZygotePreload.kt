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

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityBridge
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValidityPayloadCodec
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot

class AppZygotePreload : ZygotePreload {

    override fun doPreload(p0: ApplicationInfo) {
        val contextBridge = SelinuxContextValidityBridge()
        val nativeSnapshot = if (SelinuxContextValidityBridge.isNativeLibraryLoaded) {
            runCatching {
                contextBridge.parse(
                    SelinuxContextValidityBridge.nativeCollectContextValiditySnapshot(),
                )
            }.getOrElse { throwable ->
                SelinuxContextValiditySnapshot(
                    failureReason = throwable.message ?: "SELinux carrier probe failed.",
                    notes = listOf("SELinux native context validity probe failed to preload."),
                )
            }
        } else {
            SelinuxContextValiditySnapshot(
                failureReason = "SELinux native library unavailable.",
                notes = listOf("SELinux native context validity probe could not preload."),
            )
        }

        val dirtyPolicySnapshot = SelinuxDirtyPolicyCollector.collect(expectedUid = p0.uid)
        val mergedSnapshot = nativeSnapshot.copy(
            dirtyPolicyAvailable = dirtyPolicySnapshot.available,
            dirtyPolicyProbeAttempted = dirtyPolicySnapshot.probeAttempted,
            dirtyPolicyCarrierContext = dirtyPolicySnapshot.carrierContext,
            dirtyPolicyCarrierMatchesExpected = dirtyPolicySnapshot.carrierMatchesExpected,
            dirtyPolicyControlsPassed = dirtyPolicySnapshot.controlsPassed,
            dirtyPolicyStable = dirtyPolicySnapshot.stable,
            dirtyPolicyQueryMethod = dirtyPolicySnapshot.queryMethod,
            dirtyPolicyAccessControlAllowed = dirtyPolicySnapshot.accessControlAllowed,
            dirtyPolicyNegativeControlRejected = dirtyPolicySnapshot.negativeControlRejected,
            dirtyPolicySystemServerExecmemAllowed = dirtyPolicySnapshot.systemServerExecmemAllowed,
            dirtyPolicyMagiskBinderCallAllowed = dirtyPolicySnapshot.magiskBinderCallAllowed,
            dirtyPolicyKsuBinderCallAllowed = dirtyPolicySnapshot.ksuBinderCallAllowed,
            dirtyPolicyLsposedFileReadAllowed = dirtyPolicySnapshot.lsposedFileReadAllowed,
            dirtyPolicyFailureReason = dirtyPolicySnapshot.failureReason,
            dirtyPolicyNotes = dirtyPolicySnapshot.notes,
        )
        SelinuxContextValidityBridge.setPreloadedRawData(
            SelinuxContextValidityPayloadCodec.encode(mergedSnapshot),
        )
    }
}
