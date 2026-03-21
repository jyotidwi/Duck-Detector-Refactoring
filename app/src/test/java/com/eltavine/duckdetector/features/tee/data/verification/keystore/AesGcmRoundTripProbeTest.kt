package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.os.Build
import android.security.keystore.KeyProperties
import org.junit.Assert.assertEquals
import org.junit.Test

class AesGcmRoundTripProbeTest {

    @Test
    fun `security level label maps trusted environment on android s and above`() {
        assertEquals(
            "TEE",
            keyInfoSecurityLevelLabel(
                sdkInt = Build.VERSION_CODES.S,
                securityLevel = KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                insideSecureHardware = true,
            ),
        )
    }

    @Test
    fun `security level label falls back to secure hardware before android s`() {
        assertEquals(
            "SecureHardware",
            keyInfoSecurityLevelLabel(
                sdkInt = Build.VERSION_CODES.R,
                securityLevel = null,
                insideSecureHardware = true,
            ),
        )
    }

    @Test
    fun `security level label treats unknown secure as secure hardware`() {
        assertEquals(
            "SecureHardware",
            keyInfoSecurityLevelLabel(
                sdkInt = Build.VERSION_CODES.S,
                securityLevel = KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE,
                insideSecureHardware = true,
            ),
        )
    }

    @Test
    fun `security level label reports software when key is not hardware backed`() {
        assertEquals(
            "Software",
            keyInfoSecurityLevelLabel(
                sdkInt = Build.VERSION_CODES.R,
                securityLevel = null,
                insideSecureHardware = false,
            ),
        )
    }
}
