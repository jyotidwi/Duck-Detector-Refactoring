package com.eltavine.duckdetector.ui.shell

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScreenCaptureNoticeDialogTest {

    @Test
    fun `screen capture callback requires api 34`() {
        assertFalse(supportsScreenCaptureCallback(33))
        assertTrue(supportsScreenCaptureCallback(34))
        assertTrue(supportsScreenCaptureCallback(36))
    }
}
