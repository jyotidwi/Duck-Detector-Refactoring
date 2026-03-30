package com.eltavine.duckdetector.ui.shell

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import kotlinx.coroutines.delay

internal const val SCREEN_CAPTURE_NOTICE_MESSAGE =
    "If the screenshot does not contain detailed information, this issue will not be handled."

internal const val SCREEN_CAPTURE_NOTICE_LOCK_SECONDS = 3

internal fun supportsScreenCaptureCallback(apiLevel: Int): Boolean = apiLevel >= 34

@Composable
fun ScreenCaptureNoticeEffect(
    onScreenCaptured: () -> Unit,
) {
    val context = LocalContext.current
    val activity = remember(context) { context.findActivity() }
    val currentOnScreenCaptured = rememberUpdatedState(onScreenCaptured)

    if (activity == null || !supportsScreenCaptureCallback(Build.VERSION.SDK_INT)) {
        return
    }

    ScreenCaptureCallbackRegistration(
        activity = activity,
        onScreenCaptured = {
            currentOnScreenCaptured.value()
        },
    )
}

@RequiresApi(34)
@Composable
private fun ScreenCaptureCallbackRegistration(
    activity: Activity,
    onScreenCaptured: () -> Unit,
) {
    val currentOnScreenCaptured = rememberUpdatedState(onScreenCaptured)

    DisposableEffect(activity) {
        val callback = Activity.ScreenCaptureCallback {
            currentOnScreenCaptured.value()
        }
        activity.registerScreenCaptureCallback(
            ContextCompat.getMainExecutor(activity),
            callback,
        )
        onDispose {
            activity.unregisterScreenCaptureCallback(callback)
        }
    }
}

@Composable
fun ScreenCaptureNoticeDialog(
    noticeInstanceKey: Long,
    onDismiss: () -> Unit,
) {
    var secondsRemaining by rememberSaveable(noticeInstanceKey) {
        mutableIntStateOf(SCREEN_CAPTURE_NOTICE_LOCK_SECONDS)
    }
    val canDismiss = secondsRemaining == 0

    LaunchedEffect(noticeInstanceKey) {
        secondsRemaining = SCREEN_CAPTURE_NOTICE_LOCK_SECONDS
        while (secondsRemaining > 0) {
            delay(1_000L)
            secondsRemaining -= 1
        }
    }

    AlertDialog(
        onDismissRequest = {
            if (canDismiss) {
                onDismiss()
            }
        },
        properties = DialogProperties(
            dismissOnBackPress = canDismiss,
            dismissOnClickOutside = canDismiss,
        ),
        title = {
            WrapSafeText(
                text = "Screenshot detected",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                WrapSafeText(
                    text = SCREEN_CAPTURE_NOTICE_MESSAGE,
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = onDismiss,
                enabled = canDismiss,
            ) {
                WrapSafeText(
                    text = if (canDismiss) {
                        "Continue"
                    } else {
                        "Continue (${secondsRemaining}s)"
                    },
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
    )
}

private tailrec fun Context.findActivity(): Activity? {
    return when (this) {
        is Activity -> this
        is ContextWrapper -> baseContext.findActivity()
        else -> null
    }
}
