package io.github.dan537.devicepolicy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Best-effort immediate reaction to a newly installed app, so a browser
 * downloaded from Play gets suspended straight away rather than at the next
 * sweep.
 *
 * This is explicitly NOT the guarantee. Manifest-declared receivers for
 * PACKAGE_ADDED are subject to the background broadcast restrictions and
 * delivery varies by OEM and Android version. [PolicyWorker] is the guarantee;
 * worst case a new browser is usable until the next 15-minute pass. Verify the
 * real behaviour on device rather than assuming this fires.
 */
class PackageWatcher : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED,
            Intent.ACTION_PACKAGE_REPLACED,
            Intent.ACTION_PACKAGE_CHANGED -> {
                // Suspend immediately rather than waiting on the worker — a new
                // browser being usable for even a minute defeats the point.
                PolicyEngine.applyLocal(context)
                PolicyWorker.runOnce(context)
            }
        }
    }
}
