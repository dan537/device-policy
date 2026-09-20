package io.github.dan537.devicepolicy

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Device admin entry point. Referenced by name in the QR enrollment payload as
 * io.github.dan537.devicepolicy/io.github.dan537.devicepolicy.AdminReceiver
 *
 * The manifest deliberately does NOT declare android:testOnly. A non-test
 * device owner cannot be removed by `adb shell dpm remove-active-admin`
 * (the platform throws "Attempt to remove non-test admin"), which is what
 * makes the lock real.
 */
class AdminReceiver : DeviceAdminReceiver() {

    // applyLocal() here, not apply(): this runs on the main thread and the
    // Private DNS call does blocking network I/O. The worker picks that up.

    override fun onEnabled(context: Context, intent: Intent) {
        Log.i(TAG, "Device admin enabled.")
        PolicyEngine.applyLocal(context)
        PolicyWorker.schedule(context)
        PolicyWorker.runOnce(context)
    }

    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        Log.i(TAG, "Provisioning complete; applying policy.")
        PolicyEngine.applyLocal(context)
        PolicyWorker.schedule(context)
        PolicyWorker.runOnce(context)
    }

    companion object {
        private const val TAG = "DevicePolicy"
    }
}
