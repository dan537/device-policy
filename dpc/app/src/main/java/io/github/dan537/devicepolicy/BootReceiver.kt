package io.github.dan537.devicepolicy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Re-asserts policy on boot, and after this app updates itself.
 *
 * The user restrictions are held by the platform and survive reboots without
 * us, so the boot case is partly belt-and-braces; what it genuinely covers is
 * re-scheduling the worker and retrying Private DNS, which fails at
 * provisioning time if the network is not up yet.
 *
 * MY_PACKAGE_REPLACED is the important one. Installing an updated APK kills the
 * process and cancels the scheduled worker, and because this app has no
 * launcher activity there is nothing to tap to bring it back. Without handling
 * this, a sideloaded policy update would sit inert until the next reboot —
 * and sideloading a signed update is the only non-destructive way to change
 * policy once the grace period has closed. Verified on the emulator: after
 * `adb install -r`, no policy ran at all until this was added.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                // Local policy is safe on the main thread and applies instantly;
                // Private DNS needs a background thread, so the worker does it.
                PolicyEngine.applyLocal(context)
                PolicyEngine.applyDeferredIfDue(context)
                PolicyWorker.schedule(context)
                PolicyWorker.runOnce(context)
            }
        }
    }
}
