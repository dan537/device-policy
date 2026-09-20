"""Generate the Android Enterprise QR-enrollment payload and PNG.

Run:  python scripts/make-qr.py
Writes: dist/provisioning-qr.png  and prints the JSON payload.
The QR is scanned on the phone's welcome screen after factory reset
(6 taps on the welcome text opens the QR scanner).
"""
import json
import qrcode

# SHA-256 of the signing certificate (apksigner verify --print-certs),
# re-encoded as URL-safe base64: + -> - , / -> _
CERT_SHA256_URLSAFE_B64 = "GUnX3VnNkM57a-krAsRG3zPEMe1TrBw1tOgYYEZ3Ne8="

payload = {
    "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME":
        "io.github.dan537.devicepolicy/.AdminReceiver",
    "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM":
        CERT_SHA256_URLSAFE_B64,
    "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_URL":
        "https://raw.githubusercontent.com/dan537/device-policy/main/dist/app-release.apk",
    "android.app.extra.PROVISIONING_SKIP_ENCRYPTION": True,
    "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED": True,
    "android.app.extra.PROVISIONING_LOCALE": "en_GB",
    "android.app.extra.PROVISIONING_TIME_ZONE": "Europe/London",
}

data = json.dumps(payload, separators=(",", ":"))
print(data)
print(f"payload bytes: {len(data)}")

img = qrcode.make(data, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
img.save("dist/provisioning-qr.png")
print("wrote dist/provisioning-qr.png")
