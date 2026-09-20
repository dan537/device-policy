// Verification-only scratch project. NOT part of the shipped policy.
//
// Exists to test the browser-detection heuristic in PolicyEngine.discoverBrowsers()
// in both directions:
//
//   :fakebrowser  - hostless http/https filter, like a real browser -> MUST be suspended
//   :deeplinkapp  - host-specific filter, like a banking app        -> MUST NOT be suspended
//
// The second case matters more than the first. A heuristic that over-matches
// would suspend ordinary apps on a device whose policy cannot be removed.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "policy-testapps"
include(":fakebrowser", ":deeplinkapp")
