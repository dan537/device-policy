// Versions pinned one release behind the newest available, on purpose:
// brand-new releases have not been vetted and a meaningful share of supply
// chain problems are caught and yanked within days of publication.
// AGP 9.0+ ships Kotlin support built in; applying org.jetbrains.kotlin.android
// alongside it is an error.
plugins {
    id("com.android.application") version "9.3.2" apply false
}
