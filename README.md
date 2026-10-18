# apk-audit

What an APK actually talks to, without installing anything and without external tools.

One Node script, no dependencies. It opens the APK as a zip, decodes `AndroidManifest.xml`,
`classes*.dex`, `resources.arsc` and the native libraries, and prints:

- permissions from the manifest
- package ids found inside the app
- tracker / ad / Play Store markers (GMS, Firebase, Crashlytics, AdMob, Unity Ads, AppLovin,
  ironSource, AppsFlyer, Adjust, AppMetrica, Flurry, OneSignal, Play Billing, install referrer)
- every URL host the app mentions, sorted by count, with documentation links filtered out
- signing: v1 files present, v2/v3 signature block present

Written because `aapt`/`apktool` are a pain on old Windows and half the interesting questions
("does this APK phone home to Google Play?") can be answered from the raw bytes.

## Usage

```
node apk-scan.js <file.apk>
```

Windows without Node installed: drop a portable `node.exe` next to the script and run
`node.exe apk-scan.js app.apk`.

## Example

See [examples/sample-output.txt](examples/sample-output.txt) - a scan of the official RustDesk
arm64 build: two DEX files, four native libraries, zero tracker markers, and the only Google
host is a STUN server used for NAT traversal.

## What the output means

`playstore_refs: YES` appears when the APK references `com.android.vending`,
`play.google.com`, Play Core or the install referrer library. That is the marker for "this app
expects the Play Store", and for a repacked build it is worth checking against the declared
package name and the signing certificate.

`com/google/android/gms : 2863` is not automatically bad: it counts occurrences of the string,
so one bundled Play Games / ads library shows up thousands of times. Read it as "which SDKs are
in here", not as "which SDKs are active".

Names such as `sentry` can be false positives: `std::__ndk1::sentry` from libc++ is not the
Sentry crash reporter.

## Limits

Static analysis only. It does not run the app, does not decompile code, and does not resolve
dynamic network calls. For anything beyond that, run the APK in an emulator with a proxy.

## Work with me

APK inspections, Windows/legacy rescue, remote access setups, AutoCAD automation.
Telegram: @Arsenum

## License

MIT.
