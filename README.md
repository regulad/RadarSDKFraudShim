# Radar iOS `compromised` bypass

## The finding in one paragraph

On Android, Radar's `compromised` signal is anchored by Play Integrity's hardware-backed **STRONG** verdict, which reflects verified boot — rooting a device generally breaks it. On iOS there is no equivalent. **App Attest attests app identity + integrity (unmodified on-disk binary + genuine Apple hardware); it does not attest jailbreak/boot state.** Radar therefore gathers `compromised_jailbroken` from ordinary in-process checks (file paths, `canOpenURL:`, a `fork()` sandbox test, a `dlopen`/dyld injected-library scan). On a jailbroken device that process is attacker-controlled, so those checks can be forged **without modifying the binary, Team ID, or bundle ID** — which means App Attest still succeeds and `trackVerified()` returns a **server-accepted JWT carrying a false `compromised = false`.** That asymmetry (iOS weaker than Android) is the disclosable weakness.

## Why we override the verdict function, not the payload

The fraud payload is bound into the App Attest `clientDataHash`. Editing the payload *after* it's built breaks the binding and the server rejects the token. So the PoC overrides the one function that produces the verdict — `FraudDetection.isJailbroken()` — which runs **upstream** of payload assembly and attestation. The genuine SDK then builds an already-clean payload and attests over *that*. The result is a **valid attestation over a false signal** — which is the whole point. (Overriding the function instead of the underlying `stat`/`fopen`/`canOpenURL:`/`fork`/dyld primitives is also version-robust: Radar can reshuffle the primitive checks freely, but the verdict still funnels through this one symbol.)

## Run

```bash
# On regulad-fedora (WSL), from poc/tweak:
make package install THEOS_DEVICE_IP=<ipad-ip>
```

Launch the harness, trigger `trackVerified()`, and watch the device log (Console.app / `idevicesyslog` / `oslog`):

```
[RadarSDKFraudShim] isJailbroken() -> forced FALSE
[RadarSDKFraudShim] fraud result (attested as-is) => { ... jailbroken = 0; ... }
```

## Prove the token is actually accepted (this is the real evidence)

A false local boolean means nothing unless the **server** accepts the JWT. Validate it exactly as your backend would:

```js
// verify.js  ->  node verify.js "<jwt-from-harness>"
import jwt from 'jsonwebtoken';
const token = process.argv[2];
const secret = process.env.RADAR_JWT_SECRET;            // Settings -> Fraud
const decoded = jwt.verify(token, secret);              // throws if signature/binding invalid
console.log('signature: VALID');
console.log('passed:      ', decoded.passed);
console.log('compromised: ', decoded.user?.fraud?.compromised);
console.log('full payload:', JSON.stringify(decoded, null, 2));
```

## What this does NOT claim (keep the report honest)

- It does not forge App Attest or defeat the Secure Enclave. It shows App Attest is the wrong tool to carry a jailbreak verdict.
- If Radar's **server** cross-checks something App Attest *can* see that instrumentation perturbs, some runs may fail — capture those; the delta is itself useful signal for them.
- The `mocked_*` (CoreLocation `sourceInformation`) and `sharing_*` signals are out of scope here.

## The tweak

A single Theos/ElleKit tweak, persistent:

- `Tweak.x` — finds the `RadarSDKFraud` image via `_dyld_get_image_header` (works because `__TEXT` vmaddr is 0), then **resolves `FraudDetection.isJailbroken()` by walking the image's `LC_SYMTAB` at runtime** for the mangled name (`…12isJailbroken…`) and `MSHookFunction`s every matching body/thunk to return `false`. No hardcoded offset and no dSYM needed on the device, so it reproduces across SDK versions as long as symbols aren't stripped. A read-only `MSHookMessageEx` on `-[RadarSDKFraud getFraudPayloadWithOptions:completionHandler:]` logs the payload that gets attested. Both installers are idempotent and re-driven from `_dyld_register_func_for_add_image`, so they fire the instant RadarSDKFraud maps — at launch **or later**.

### Injection & scoping

The filter (`RadarSDKFraudShim.plist`) injects into **every UIKit app**, not a specific bundle id, and all work is gated in-process on RadarSDKFraud being present. This is deliberate:

- Triage's harness bundle id is unknown, so we can't filter on it.
- A `Classes: [RadarSDKFraud]` filter is evaluated **once, at injection time**; if RadarSDKFraud is loaded *after* launch (dynamically, or as a lazily-pulled sub-framework) the filter's pass has already happened and the tweak is **never injected** — its `%ctor`/callbacks never run. Broad-inject + in-process gate avoids that entirely.

Trade-off: the tweak is resident in every app but **inert** unless that process loads RadarSDKFraud — in which case it *will* force the verdict there. So run this on a **dedicated jailbroken test device**, not a daily driver, since it would silence the `compromised` signal in any Radar-fraud app on that device.

### Debug diagnostics (non-`FINALPACKAGE` builds only)

Because the tweak injects broadly but only *acts* where RadarSDKFraud is present, a debug build (anything not built with `FINALPACKAGE=1`) emits — gated by `-DRADAR_DIAG=1`, added automatically by the Makefile — logging to confirm injection and watch for the framework, even in processes where it never activates:

- On load in **every** injected process: `loaded into '<proc>' (bundle …, pid …)`, then a one-time snapshot listing every `*.framework` already mapped and a `RadarSDKFraud=… RadarSDK=…` presence line.
- On each framework mapped **after** launch (lazy load / `dlopen` / sub-framework): `new framework loaded: <path>`, re-reporting Radar presence when it's one of Radar's.

This is how you tell "the tweak isn't injecting" apart from "it's injecting but this app never loads Radar." A `FINALPACKAGE=1` package strips all of it; only the functional hook lines remain.

Notes:
- Wholesale replace (`MSHookFunction` returning `false`) skips the SDK's internal `fork()`/dyld checks entirely, so there's nothing for its in-function anti-tamper to notice.
- Resolution is build-aware. The symtab walk is tried first (works on unstripped/debug builds); release builds strip the local Swift symbol, so it falls back to a **verified offset keyed on the image's Mach-O `LC_UUID`** in the `kIsJailbrokenOffsets` table (`Tweak.x`). UUID — not version string — because the version string does not identify a build: every `0.0.x` beta reports `CFBundleShortVersionString "1.0"` (same as real 1.0.0) across four different offsets, and `1.3.0-beta.1` reports `"1.2.0"`. The `LC_UUID` is unique per build and readable at runtime. Offsets derived from each build's device `ios-arm64` dSYM (`__TEXT` vmaddr `0` on all):

  | build | UUID | symbol | offset |
  |---|---|---|---|
  | `1.3.0` | `2C0957F1-…1A51` | Swift `…Tf4d_n` | `0x4b18` |
  | `1.2.0` | `24EB49B1-…8D76` | Swift `…Tf4d_n` | `0xecf0` |
  | `1.1.0` | `371E795A-…FC3A` | Swift `…Tf4d_n` | `0x4b18` |
  | `1.0.0` | `CA4CC662-…996D` | Obj-C `-[RadarSDKFraud isJailbroken]` | `0x46bc` |
  | `1.3.0-beta.1` | `5455BDB7-…9B4C` | Swift `…Tf4d_n` | `0xde6c` |
  | `0.0.3-beta.1` | `24BA0720-…B976` | Obj-C | `0x46a0` |
  | `0.0.2-beta.7/8/9` | `386AF5F8-…8436` | Obj-C | `0x46a0` |
  | `0.0.2-beta.6` | `D301048D-…341E` | Obj-C | `0x4614` |
  | `0.0.1-beta.3..13 / 0.0.2-beta.5` | `405E51B6-…FA70` | Obj-C | `0x4584` |

  (`0.0.1-beta.1/2/5/7` ship no xcframework asset, so there's nothing to hook.) Through 1.0.0 the check is Obj-C `-[RadarSDKFraud isJailbroken]`; 1.1.0 refactored it to the Swift `FraudDetection.isJailbroken()` static. If the running build's UUID isn't in the table, the tweak logs the UUID + version and **refuses to hook** (leaving `jailbroken` true) rather than corrupting a guessed address. To add a build: from its `.xcframework` dSYM run `llvm-nm --defined-only .../ios-arm64/dSYMs/.../DWARF/RadarSDKFraud | grep -i isJailbroken` (take the `t` code symbol), confirm `__TEXT` vmaddr `0` and read `LC_UUID` via `llvm-objdump --macho --private-headers`, and add `{ "<uuid>", 0x<off>, "<label>" }`. The `tools/derive_offsets.sh` helper does this across every published release.
- ElleKit handles arm64e/PAC on the A12; the third-party harness itself runs arm64, so the arm64 slice does the hooking.
- roothide already hides many jailbreak *paths* from apps, so Radar's file-based checks may pass on their own — but the `isJailbroken()` override is what guarantees a `false` verdict against checks roothide doesn't mask (e.g. the `fork()` sandbox test, the dyld scan for the injected tweak). Overriding the verdict function is strictly more complete than relying on roothide's hiding.

## Suggested remediation to include for Radar

- Treat iOS `compromised` as **advisory**, not authoritative, and say so in the docs at the same strength as Android.
- Where a hardware anchor is required on iOS, there isn't a true jailbreak equivalent — so the honest guidance is defense-in-depth: server-side behavioral/impossible-travel checks, and never gating solely on `compromised`.
- Bind more instrumentation-sensitive evidence into the attested `clientDataHash`, and document the residual in-process trust assumption plainly.

## License

Licensed under the GNU Affero General Public License v3.0 — see [`LICENSE`](LICENSE) (verbatim FSF text).
