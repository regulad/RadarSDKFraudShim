/*
 * RadarSDKFraudShim / Tweak.x
 * -------------------------------------------------------------------------
 * INJECTION MODEL (see RadarSDKFraudShim.plist):
 *   Because triage's harness bundle id is unknown AND a Classes filter misses a
 *   framework that loads after launch, we inject into every UIKit app and gate
 *   ALL work on RadarSDKFraud being present in-process. In any app that never
 *   loads RadarSDKFraud the tweak does nothing. NB: this means it WILL act in
 *   any Radar-fraud app on that device -> use a dedicated test device.
 *
 * Chokepoint (the finding, unchanged):
 *   static RadarSDKFraud.FraudDetection.isJailbroken() -> Swift.Bool
 *   mangled: $s13RadarSDKFraud14FraudDetectionC12isJailbrokenSbyFZ  (+ Tf4d_n thunk)
 *
 * It runs UPSTREAM of FraudPayload.init(...jailbroken:...attestationString:...)
 * and of the App Attest binding, so forcing it false yields a clean payload
 * attested as-is -> a server-accepted trackVerified() JWT carrying a false
 * jailbroken/compromised, while the binary / Team ID / bundle id are untouched
 * (App Attest still passes). That asymmetry vs. Android's Play Integrity STRONG
 * verdict is the finding.
 *
 * WHY WE DO NOT EDIT THE PAYLOAD IN getFraudPayloadWithOptions:
 *   The verdict is bound into the App Attest clientDataHash. That selector hands
 *   back the ALREADY-ASSEMBLED, ALREADY-ATTESTED payload, so editing it there
 *   breaks the binding and the server rejects the token. We keep that hook
 *   READ-ONLY (proof/logging) and force the verdict upstream instead.
 *
 * LATE-LOAD ROBUSTNESS:
 *   - The verdict override resolves isJailbroken() by walking the RadarSDKFraud
 *     image's LC_SYMTAB at runtime (mangled-name match), no offset/dSYM needed.
 *     It is driven purely by mach-o, so it works the instant the image maps.
 *   - The read-only payload log is installed via MSHookMessageEx (NOT a Logos
 *     ctor-time %hook), so it also installs only once the RadarSDKFraud class is
 *     registered -- surviving a framework that loads after launch.
 *   Both are (re)attempted from _dyld_register_func_for_add_image, so whenever
 *   RadarSDKFraud appears -- at launch or later -- the hooks go in.
 *   The pinned offset 0x4b18 (xcframework 1.3.0 arm64) remains ONLY as a
 *   last-resort fallback for a stripped symbol table.
 * -------------------------------------------------------------------------
 */

#import <substrate.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <objc/runtime.h>
#import <stdio.h>
#import <string.h>
#import <Foundation/Foundation.h>

static const char     *kFraudImageMatch         = "RadarSDKFraud";
// Swift length-prefixed identifier "isJailbroken" (12 chars). Present in the
// mangled symbol on every version we've seen; specific enough not to collide.
static const char     *kIsJailbrokenNeedle      = "12isJailbroken";

// Per-version verified isJailbroken offsets (from __TEXT+off, and __TEXT vmaddr
// is 0 so this is base+off at runtime). Release builds strip the local Swift
// symbol from the runtime symtab, so the symbol walk misses and we look the
// offset up by the framework's own CFBundleShortVersionString. Derive each entry
// from THAT version's dSYM (see README) -- we refuse to hook a version that isn't
// in this table rather than corrupt a wrong address.
// Keyed on the Mach-O LC_UUID of the device ios-arm64 slice, NOT the version
// string: every 0.0.x beta reports CFBundleShortVersionString "1.0" (like the
// real 1.0.0) and 1.3.0-beta.1 reports "1.2.0", so the version string cannot
// tell distinct builds apart -- but the UUID is unique per build and is readable
// at runtime from the loaded image. Offsets are __TEXT+off (segment vmaddr 0),
// derived from each release's dSYM; the `label` is just for logging.
typedef struct { const char *uuid; uintptr_t off; const char *label; } radar_off_t;
static const radar_off_t kIsJailbrokenOffsets[] = {
    // --- stable releases (Swift FraudDetection.isJailbroken() ...Tf4d_n) ---
    { "2C0957F1-1C7B-3854-82E0-D75F6CBF1A51", 0x4b18, "1.3.0" },
    { "24EB49B1-BDE3-31B3-87F5-90CB30DF8D76", 0xecf0, "1.2.0" },
    { "371E795A-8835-3679-9AC1-118BE21FFC3A", 0x4b18, "1.1.0" },
    // --- 1.0.0: Obj-C -[RadarSDKFraud isJailbroken] IMP ---
    { "CA4CC662-765A-350D-A740-DDC60627996D", 0x46bc, "1.0.0" },
    // --- pre-releases (UUID-keyed, since their version strings collide) ---
    { "5455BDB7-0773-319D-8E9D-FF9864AD9B4C", 0xde6c, "1.3.0-beta.1 (Swift Tf4d_n)" },
    { "24BA0720-20FD-31C1-9BCB-831623F8B976", 0x46a0, "0.0.3-beta.1 (Obj-C)" },
    { "386AF5F8-331C-31BF-B27E-A31F5E7E8436", 0x46a0, "0.0.2-beta.7/8/9 (Obj-C)" },
    { "D301048D-E0EE-3333-9F4E-575589F4341E", 0x4614, "0.0.2-beta.6 (Obj-C)" },
    { "405E51B6-9755-35CF-B58A-EC814E32FA70", 0x4584, "0.0.1-beta.3..13 / 0.0.2-beta.5 (Obj-C)" },
    // Betas 0.0.1-beta.1/2/5/7 ship no xcframework asset -> nothing to hook.
};

// ---- verdict override --------------------------------------------------------
// static () -> Bool. We ignore the Swift metatype self (context reg) and just
// return false in w0; the caller only reads the Bool. We never call orig.
static bool (*orig_isJailbroken)(void);
static bool hooked_isJailbroken(void) {
    NSLog(@"[RadarSDKFraudShim] isJailbroken() -> forced FALSE");
    return false;
}

// ---- read-only payload proof -------------------------------------------------
// -[RadarSDKFraud getFraudPayloadWithOptions:completionHandler:]
static void (*orig_getFraudPayload)(id, SEL, NSDictionary *, void (^)(NSDictionary *));
// READ-ONLY. Logs the shape of what getFraudPayloadWithOptions: returns so we can
// tell a plaintext qualifier dict (short string/number values) from an already-
// hashed / attestation blob (long base64/hex/NSData values). We never mutate it.
static void describe_payload(NSDictionary *result) {
    if (![result isKindOfClass:[NSDictionary class]]) {
        NSLog(@"[RadarSDKFraudShim] payload is %@, not a dictionary", [result class]);
        return;
    }
    NSMutableString *shape = [NSMutableString stringWithFormat:@"payload shape (%lu keys):",
                             (unsigned long)result.count];
    for (id key in result) {
        id v = result[key];
        NSString *type = NSStringFromClass([v class]);
        NSUInteger len = 0;
        if ([v isKindOfClass:[NSString class]]) len = [(NSString *)v length];
        else if ([v isKindOfClass:[NSData class]]) len = [(NSData *)v length];
        [shape appendFormat:@"\n    %@ : %@ (len=%lu)", key, type, (unsigned long)len];
    }
    NSLog(@"[RadarSDKFraudShim] %@", shape);
}

static void hooked_getFraudPayload(id self, SEL _cmd, NSDictionary *options,
                                   void (^completionHandler)(NSDictionary *)) {
    void (^wrapped)(NSDictionary *) = ^(NSDictionary *result) {
        NSLog(@"[RadarSDKFraudShim] fraud result (attested as-is) => %@", result);
        describe_payload(result); // read-only: key names, value types, byte-lengths
        if (completionHandler) completionHandler(result);
    };
    if (orig_getFraudPayload) orig_getFraudPayload(self, _cmd, options, wrapped);
}

// ---- image / symbol helpers --------------------------------------------------
static const struct mach_header *find_image_header(const char *needle, intptr_t *out_slide) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, needle)) {
            if (out_slide) *out_slide = _dyld_get_image_vmaddr_slide(i);
            return _dyld_get_image_header(i);
        }
    }
    return NULL;
}

typedef void (^sym_cb_t)(const char *name, uintptr_t runtime_addr);

// Walk LC_SYMTAB of an already-mapped 64-bit image, invoking cb for every
// defined-in-section function symbol whose name contains `needle`. Returns
// the number of matches. Standard __LINKEDIT file-offset -> memory mapping.
static int for_each_matching_symbol(const struct mach_header *mh, intptr_t slide,
                                    const char *needle, sym_cb_t cb) {
    if (!mh) return 0;
    if (mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64) return 0; // arm64/arm64e only

    const struct mach_header_64 *mh64 = (const struct mach_header_64 *)mh;
    const struct load_command *lc = (const struct load_command *)(mh64 + 1);

    const struct symtab_command *symtab = NULL;
    uintptr_t linkedit_vmaddr = 0;
    uint64_t  linkedit_fileoff = 0;
    bool have_linkedit = false;

    for (uint32_t i = 0; i < mh64->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, SEG_LINKEDIT) == 0) {
                linkedit_vmaddr  = (uintptr_t)seg->vmaddr;
                linkedit_fileoff = seg->fileoff;
                have_linkedit = true;
            }
        } else if (lc->cmd == LC_SYMTAB) {
            symtab = (const struct symtab_command *)lc;
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    if (!symtab || !have_linkedit) return 0;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_vmaddr - (uintptr_t)linkedit_fileoff;
    const struct nlist_64 *syms = (const struct nlist_64 *)(linkedit_base + symtab->symoff);
    const char *strs = (const char *)(linkedit_base + symtab->stroff);

    int matches = 0;
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        const struct nlist_64 *s = &syms[i];
        if (s->n_type & N_STAB) continue;              // debug (dSYM-style) entry
        if ((s->n_type & N_TYPE) != N_SECT) continue;  // must be defined in a section
        if (s->n_un.n_strx == 0) continue;
        const char *name = strs + s->n_un.n_strx;
        if (!name || !name[0]) continue;
        if (!strstr(name, needle)) continue;
        uintptr_t addr = (uintptr_t)s->n_value + (uintptr_t)slide; // __TEXT vmaddr 0 => n_value+slide
        if (!addr) continue;
        cb(name, addr);
        matches++;
    }
    return matches;
}

// ---- installers (idempotent, safe to call repeatedly) ------------------------
static bool g_fn_hooked      = false; // isJailbroken() verdict override (the bypass)
static bool g_fn_unavailable = false; // stripped symtab AND no verified offset -> give up (no retry spam)
static bool g_msg_hooked     = false; // read-only payload log (diagnostics only)

// Canonical uppercase LC_UUID ("XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX") of a
// mapped image, into a 37-byte buffer. This is our stable per-build key.
static bool image_uuid_string(const struct mach_header *mh, char out[37]) {
    if (!mh || (mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64)) return false;
    const struct mach_header_64 *mh64 = (const struct mach_header_64 *)mh;
    const struct load_command *lc = (const struct load_command *)(mh64 + 1);
    for (uint32_t i = 0; i < mh64->ncmds; i++) {
        if (lc->cmd == LC_UUID) {
            const uint8_t *u = ((const struct uuid_command *)lc)->uuid;
            snprintf(out, 37,
                "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                u[0],u[1],u[2],u[3], u[4],u[5], u[6],u[7], u[8],u[9],
                u[10],u[11],u[12],u[13],u[14],u[15]);
            return true;
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    return false;
}

static bool offset_for_uuid(const char *uuid, uintptr_t *out, const char **label) {
    for (size_t i = 0; i < sizeof(kIsJailbrokenOffsets) / sizeof(kIsJailbrokenOffsets[0]); i++) {
        if (strcmp(kIsJailbrokenOffsets[i].uuid, uuid) == 0) {
            *out = kIsJailbrokenOffsets[i].off;
            *label = kIsJailbrokenOffsets[i].label;
            return true;
        }
    }
    return false;
}

// CFBundleShortVersionString, only for the "unknown build" diagnostic message.
static NSString *radar_fraud_version(void) {
    Class c = objc_getClass(kFraudImageMatch);
    if (!c) return nil;
    return [NSBundle bundleForClass:c].infoDictionary[@"CFBundleShortVersionString"];
}

// Force the verdict false. Symtab-based, so it works the moment the image maps;
// needs no Obj-C. This is the part the finding depends on.
static void install_fn_hook(void) {
    if (g_fn_hooked || g_fn_unavailable) return;

    intptr_t slide = 0;
    const struct mach_header *mh = find_image_header(kFraudImageMatch, &slide);
    if (!mh) return; // RadarSDKFraud not in this process (yet)

    __block int hooked_count = 0;
    for_each_matching_symbol(mh, slide, kIsJailbrokenNeedle, ^(const char *name, uintptr_t addr) {
        void *target = (void *)addr;
        void *prev = NULL;
        MSHookFunction(target, (void *)hooked_isJailbroken, (void **)&prev);
        if (!orig_isJailbroken) orig_isJailbroken = (bool (*)(void))prev; // unused; we always return false
        hooked_count++;
        NSLog(@"[RadarSDKFraudShim] hooked %s @ %p", name, target);
    });

    if (hooked_count == 0) {
        // Symbol stripped from the runtime symtab: look up a VERIFIED offset by the
        // image's LC_UUID (stable per build). Never hook a guessed address.
        char uuid[37];
        if (!image_uuid_string(mh, uuid)) return; // no LC_UUID? bail (extremely unusual)

        uintptr_t off = 0;
        const char *label = NULL;
        if (offset_for_uuid(uuid, &off, &label)) {
            void *target = (void *)((uintptr_t)mh + off); // __TEXT vmaddr 0 => header IS the base
            MSHookFunction(target, (void *)hooked_isJailbroken, (void **)&orig_isJailbroken);
            hooked_count = 1;
            NSLog(@"[RadarSDKFraudShim] symtab stripped; matched RadarSDKFraud UUID %s (%s) -> offset 0x%lx @ %p",
                  uuid, label, (unsigned long)off, target);
        } else {
            g_fn_unavailable = true; // stop retrying; this is a config gap, not a timing one
            NSString *ver = radar_fraud_version();
            NSLog(@"[RadarSDKFraudShim] symtab stripped AND no verified offset for RadarSDKFraud UUID %s "
                  @"(CFBundleShortVersionString '%@'). NOT hooking a guessed address -- derive the offset from "
                  @"this build's dSYM and add { \"%s\", 0x<off>, ... } to kIsJailbrokenOffsets. "
                  @"(verdict will remain TRUE until then)", uuid, ver ?: @"?", uuid);
            return;
        }
    }

    g_fn_hooked = (hooked_count > 0);
    NSLog(@"[RadarSDKFraudShim] verdict override installed: %d hook(s); RadarSDKFraud base %p slide %p",
          hooked_count, (void *)mh, (void *)slide);
}

// Read-only payload logger. Needs the Obj-C class registered; on late load that
// happens shortly after the image maps, so we retry from the add-image callback.
static void install_msg_hook(void) {
    if (g_msg_hooked) return;

    Class cls = objc_getClass(kFraudImageMatch); // "RadarSDKFraud"
    if (!cls) return; // class not registered yet; retried on the next image load
    SEL sel = @selector(getFraudPayloadWithOptions:completionHandler:);
    if (!class_getInstanceMethod(cls, sel)) return; // selector absent on this version -> skip cleanly

    MSHookMessageEx(cls, sel, (IMP)hooked_getFraudPayload, (IMP *)&orig_getFraudPayload);
    g_msg_hooked = true;
    NSLog(@"[RadarSDKFraudShim] hooked -[RadarSDKFraud getFraudPayloadWithOptions:completionHandler:] (read-only)");
}

static void try_install(void) {
    install_fn_hook();   // the bypass (mach-o only)
    install_msg_hook();  // the proof log (needs the Obj-C class)
}

// ---- diagnostics (debug builds only; compiled out when FINALPACKAGE=1) --------
// Answers "did we even get injected here, and does this process load Radar?"
// The ctor logs a one-line presence check at launch; if a Radar framework is
// pulled in later (lazily / via dlopen / as a sub-framework), the add-image path
// reports just that. We deliberately do NOT enumerate every loaded library.
#ifdef RADAR_DIAG
static bool g_diag_live = false; // true after the launch-time image enumeration

static const char *diag_name_for_header(const struct mach_header *mh) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        if (_dyld_get_image_header(i) == mh) return _dyld_get_image_name(i);
    }
    return NULL;
}

// "RadarSDKFraud" is a substring of its own path; the base SDK's image path is
// .../RadarSDK.framework/RadarSDK, which does NOT contain "RadarSDKFraud", and
// "RadarSDK.framework" does NOT match "RadarSDKFraud.framework". So the two are
// distinguishable by these needles.
static void diag_report_radar_presence(void) {
    bool fraud = false, base = false;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "RadarSDKFraud"))           fraud = true;
        else if (strstr(nm, "RadarSDK.framework")) base  = true;
    }
    NSLog(@"[RadarSDKFraudShim][diag] Radar frameworks present: RadarSDKFraud=%s RadarSDK=%s",
          fraud ? "YES" : "no", base ? "YES" : "no");
}

// Fired for each image that maps AFTER launch (dynamic framework loads, dlopen).
// We only care whether a Radar framework just showed up -- not every dylib.
static void diag_on_image_added(const struct mach_header *mh) {
    const char *nm = diag_name_for_header(mh);
    if (!nm) return;
    if (strstr(nm, "RadarSDKFraud") || strstr(nm, "RadarSDK.framework")) {
        NSLog(@"[RadarSDKFraudShim][diag] Radar framework loaded late: %s", nm);
        diag_report_radar_presence();
    }
}
#endif

// Fires for every already-mapped image at registration, then for each new load.
// Cheap once both hooks are in (both installers early-return).
static void image_added(const struct mach_header *mh, intptr_t slide) {
    (void)slide;
    if (!(g_fn_hooked && g_msg_hooked)) try_install();
#ifdef RADAR_DIAG
    if (g_diag_live) diag_on_image_added(mh); // report genuinely-new framework loads
#else
    (void)mh;
#endif
}

%ctor {
    @autoreleasepool {
#ifdef RADAR_DIAG
        // Prints in EVERY injected process, before/whether or not we activate.
        NSLog(@"[RadarSDKFraudShim][diag] loaded into '%@' (bundle %@, pid %d).",
              [[NSProcessInfo processInfo] processName],
              [[NSBundle mainBundle] bundleIdentifier] ?: @"(none)",
              (int)[[NSProcessInfo processInfo] processIdentifier]);
        diag_report_radar_presence();   // one line: is Radar in this process? (no full library dump)
#endif
        try_install();                                    // RadarSDKFraud already mapped? hook now.
        _dyld_register_func_for_add_image(image_added);   // otherwise catch it whenever it loads
#ifdef RADAR_DIAG
        g_diag_live = true;                               // from here on, add-image = real new load
#endif
        NSLog(@"[RadarSDKFraudShim] resident (fn_hooked=%d msg_hooked=%d).", g_fn_hooked, g_msg_hooked);
    }
}
