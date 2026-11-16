import { traceFunctionCoverage } from "./drcov.js";

/** Exported function of the main executable to record coverage for. */
const TARGET_EXPORT = "add";
/** Files are written to `<OUTPUT_PREFIX>_<n>.log` in the target's working directory. */
const OUTPUT_PREFIX = "new_cov";

// Trust code from its first execution: fastest, but wrong for self-modifying
// (packed/obfuscated) code; use -1 there.
Stalker.trustThreshold = 0;

// Record only blocks executed inside the main executable.
const mainModule = Process.mainModule;
for (const module of Process.enumerateModules()) {
    if (module.path !== mainModule.path) {
        Stalker.exclude(module);
    }
}

traceFunctionCoverage(mainModule.getExportByName(TARGET_EXPORT), { outputPrefix: OUTPUT_PREFIX });
