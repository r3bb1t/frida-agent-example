import { instrumentDrcov } from "./drcov.js";


Stalker.trustThreshold = 0; // For the fastest instrumentation (not suitable for packed/obfuscated)
const mainModule = Process.enumerateModules()[0].name;



const modMaps = new ModuleMap()
for (const module of modMaps.values()) {
    // Instrumenting only the binary we launched
    if (module.name != mainModule) {
        // console.log(`excluding  ${module.name}`)
        Stalker.exclude(module)
    }
}

// Replace this with your addr
const addr = Module.getExportByName(null, "add")
Interceptor.attach(addr, {
    onEnter(_args) {
        Stalker.flush()
        // Replace this with the name of coverage file you want
        instrumentDrcov(this.threadId, "new_cov");
    },
    onLeave(_retval) {
        Stalker.unfollow(this.threadId);
    },
});
