"use strict";

function generateHead(headFile: File, bbAmount: number, modules: ModuleInfo[]) {

    headFile.write("DRCOV VERSION: 3\n");
    headFile.write("DRCOV FLAVOR: drcov\n");

    headFile.write(`Module Table: version 5, count ${modules.length}\n`);
    headFile.write(
        "Columns: id, containing_id, start, end, entry, offset, preferred_base, path\n"
    );
    const emptyMock = "0x0000";
    for (const mod of modules) {
        headFile.write(
            `  ${mod.id}, ${mod.id}, ${mod.base}, ${mod.end}, ${emptyMock}, ${emptyMock}, ${emptyMock}, ${mod.path}\n`
        );
    }
    headFile.write(`BB Table: ${bbAmount} bbs\n`);
}




const _instrumentClosure = () => {

    let GlobalRunCount = 0

    // The main tracer function
    return function (threadId: number, covName: string) {

        const modules = getmodules();
        const modIds: {
            [moduleName: string]: NativePointer;
        } = {};

        for (const module of modules) {
            modIds[module.name] = module.base;
        }

        Stalker.follow(threadId, {
            events: {
                compile: true,
            },
            onReceive: (events) => {
                GlobalRunCount++
                const bb_events = Stalker.parse(events, {
                    stringify: false,
                    annotate: false,
                }) as unknown as StalkerEventBare[];

                const logFile = new File(`${covName}_${GlobalRunCount}.txt`, "wb")
                const moduleMaps = new ModuleMap();

                const currBbAmount = bb_events.filter(event => moduleMaps.has(event[0] as NativePointer)).length;

                generateHead(logFile, currBbAmount, modules);

                console.log(`${GlobalRunCount}: Basic blocks ${bb_events.length} (unfiltered)`)


                // Write coverage blocks one by one
                for (const bb_event of bb_events) {

                    const bb_start = bb_event[0] as NativePointer;
                    const bb_end = bb_event[1] as NativePointer;

                    const modName = moduleMaps.findName(bb_start);
                    if (modName === null) {
                        continue;
                    }

                    /* dynamorio/ext/drcovlib/drcovlib.h */
                    /*
                    typedef struct _bb_entry_t {
                        uint start;
                        ushort size;
                        ushort mod_id;
                    } bb_entry_t;
                    */

                    const mod_info = modIds[modName];

                    const size = bb_end.sub(bb_start);                  // szie
                    const offset = bb_start.sub(mod_info).toInt32();    // start

                    const arr = new Uint32Array(1);                     // holds start
                    arr[0] = offset;

                    const size_and_mod_id = new Uint16Array(2);         // holds size, mod_id
                    size_and_mod_id[0] = size.toInt32();
                    size_and_mod_id[1] = modIds[modName].toInt32();

                    logFile.write(arr.buffer.slice(0) as ArrayBuffer);
                    logFile.write(size_and_mod_id.buffer.slice(0) as ArrayBuffer);
                }
                logFile.close();
            },
        });
    }

}


class ModuleInfo {

    id: number;
    base: NativePointer;
    end: NativePointer;
    path: string;
    name: string;

    constructor(id: number, base: NativePointer, end: NativePointer, path: string, name: string) {
        this.id = id;
        this.base = base;
        this.end = end;
        this.path = path;
        this.name = name;
    }
}


function getmodules(): ModuleInfo[] {

    const dr_modules: ModuleInfo[] = [];
    for (const [index, module] of Process.enumerateModules().entries()) {
        const modInfoV2 = new ModuleInfo(
            index,
            module.base,
            module.base.add(module.size),
            module.path,
            module.name,
        )
        dr_modules.push(modInfoV2);
    }
    return dr_modules;
}



/**
    Starts stalking your thread and creates drcov log files each time function called .
    Requires manual call to Stalker.unfollow() after the target function's execution ends.
    P.s. Beginnig and ending of basic blocks of the traced function are missed.

 * @param {number} threadId Thread to be traced.
 * @param {string} covName Start of the names of the coverage files to be generated.
 */
export const instrumentDrcov = _instrumentClosure()



// Examples:

// @ts-ignore 
// // Example: trace only executable and ignore dll's 
// // (not all dlls can be ignored tho)
// const modMaps = new ModuleMap()
// for (const module of modMaps.values()) {
//     if (!module.name.endsWith(".exe")) {
//         console.log(`excluding  ${module.name}`)
//         Stalker.exclude(module)
//     }
// }

// @ts-ignore 
// // Example: Trace function with exported function name "add"
// Stalker.trustThreshold = 0; // Use 0 if tracing "normal" program
// const addr = Module.getExportByName(null, "add")
// Interceptor.attach(addr, {
//     onEnter(_args) {
//         Stalker.flush()
//         instrument(this.threadId, "new_cov");
//     },
//     onLeave(_retval) {
//         Stalker.unfollow(this.threadId);
//     },
// });
