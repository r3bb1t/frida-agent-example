"use strict";

function generateHead(headFile: File, bbAmount: number, modules: ModuleInfo[]) {

    headFile.write("DRCOV VERSION: 3\n");	// just change it to 2 if you want to use in "Lighthouse" IDA plugin
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
            [modId: string]: NativePointer
        } = {};
        const modBases: {
            [moduleName: string]: NativePointer;
        } = {};

        for (const module of modules) {
            modIds[module.name] = new NativePointer(module.id);
            modBases[module.name] = module.base;
        }

        Stalker.follow(threadId, {
            events: {
                // compile: true, // use only compile if you need only unique blocks
		block: true	  // using block because i want to see full history of execution
            },
            onReceive: (events) => {
                GlobalRunCount++
                const bbEvents = Stalker.parse(events, {
                    stringify: false,
                    annotate: false,
                }) as unknown as StalkerEventBare[];

                const logFile = new File(`${covName}_${GlobalRunCount}.txt`, "wb")
                const moduleMaps = new ModuleMap();

                const currBbAmount = bbEvents.filter(event => moduleMaps.has(event[0] as NativePointer)).length;

                generateHead(logFile, currBbAmount, modules);

                // console.log(`${GlobalRunCount}: Basic blocks ${bbEvents.length} (unfiltered)`)


                // Write coverage blocks one by one
                for (const bbEvent of bbEvents) {

                    const bbStart = bbEvent[0] as NativePointer;
                    const bbEnd = bbEvent[1] as NativePointer;

                    const modName = moduleMaps.findName(bbStart);
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

                    const modAddr = modBases[modName];

                    const size = bbEnd.sub(bbStart).toUInt32();		// szie
                    const offset = bbStart.sub(modAddr).toUInt32();	// start
                    const modId = modIds[modName].toUInt32();		// mod_id

                    const arr = new Uint32Array(1);			// holds start
                    arr[0] = offset;

                    const sizeAndModId = new Uint16Array(2);		// holds size, mod_id
                    sizeAndModId[0] = size;
                    sizeAndModId[1] = modId;

                    logFile.write(arr.buffer.slice(0) as ArrayBuffer);
                    logFile.write(sizeAndModId.buffer.slice(0) as ArrayBuffer);
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

    const drModules: ModuleInfo[] = [];
    for (const [index, module] of Process.enumerateModules().entries()) {
        const modInfoV2 = new ModuleInfo(
            index,
            module.base,
            module.base.add(module.size),
            module.path,
            module.name,
        )
        drModules.push(modInfoV2);
    }
    return drModules;
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
//         instrumentDrcov(this.threadId, "new_cov");
//     },
//     onLeave(_retval) {
//         Stalker.unfollow(this.threadId);
//     },
// });

