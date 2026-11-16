/**
 * Basic-block coverage recording in the DynamoRIO drcov format, readable by
 * coverage tools such as Lighthouse.
 *
 * Format reference: dynamorio/ext/drcovlib/drcovlib.h
 */

/** Value of the `DRCOV VERSION` header. Lighthouse requires 2. */
export type DrcovVersion = 2 | 3;

export interface DrcovOptions {
    /**
     * Coverage files are written to `<outputPrefix>_<n>.log`, with `n`
     * counting up from 1 for every traced call. Relative paths resolve
     * against the target process's working directory.
     */
    outputPrefix: string;
    /** Defaults to 3. */
    version?: DrcovVersion;
}

/**
 * Size of one `bb_entry_t` record:
 * `{ uint32 start; uint16 size; uint16 mod_id; }`, little-endian.
 */
const BB_ENTRY_SIZE = 8;

/**
 * Records the basic blocks executed by one thread from construction until
 * {@link stop}, then serializes them with {@link save}.
 *
 * Only blocks inside modules loaded at construction time are recorded.
 */
export class DrcovRecorder {
    readonly threadId: ThreadId;
    private readonly moduleMap = new ModuleMap();
    private readonly modules = this.moduleMap.values();
    private readonly moduleIds = new Map(this.modules.map((module, id) => [module.path, id]));
    private readonly chunks: ArrayBuffer[] = [];
    private blockCount = 0;

    constructor(threadId: ThreadId) {
        this.threadId = threadId;
        Stalker.follow(threadId, {
            events: { block: true },
            onReceive: events => this.record(events),
        });
    }

    /** Delivers pending events and stops following the thread. */
    stop(): void {
        Stalker.flush();
        Stalker.unfollow(this.threadId);
    }

    save(path: string, version: DrcovVersion = 3): void {
        const file = new File(path, "wb");
        file.write(this.header(version));
        for (const chunk of this.chunks) {
            file.write(chunk);
        }
        file.close();
    }

    private record(events: ArrayBuffer): void {
        // With `stringify: false`, block events are `[start, end]` pointer pairs.
        const blocks = Stalker.parse(events, { annotate: false, stringify: false }) as [NativePointer, NativePointer][];
        const chunk = new DataView(new ArrayBuffer(blocks.length * BB_ENTRY_SIZE));
        let count = 0;

        for (const [start, end] of blocks) {
            const module = this.moduleMap.find(start);
            if (module === null) {
                continue;
            }
            const offset = count * BB_ENTRY_SIZE;
            chunk.setUint32(offset, start.sub(module.base).toUInt32(), true);
            chunk.setUint16(offset + 4, end.sub(start).toUInt32(), true);
            chunk.setUint16(offset + 6, this.moduleIds.get(module.path)!, true);
            count++;
        }

        this.chunks.push(chunk.buffer.slice(0, count * BB_ENTRY_SIZE));
        this.blockCount += count;
    }

    private header(version: DrcovVersion): string {
        const lines = [
            `DRCOV VERSION: ${version}`,
            "DRCOV FLAVOR: drcov",
            `Module Table: version 5, count ${this.modules.length}`,
            "Columns: id, containing_id, start, end, entry, offset, preferred_base, path",
            ...this.modules.map((module, id) =>
                `  ${id}, ${id}, ${module.base}, ${module.base.add(module.size)}, 0x0, 0x0, 0x0, ${module.path}`),
            `BB Table: ${this.blockCount} bbs`,
        ];
        return lines.join("\n") + "\n";
    }
}

let fileCount = 0;

/**
 * Writes one drcov file per call to `target`.
 *
 * The first instructions of `target` are relocated into the Interceptor's
 * trampoline and run outside the module, so they are not recorded. Calls
 * that exit without returning (exceptions, longjmp) leave the thread
 * followed and produce no file. Recursive calls are recorded as part of the
 * outermost one.
 */
export function traceFunctionCoverage(target: NativePointerValue, options: DrcovOptions): InvocationListener {
    const tracedThreads = new Set<ThreadId>();

    return Interceptor.attach(target, {
        onEnter() {
            if (tracedThreads.has(this.threadId)) {
                return;
            }
            tracedThreads.add(this.threadId);
            this.recorder = new DrcovRecorder(this.threadId);
        },
        onLeave() {
            const recorder: DrcovRecorder | undefined = this.recorder;
            if (recorder === undefined) {
                return;
            }
            recorder.stop();
            tracedThreads.delete(this.threadId);
            recorder.save(`${options.outputPrefix}_${++fileCount}.log`, options.version);
        },
    });
}
