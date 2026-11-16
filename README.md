# frida-agent-example

A Frida agent that records basic-block coverage of a function in the
[drcov](https://dynamorio.org/page_drcov.html) format, so it can be loaded
into coverage tools such as [Lighthouse](https://github.com/gaasedelen/lighthouse).

Every call to the target function produces one coverage file.

## Requirements

- [Frida](https://frida.re) 17 (`pip install frida-tools`)
- [Bun](https://bun.sh) or Node.js with npm

## Build

```sh
git clone https://github.com/r3bb1t/frida-agent-example.git
cd frida-agent-example
bun install
bun pm trust frida
bun install
```

`bun install` runs the build and produces `_agent.js`. Rebuild with
`npm run build`.

## Usage

Set the function to trace and the output name at the top of
[`agent/index.ts`](agent/index.ts):

```ts
const TARGET_EXPORT = "add";
const OUTPUT_PREFIX = "new_cov";
```

By default only blocks inside the main executable are recorded and the target
is looked up among its exports. Rebuild after editing, then load the agent:

```sh
frida -f program.exe -l _agent.js               # spawn a local program
frida -p <pid> -l _agent.js                     # attach to a running process
frida -U -f com.example.android -l _agent.js    # Android over USB
```

Each call to the target writes `new_cov_1.log`, `new_cov_2.log`, ... into the
target process's working directory.

### Using the library directly

[`agent/drcov.ts`](agent/drcov.ts) exports:

- `traceFunctionCoverage(target, { outputPrefix, version })`: hooks `target`
  and writes one file per call.
- `DrcovRecorder`: follows one thread between your own start and stop points,
  e.g. from entering one function until entering another:

  ```ts
  let recorder: DrcovRecorder | undefined;
  Interceptor.attach(startAddress, {
      onEnter() { recorder ??= new DrcovRecorder(this.threadId); },
  });
  Interceptor.attach(stopAddress, {
      onEnter() {
          if (recorder?.threadId !== this.threadId) return;
          recorder.stop();
          recorder.save("coverage.log");
          recorder = undefined;
      },
  });
  ```

### Loading into Lighthouse

Lighthouse only reads drcov version 2 files. Pass `version: 2`:

```ts
traceFunctionCoverage(target, { outputPrefix: OUTPUT_PREFIX, version: 2 });
```

### Limitations

- The first instructions of the traced function are run from the Interceptor
  trampoline and are missing from the coverage.
- Code in modules loaded after recording starts is not recorded.
- `Stalker.trustThreshold = 0` is fastest but incorrect for self-modifying
  (packed or obfuscated) code; set it to `-1` there.

## Development

Open the folder in Visual Studio Code and install the recommended ESLint
extension. When prompted, choose "Allow" to use the workspace TypeScript
version, which provides Frida API completion and type checking from
`@types/frida-gum`.

Run the `frida: watch` task (Terminal → Run Task) or `npm run watch` to rebuild
on every change. The Frida CLI reloads `_agent.js` automatically.

```sh
npm run typecheck
npm run lint
```

### Debugging

Load the agent with the V8 runtime and the inspector enabled:

```sh
frida -f program.exe --runtime=v8 --debug -l _agent.js
```

Then start the `Attach to Frida agent` launch configuration in VS Code
(port 9229). A `debugger;` statement in the agent pauses execution there.
