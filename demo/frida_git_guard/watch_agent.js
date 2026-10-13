'use strict';
const state = {push: false, checked: false, deny: false, stopping: false};
const kernel = Process.getModuleByName('kernel32.dll');
const getCommandLine = new NativeFunction(kernel.getExportByName('GetCommandLineW'), 'pointer', []);
const shell = Module.load('shell32.dll');
const argvCount = Memory.alloc(4);
const parseArgs = new NativeFunction(shell.getExportByName('CommandLineToArgvW'), 'pointer', ['pointer', 'pointer']);
const free = new NativeFunction(kernel.getExportByName('LocalFree'), 'pointer', ['pointer']);
const nativeArgv = parseArgs(getCommandLine(), argvCount);
const argv = [];
for (let i = 0; i < argvCount.readS32(); i++) {
  argv.push(nativeArgv.add(i * Process.pointerSize).readPointer().readUtf16String());
}
free(nativeArgv);

function check() {
  if (!state.push || state.stopping) return false;
  if (!state.checked) {
    const response = recv('decision', message => {
      state.deny = !!message.payload.deny;
      state.checked = true;
    });
    send({type: 'check', pid: Process.id, cwd: Process.getCurrentDir()});
    response.wait();
  }
  return state.deny;
}

const signature = ['pointer', 'pointer', 'pointer', 'pointer', 'int',
  'uint32', 'pointer', 'pointer', 'pointer', 'pointer'];
const addresses = new Set();
for (const api of ['CreateProcessW', 'CreateProcessA']) {
  const address = kernel.getExportByName(api);
  if (addresses.has(address.toString())) continue;
  addresses.add(address.toString());
  const original = new SystemFunction(address, 'int', signature);
  Interceptor.replace(address, new NativeCallback(function (...args) {
    // All children of a push are checked: local receiver, HTTP helper, SSH,
    // pre-push hooks and any aliases/helpers, without transport string matching.
    if (check()) {
      send({type: 'blocked', pid: Process.id, api, native_return: 0, win32_error: 5});
      this.lastError = 5;
      return 0;
    }
    const result = original(...args);
    this.lastError = result.lastError;
    return result.value;
  }, 'int', signature));
}

// Native git:// uses Winsock in Git itself, not an HTTP/SSH child.
const observer = Process.attachModuleObserver({onAdded(module) {
  if (module.name.toLowerCase() !== 'ws2_32.dll') return;
  const setError = new NativeFunction(module.getExportByName('WSASetLastError'), 'void', ['int']);
  for (const [api, types] of [
    ['connect', ['pointer', 'pointer', 'int']],
    ['WSAConnect', ['pointer', 'pointer', 'int', 'pointer', 'pointer', 'pointer', 'pointer']]
  ]) {
    const address = module.getExportByName(api);
    const original = new NativeFunction(address, 'int', types);
    Interceptor.replace(address, new NativeCallback(function (...args) {
      if (check()) {
        send({type: 'blocked', pid: Process.id, api, native_return: -1, winsock_error: 10013});
        setError(10013);
        return -1;
      }
      return original(...args);
    }, 'int', types));
  }
}});

Interceptor.flush();
rpc.exports = {
  info() { return {pid: Process.id, cwd: Process.getCurrentDir(), argv}; },
  configure(push) { state.push = push; return {push}; },
  stop() {
    state.stopping = true;
    observer.detach();
    Interceptor.revert(kernel.getExportByName('CreateProcessW'));
    Interceptor.revert(kernel.getExportByName('CreateProcessA'));
    // Other replacements are automatically removed by script unload.
  }
};
