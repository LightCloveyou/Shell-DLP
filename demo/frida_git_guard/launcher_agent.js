'use strict';
const kernel = Process.getModuleByName('kernel32.dll');
const shell = Module.load('shell32.dll');
const parse = new NativeFunction(shell.getExportByName('CommandLineToArgvW'), 'pointer', ['pointer', 'pointer']);
const free = new NativeFunction(kernel.getExportByName('LocalFree'), 'pointer', ['pointer']);
let sequence = 0;
let stopping = false;
const replacements = [];
const pending = new Map();
function argv(command) {
  const count=Memory.alloc(4), p=parse(Memory.allocUtf16String(command),count), out=[];
  for(let i=0;i<count.readS32();i++)out.push(p.add(i*Process.pointerSize).readPointer().readUtf16String());
  free(p);return out;
}
function directPush(args) {
  const takesValue=new Set(['-C','-c','--git-dir','--work-tree','--namespace','--config-env','--super-prefix']);
  let i=1;
  while(i<args.length&&args[i].startsWith('-')) {
    const token=args[i++];if(token==='--')break;if(takesValue.has(token))i++;
  }
  return args[i]==='push';
}
const signature=['pointer','pointer','pointer','pointer','int','uint32','pointer','pointer','pointer','pointer'];
const addresses=new Set();
for(const api of ['CreateProcessW','CreateProcessA']) {
  const address=kernel.getExportByName(api);
  if(addresses.has(address.toString()))continue;addresses.add(address.toString());
  const original=new SystemFunction(address,'int',signature);
  replacements.push(address);
  Interceptor.replace(address,new NativeCallback(function(...args) {
    let deny=false;
    if(!stopping) {
      try {
        const text=p=>p.isNull()?'':(api.endsWith('A')?p.readAnsiString():p.readUtf16String());
        const app=text(args[0]),command=text(args[1]);
        const first=app||((command.match(/^\s*(?:"([^"]+)"|([^\s]+))/)||[]).slice(1).find(Boolean)||'');
        if(/(?:^|[\\/])git(?:\.exe)?$/i.test(first)) {
          const words=argv(command||app);
          if(directPush(words)) {
            const id=String(++sequence), info={argv:words,cwd:text(args[7])||Process.getCurrentDir()};
            const slot={deny:true};pending.set(id,slot);
            const response=recv('decision-'+id,message=>{slot.deny=!!message.payload.deny;});
            send({type:'launch-check',id,info,pid:Process.id});response.wait();
            deny=slot.deny;pending.delete(id);
          }
        }
      } catch(error) {
        // A detected Git push that loses its decision must fail before creation.
        deny=true;send({type:'launcher-error',error:String(error),pid:Process.id});
      }
    }
    if(deny) {
      send({type:'blocked',pid:Process.id,api,stage:'launcher-before-create',win32_error:5,native_return:0});
      this.lastError=5;return 0;
    }
    const result=original(...args);this.lastError=result.lastError;return result.value;
  },'int',signature));
}
Interceptor.flush();
rpc.exports={stop(){stopping=true;for(const address of replacements)Interceptor.revert(address);}};