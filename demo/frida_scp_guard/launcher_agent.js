'use strict';
const kernel=Process.getModuleByName('kernel32.dll');
const shell=Module.load('shell32.dll');
const parse=new NativeFunction(shell.getExportByName('CommandLineToArgvW'),'pointer',['pointer','pointer']);
const free=new NativeFunction(kernel.getExportByName('LocalFree'),'pointer',['pointer']);
const signature=['pointer','pointer','pointer','pointer','int','uint32','pointer','pointer','pointer','pointer'];
const replacements=[];let sequence=0,stopping=false;
function argv(command){const n=Memory.alloc(4),p=parse(Memory.allocUtf16String(command),n),a=[];for(let i=0;i<n.readS32();i++)a.push(p.add(i*Process.pointerSize).readPointer().readUtf16String());free(p);return a;}
for(const api of ['CreateProcessW','CreateProcessA']){
 const address=kernel.getExportByName(api),original=new SystemFunction(address,'int',signature);replacements.push(address);
 Interceptor.replace(address,new NativeCallback(function(...args){let deny=false;
  if(!stopping)try{const text=p=>p.isNull()?'':(api.endsWith('A')?p.readAnsiString():p.readUtf16String());const app=text(args[0]),command=text(args[1]);const first=app||((command.match(/^\s*(?:"([^"]+)"|([^\s]+))/)||[]).slice(1).find(Boolean)||'');
   if(/(?:^|[\\/])scp(?:\.exe)?$/i.test(first)){const words=argv(command||app),id=String(++sequence),slot={deny:true};const response=recv('decision-'+id,m=>{slot.deny=!!m.payload.deny;});send({type:'launch-check',id,info:{argv:words,cwd:text(args[7])||Process.getCurrentDir()}});response.wait();deny=slot.deny;}
  }catch(error){deny=true;send({type:'launcher-error',error:String(error)});}
  if(deny){send({type:'blocked',win32_error:5});this.lastError=5;return 0;}const result=original(...args);this.lastError=result.lastError;return result.value;
 },'int',signature));
}
Interceptor.flush();rpc.exports={stop(){stopping=true;for(const address of replacements)Interceptor.revert(address);}};
