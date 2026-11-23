param([string]$Bridge,[string]$Directory)
$ErrorActionPreference='Stop'
if ((Get-Location).Path -ne $Directory) { Set-Location -LiteralPath $Directory }
Add-Type -TypeDefinition @"
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.IO;
public static class PeerScan {
  [StructLayout(LayoutKind.Sequential)]
  struct Request { public IntPtr Source, Output; public int Length, Capacity, Decision; }
  static Type bridge;
  public static void Load(string path) {
    using var f=File.OpenRead(path);
    bridge=new AssemblyLoadContext("peer-policy",false).LoadFromStream(f).GetType("PowerShell7Guard.AstBridge",true);
  }
  public static int PersistentCount() {
    var flags=BindingFlags.Static|BindingFlags.NonPublic;
    var store=bridge.GetNestedType("Store",BindingFlags.NonPublic);
    if (!(bool)store.GetMethod("RefreshDerived",flags).Invoke(null,new object[]{false})) return -2;
    var rows=(System.Collections.IEnumerable)store.GetMethod("Persistent",flags).Invoke(null,new object[]{"user","fixture-owner","FLOW_ONLY"});
    int count=0;
    foreach (var _ in rows) count++;
    return count;
  }
  public static int Scan(string text) {
    IntPtr source=Marshal.StringToHGlobalUni(text),output=Marshal.AllocHGlobal(65536);
    IntPtr request=Marshal.AllocHGlobal(Marshal.SizeOf<Request>());
    try {
      Marshal.StructureToPtr(new Request {Source=source,Output=output,Length=text.Length,Capacity=65536,Decision=-1},request,false);
      int count=(int)bridge.GetMethod("Analyze").Invoke(null,new object[]{request,Marshal.SizeOf<Request>()});
      if (count<=0) throw new Exception("analysis failed");
      return Marshal.PtrToStructure<Request>(request).Decision;
    } finally {Marshal.FreeHGlobal(source);Marshal.FreeHGlobal(output);Marshal.FreeHGlobal(request);}
  }
}
"@
[PeerScan]::Load($Bridge)
while ($null -ne ($line=[Console]::ReadLine())) {
    $decision=if($line -eq ":persistent-fixture"){[PeerScan]::PersistentCount()}else{[PeerScan]::Scan($line)}
    [Console]::WriteLine($decision)
}
