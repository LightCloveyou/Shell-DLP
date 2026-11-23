using System;
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.InteropServices;

namespace PowerShell7Guard.Loader
{
    // The loader has a fixed name and ABI. The actual Guard assembly retains
    // its original name and is loaded privately from the native DLL resource.
    public static class Entry
    {
        [StructLayout(LayoutKind.Sequential)]
        struct Request { public IntPtr Bytes; public int Length; public IntPtr Analyze; }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate int Analyze(IntPtr request, int length);

        static readonly ConcurrentBag<Analyze> Active = new ConcurrentBag<Analyze>();

        public static int Open(IntPtr data, int length)
        {
            try
            {
                if (data == IntPtr.Zero || length != Marshal.SizeOf<Request>()) return -1;
                var request = Marshal.PtrToStructure<Request>(data);
                if (request.Bytes == IntPtr.Zero || request.Length <= 0 || request.Length > 2 * 1024 * 1024) return -1;
                var bytes = new byte[request.Length];
                Marshal.Copy(request.Bytes, bytes, 0, bytes.Length);
                // Unlike native host loading into the default context, this overload
                // creates a private context for the image, even for equal simple names.
                var assembly = Assembly.Load(bytes);
                if (assembly.GetName().Name != "PowerShell7Guard.Ast") return -1;
                var type = assembly.GetType("PowerShell7Guard.AstBridge", true)!;
                var method = type.GetMethod("Analyze", BindingFlags.Public | BindingFlags.Static,
                    null, new[] { typeof(IntPtr), typeof(int) }, null)!;
                var invoke = (Analyze)Delegate.CreateDelegate(typeof(Analyze), method);
                request.Analyze = Marshal.GetFunctionPointerForDelegate(invoke);
                Active.Add(invoke);
                Marshal.StructureToPtr(request, data, false);
                return 0;
            }
            catch { return -1; }
        }
    }
}
