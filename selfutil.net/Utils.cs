using System;
using System.Runtime.InteropServices;

namespace selfutil
{
    public class Utils
    {
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int memcmp(byte[] b1, byte[] b2, long count);

        /// <summary>
        /// Comparing two byte arrays
        /// https://stackoverflow.com/a/1445405
        /// Validate buffers are the same length.
        /// This also ensures that the count does not exceed the length of either buffer.  
        /// </summary>
        /// <param name="b1"></param>
        /// <param name="b2"></param>
        /// <returns></returns>
        public static bool BytesCompare(byte[] b1, byte[] b2) => b1.Length == b2.Length && memcmp(b1, b2, b1.Length) == 0;

        public static T BytesToStruct<T>(byte[] data) where T : struct
        {
            T result = default;
            GCHandle handle = default;
            try
            {
                handle = GCHandle.Alloc(data, GCHandleType.Pinned);
                result = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            }
            catch { }
            finally { if (handle.IsAllocated) handle.Free(); }

            return result;
        }

        public static byte[] StructToBytes<T>(T structure, int SizeOF) where T : struct
        {
            IntPtr ptr = default;
            byte[] data = default;
            try
            {
                ptr = Marshal.AllocHGlobal(SizeOF);
                data = new byte[SizeOF];
                Marshal.StructureToPtr(structure, ptr, true);
                Marshal.Copy(ptr, data, 0, SizeOF);
            }
            catch { }
            finally { Marshal.FreeHGlobal(ptr); }

            return data;
        }

        /// <summary>
        /// Align the value to the specified alignment value
        /// </summary>
        /// <param name="val">query value</param>
        /// <param name="alignment">set alignment value</param>
        /// <returns>aligned value</returns>
        public static ulong AlignUp(ulong val, ulong alignment) => val + (alignment - 1) & ~(alignment - 1);

        /// <summary>
        /// Tag:SCE_NEEDED_MODULE
        /// </summary>
        /// <param name="val"></param>
        /// <returns></returns>
        public static (ulong id, ulong versionMinor, ulong versionMajor, ulong index) ParseSceModuleVersion(UInt64 val)
        {
            ulong id = val >> 48;
            ulong versionMinor = (val >> 40) & 0xF;
            ulong versionMajor = (val >> 32) & 0xF;
            ulong index = val & 0xFFF;

            return (id, versionMinor, versionMajor, index);
        }
    }
}
