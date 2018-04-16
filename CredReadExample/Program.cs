using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace CredReadExample
{
    class Program
    {
        static void Main(string[] args)
        {
            IntPtr Credentials = IntPtr.Zero;
            try
            {
                var i = 0;
                if(CredEnumerate(null, 0, out var count,out Credentials))
                    foreach(var c in Enumerable.Range(0, count)
                     .Select(n => Marshal.ReadIntPtr(Credentials, n * Marshal.SizeOf(typeof(IntPtr))))
                     .Select(ptr => Marshal.PtrToStructure<CREDENTIAL>(ptr)))
                    {
                        Console.WriteLine($"{++i}");
                        Console.WriteLine($"{nameof(c.Flags)}:{c.Flags}");
                        Console.WriteLine($"{nameof(c.Type)}:{c.Type}");
                        Console.WriteLine($"{nameof(c.TargetName)}:{c.TargetName}");
                        Console.WriteLine($"{nameof(c.Comment)}:{c.Comment}");
                        Console.WriteLine($"{nameof(c.LastWritten)}:{DateTime.FromFileTime((long)(c.LastWritten.dwHighDateTime << 32) | (uint)c.LastWritten.dwLowDateTime)}");
                        Console.WriteLine($"{nameof(c.CredentialBlobSize)}:{c.CredentialBlobSize}");
                        var _CredentialBlob = new byte[c.CredentialBlobSize];
                        if (c.CredentialBlobSize > 0)
                            Marshal.Copy(c.CredentialBlob, _CredentialBlob, 0, (int)c.CredentialBlobSize);
                        Console.WriteLine($"{nameof(c.CredentialBlob)}:[{string.Join(" ", _CredentialBlob.Select(b => $"{b:X2}"))}]");
                        Console.WriteLine($"{nameof(c.Persist)}:{c.Persist}");
                        Console.WriteLine($"{nameof(c.AttributeCount)}:{c.AttributeCount}");
                        var ai = 0;
                        foreach(var attribute in Enumerable.Range(0, (int)c.AttributeCount)
                                        .Select(x => Marshal.ReadIntPtr(c.Attributes, x * Marshal.SizeOf<CREDENTIAL_ATTRIBUTE>()))
                                        .Select(x => Marshal.PtrToStructure<CREDENTIAL_ATTRIBUTE>(x)))
                        {
                            Console.WriteLine($"{nameof(c.Attributes)} - {++ai}");
                            Console.WriteLine($"{nameof(attribute.Keyword)}:{attribute.Keyword}");
                            Console.WriteLine($"{nameof(attribute.Flags)}:{attribute.Flags}");
                            Console.WriteLine($"{nameof(attribute.ValueSize)}:{attribute.ValueSize}");
                            var _AttributeValue = new byte[attribute.ValueSize];
                            if (attribute.ValueSize > 0)
                                Marshal.Copy(attribute.Value, _AttributeValue, 0, (int)attribute.ValueSize);
                            Console.WriteLine($"{nameof(attribute.Value)}:[{string.Join(" ", _AttributeValue.Select(v => $"{v:X2}"))}]");
                        }
                        Console.WriteLine($"{nameof(c.TargetAlias)}:{c.TargetAlias}");
                        Console.WriteLine($"{nameof(c.UserName)}:{c.UserName}");
                    }
            }
            finally
            {
                if (Credentials != IntPtr.Zero)
                    CredFree(Credentials);
            }
            Console.ReadLine();
        }
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredEnumerate(string filter, CRED_FLAGS flag, out int count, out IntPtr Credentials);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CredFree([In] IntPtr buffer);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CREDENTIAL
        {
            public CRED_FLAGS Flags;
            public CRED_TYPE Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public CRED_PERSIST Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }
        public enum CRED_TYPE : uint
        {
            GENERIC = 1,
            DOMAIN_PASSWORD = 2,
            DOMAIN_CERTIFICATE = 3,
            DOMAIN_VISIBLE_PASSWORD = 4,
            GENERIC_CERTIFICATE = 5,
            DOMAIN_EXTENDED = 6,
            MAXIMUM = 7,
            MAXIMUM_EX = (MAXIMUM + 1000),
        }

        public enum CRED_PERSIST : uint
        {
            SESSION = 1,
            LOCAL_MACHINE = 2,
            ENTERPRISE = 3,
        }

        public enum CRED_FLAGS : uint
        {
            PROMPT_NOW = 0x2,
            USERNAME_TARGET = 0x4
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CREDENTIAL_ATTRIBUTE
        {
            public string Keyword;
            public uint Flags;
            public uint ValueSize;
            public IntPtr Value;
        }
    }
}
