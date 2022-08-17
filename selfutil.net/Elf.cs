using System;
using System.Runtime.InteropServices;

namespace selfutil
{
    public class Elf
    {
        public static readonly uint ELF_MAGIC = 0x464C457F; // \x7F E L F

        /// <summary>
        /// SizeOF:64
        /// FMT = "<4s5B6xB2HI3QI6H", calcsize:64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Header
        {
            public UInt32 magic;
            public ECLASS cls;
            public EDATA encoding;
            public ELV legacyVersion;
            public EOSABI osAbi;
            public byte abiVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] padBytes;
            public byte nidentSize;
            public EType type_;
            public EMachine machine;
            public EVersion version;
            public UInt64 entry;        // Entry point virtual address
            public UInt64 phdrOffset;   // Program header table file offset
            public UInt64 shdrOffset;   // Section header table file offset
            public UInt32 flags;
            public UInt16 ehdrSize;
            public UInt16 phdrSize;
            public UInt16 phdrCount;
            public UInt16 shentSize;
            public UInt16 shdrCount;
            public UInt16 shdrStrtableIdx;
        }

        /// <summary>
        /// SizeOF:56
        /// FMT = "<2I6Q", calcsize:56
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ProgramHeader
        {
            public PhdrType type_;
            public PhdrFlag flags;
            public UInt64 offset; // Segment file offset
            public UInt64 vaddr;  // Segment virtual address(mem addr)
            public UInt64 paddr;  // Segment physical address(file addr)
            public UInt64 filesz; // Segment size in file
            public UInt64 memsz;  // Segment size in memory
            public UInt64 align;  // Segment alignment, file & memory
        }

        /// <summary>
        /// SizeOF:64, Extended Info for Signed ELF
        /// https://github.com/OpenOrbis/create-fself/blob/master/pkg/fself/FSELF.go
        /// https://www.psxhax.com/threads/ps2-game-backups-on-ps4-hen-4-05-make_fself-py-update-by-flat_z.3541
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ExInfo
        {
            public UInt64 paid;          //program authentication id
            public PTYPE ptype;          //program type
            public UInt64 appVersion;    //application version
            public UInt64 fwVersion;     //firmware version
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] digest; //sha256 digest
        }

        /// <summary>
        /// calcsize:20
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ProgramParam
        {
            public UInt32 paramSize;
            public UInt32 padVar1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] paramMagic;
            public UInt32 padVar2;
            public UInt32 sdkVersion;
        }

        /// <summary>
        /// FMT = "<QQ", calcsize:16
        /// </summary>
        public struct Dynamic
        {
            public DTag tag;   // entry tag
            public UInt64 val; // entry value, union { UInt64 d_val; UInt64 d_ptr; } d_un;
        }

        /// <summary>
        /// FMT = "<QLLq", calcsize:24
        /// </summary>
        public struct Relocation
        {
            public UInt64 offset;    // Location at which to apply the action
            public RTYPES info;      // type of relocation
            public UInt32 sym;       // index of relocation
            public Int64 addend;     // Constant addend used to compute value
        }

        /// <summary>
        /// FMT = "<IBBHQQ", calcsize:24
        /// </summary>
        public struct Symbol
        {
            public UInt32 name;  // Symbol name, index in string tbl
            public STInfo info;  // Type and binding attributes
            public byte other;   // No defined meaning, 0
            public UInt16 shndx; // Associated section index
            public UInt64 value; // Value of the symbol
            public UInt64 size;  // Associated symbol size
        }

        /// <summary>
        /// FMT = "<2I4Q2I2Q", calcsize:64
        /// </summary>
        public struct SectionHeader
        {
            public UInt32 name;      // Section name, index in string tbl
            public UInt32 type;      // Type of section
            public UInt64 flags;     // Miscellaneous section attributes
            public UInt64 addr;      // Section virtual addr at execution
            public UInt64 offset;    // Section file offset
            public UInt64 size;      // Size of section in bytes
            public UInt32 link;      // Index of another section
            public UInt32 info;      // Additional section information
            public UInt64 addralign; // Section alignment
            public UInt64 entsize;   // Entry size if section holds table
        }

        /// <summary>
        /// Note header in a ProgHdrType.NOTE section
        /// </summary>
        public struct NoteHdr
        {
            public UInt32 namesz; // Name size
            public UInt32 descsz; // Content size
            public UInt32 type;   // Content type
        }

        /// <summary>
        /// SizeOF:64
        /// </summary>
        public static readonly int SizeEhdr = Marshal.SizeOf(typeof(Header));
        /// <summary>
        /// SizeOF:56
        /// </summary>
        public static readonly int SizePhdr = Marshal.SizeOf(typeof(ProgramHeader));
        /// <summary>
        /// SizeOF:64
        /// </summary>
        public static readonly int SizeExInfo = Marshal.SizeOf(typeof(ExInfo));
        /// <summary>
        /// SizeOF:20
        /// </summary>
        public static readonly int SizeProgParam = Marshal.SizeOf(typeof(ProgramParam));
        /// <summary>
        /// SizeOF:16 structFmt = '<QQ';
        /// </summary>
        public static readonly int sizeDynamic = Marshal.SizeOf(typeof(Dynamic));
        /// <summary>
        /// SizeOF:24 structFmt = '<QLLq';
        /// </summary>
        public static readonly int sizeRela = Marshal.SizeOf(typeof(Relocation));
        /// <summary>
        /// SizeOF:24 structFmt = '<IBBHQQ';
        /// </summary>
        public static readonly int sizeSymbol = Marshal.SizeOf(typeof(Symbol));

        public enum ECLASS : byte
        {
            CLASSNONE = 0, // EI_CLASS
            CLASS32 = 1,
            CLASS64 = 2,
            CLASSNUM = 3,
        }

        public enum EDATA : byte
        {
            DATANONE = 0, // e_ident[EI_DATA]
            DATA2LSB = 1,
            DATA2MSB = 2,
        }

        public enum ELV : byte
        {
            NONE    = 0, // e_version
            CURRENT = 1,
            NUM     = 2,
        }

        public enum EVersion : UInt32
        {
            NONE    = 0, // EI_VERSION
            CURRENT = 1,
            NUM     = 2,
        }

        public enum EOSABI : byte
        {
            NONE    = 0,
            LINUX   = 3,
            FREEBSD = 9, // e_ident[IE_OSABI]
        }

        /// <summary>
        /// These constants define the different elf file types
        /// SCE-specific definitions for e_type
        /// </summary>
        public enum EType : UInt16
        {
            NONE            = 0,
            REL             = 1,
            EXEC            = 2,
            DYN             = 3,
            CORE            = 4,
            LOPROC          = 0xff00,
            HIPROC          = 0xffff,

            SCE_EXEC        = 0xFE00, // SCE Executable file
            SCE_REPLAY_EXEC = 0xFE01,
            SCE_RELEXEC     = 0xFE04, // SCE Relocatable Executable file
            SCE_STUBLIB     = 0xFE0C, // SCE SDK Stubs
            SCE_DYNEXEC     = 0xFE10, // SCE EXEC_ASLR
            SCE_DYNAMIC     = 0xFE18, // Unused
            SCE_PSPRELEXEC  = 0xFFA0, // Unused (PSP ELF only)
            SCE_PPURELEXEC  = 0xFFA4, // Unused (SPU ELF only)
            SCE_UNK         = 0xFFA5, // Unknown
        }

        /// <summary>
        /// These constants define the various ELF target machines
        /// </summary>
        public enum EMachine : UInt16
        {
            NONE        = 0,
            M32         = 1,
            SPARC       = 2,
            E386        = 3,
            E68K        = 4,
            E88K        = 5,
            E486        = 6, // Perhaps disused
            E860        = 7,

            MIPS        = 8,  // MIPS R3000 (officially, big-endian only)
            MIPS_RS4_BE = 10, // MIPS R4000 big-endian
            PARISC      = 15, // HPPA
            SPARC32PLUS = 18, // Sun's "v8plus"
            PPC         = 20, // PowerPC
            PPC64       = 21, // PowerPC64
            SH          = 42, // SuperH
            SPARCV9     = 43, // SPARC v9 64-bit
            IA_64       = 50, // HP/Intel IA-64
            X86_64      = 62, // AMD x86-64
            S390        = 22, // IBM S/390
            CRIS        = 76, // Axis Communications 32-bit embedded processor
            V850        = 87, // NEC v850
            M32R        = 88, // Renesas M32R
            H8_300      = 46, // Renesas H8/300,300H,H8S

            ALPHA       = 0x9026,
            CYGNUS_V850 = 0x9080, // Bogus old v850 magic number, used by old tools. 
            CYGNUS_M32R = 0x9041, // Bogus old m32r magic number, used by old tools. 
            S390_OLD    = 0xA390, // This is the old interim value for S/390 architecture
            FRV         = 0x5441, // Fujitsu FR-V
        }

        /// <summary>
        /// Program Segment Type
        /// These constants are for the segment types stored in the image headers
        /// </summary>
        public enum PhdrType : UInt32
        {
            NULL            = 0x0,
            LOAD            = 0x1,
            DYNAMIC         = 0x2,
            INTERP          = 0x3,
            NOTE            = 0x4,
            SHLIB           = 0x5,
            PHDR            = 0x6,
            TLS             = 0x7,                  // Thread local storage segment
            LOOS            = 0x60000000,           // OS-specific
            HIOS            = 0x6fffffff,           // OS-specific
            LOPROC          = 0x70000000,
            HIPROC          = 0x7fffffff,
            SCE_SEGSYM      = 0x700000A8,
            SCE_RELA        = LOOS,                 // .rela No +0x1000000 ?
            SCE_DYNLIBDATA  = LOOS + 0x1000000,     // .sce_special
            SCE_PROCPARAM   = LOOS + 0x1000001,     // .sce_process_param
            SCE_MODULEPARAM = LOOS + 0x1000002,
            SCE_RELRO       = LOOS + 0x1000010,     // .data.rel.ro
            SCE_COMMENT     = LOOS + 0xfffff00,     // .sce_comment
            SCE_VERSION     = LOOS + 0xfffff01,     // .sce_version
            GNU_EH_FRAME    = LOOS + 0x474E550,     // .eh_frame_hdr
            GNU_STACK       = LOOS + 0x474e551,
        }

        /// <summary>
        /// These constants define the permissions on sections in the program header, p_flags
        /// </summary>
        public enum PhdrFlag : UInt32
        {
            X  = 0x1,
            W  = 0x2,
            R  = 0x4,
            RX = R | X,
            RW = R | W,
        }

        /// <summary>
        /// ExInfo::ptype
        /// </summary>
        public enum PTYPE : UInt64
        {
            FAKE          = 0x1,
            NPDRM_EXEC    = 0x4,
            NPDRM_DYNLIB  = 0x5,
            SYSTEM_EXEC   = 0x8,
            SYSTEM_DYNLIB = 0x9, // including Mono binaries
            HOST_KERNEL   = 0xC,
            SEC_MODULE    = 0xE,
            SEC_KERNEL    = 0xF,
        }

        /// <summary>
        /// Dynamic Section Types
        /// This is the info that is needed to parse the dynamic section of the file
        /// SCE_PRIVATE: bug 63164, add for objdump
        /// </summary>
        public enum DTag : UInt64
        {
            NULL                     = 0,
            NEEDED                   = 1,
            PLTRELSZ                 = 2,
            PLTGOT                   = 3,
            HASH                     = 4,
            STRTAB                   = 5,
            SYMTAB                   = 6,
            RELA                     = 7,
            RELASZ                   = 8,
            RELAENT                  = 9,
            STRSZ                    = 10,
            SYMENT                   = 11,
            INIT                     = 12,
            FINI                     = 13,
            SONAME                   = 14,
            RPATH                    = 15,
            SYMBOLIC                 = 16,
            REL                      = 17,
            RELSZ                    = 18,
            RELENT                   = 19,
            PLTREL                   = 20,
            DEBUG                    = 21,
            TEXTREL                  = 22,
            JMPREL                   = 23,
            LOPROC                   = 0x70000000,
            HIPROC                   = 0x7fffffff,
            // Tag for SCE string table size
            SCE_IDTABENTSZ = 0x61000005,
            SCE_FINGERPRINT          = 0x61000007,
            SCE_ORIGINAL_FILENAME    = 0x61000009,
            SCE_MODULE_INFO          = 0x6100000d,
            SCE_NEEDED_MODULE        = 0x6100000f,
            SCE_MODULE_ATTR          = 0x61000011,
            SCE_EXPORT_LIB           = 0x61000013,
            SCE_IMPORT_LIB           = 0x61000015,
            SCE_EXPORT_LIB_ATTR      = 0x61000017,
            SCE_IMPORT_LIB_ATTR      = 0x61000019,
            SCE_STUB_MODULE_NAME     = 0x6100001d,
            SCE_STUB_MODULE_VERSION  = 0x6100001f,
            SCE_STUB_LIBRARY_NAME    = 0x61000021,
            SCE_STUB_LIBRARY_VERSION = 0x61000023,
            SCE_HASH                 = 0x61000025,
            SCE_PLTGOT               = 0x61000027,
            SCE_JMPREL               = 0x61000029,
            SCE_PLTREL               = 0x6100002b,
            SCE_PLTRELSZ             = 0x6100002d,
            SCE_RELA                 = 0x6100002f,
            SCE_RELASZ               = 0x61000031,
            SCE_RELAENT              = 0x61000033,
            SCE_STRTAB               = 0x61000035,
            SCE_STRSZ                = 0x61000037,
            SCE_SYMTAB               = 0x61000039,
            SCE_SYMENT               = 0x6100003b,
            SCE_HASHSZ               = 0x6100003d,
            SCE_SYMTABSZ             = 0x6100003f,
        }

        /// <summary>
        /// type of relocation
        /// </summary>
        public enum RTYPES : UInt32
        {
            AMD64_default   = 0x00,
            AMD64_64        = 0x01,
            AMD64_PC32      = 0x02,
            AMD64_GOT32     = 0x03,
            AMD64_PLT32     = 0x04,
            AMD64_COPY      = 0x05,
            AMD64_GLOB_DAT  = 0x06,
            AMD64_JUMP_SLOT = 0x07,
            AMD64_RELATIVE  = 0x08,
            AMD64_GOTPCREL  = 0x09,
            AMD64_32        = 0x0A,
            AMD64_32S       = 0x0B,
            AMD64_16        = 0x0C,
            AMD64_PC16      = 0x0D,
            AMD64_8         = 0x0E,
            AMD64_PC8       = 0x0F,
            AMD64_DTPMOD64  = 0x10,
            AMD64_DTPOFF64  = 0x11,
            AMD64_TPOFF64   = 0x12,
            AMD64_TLSGD     = 0x13,
            AMD64_TLSLD     = 0x14,
            AMD64_DTPOFF32  = 0x15,
            AMD64_GOTTPOFF  = 0x16,
            AMD64_TPOFF32   = 0x17,
            AMD64_PC64      = 0x18,
            AMD64_GOTOFF64  = 0x19,
            AMD64_GOTPC32   = 0x1A,
        }

        /// <summary>
        /// Symbol Information
        /// This info is needed when parsing the symbol table
        /// TYPES: info & 0xF (NOTYPE, OBJECT, FUNC, SECTION, FILE, COMMON, TLS)
        /// BINDS: info >> 4 (LOCAL, GLOBAL, WEAK)
        /// </summary>
        public enum STInfo : byte
        {
            LOCAL_NONE      = 0x0,
            LOCAL_OBJECT    = 0x1,
            LOCAL_FUNCTION  = 0x2,
            LOCAL_SECTION   = 0x3,
            LOCAL_FILE      = 0x4,
            LOCAL_COMMON    = 0x5,
            LOCAL_TLS       = 0x6,

            GLOBAL_NONE     = 0x10,
            GLOBAL_OBJECT   = 0x11,
            GLOBAL_FUNCTION = 0x12,
            GLOBAL_SECTION  = 0x13,
            GLOBAL_FILE     = 0x14,
            GLOBAL_COMMON   = 0x15,
            GLOBAL_TLS      = 0x16,

            WEAK_NONE       = 0x20,
            WEAK_OBJECT     = 0x21,
            WEAK_FUNCTION   = 0x22,
            WEAK_SECTION    = 0x23,
            WEAK_FILE       = 0x24,
            WEAK_COMMON     = 0x25,
            WEAK_TLS        = 0x26,
        }

        /// <summary>
        /// Symbolic values for the entries in the auxiliary table put on the initial stack
        /// </summary>
        public enum AT : uint
        {
            NULL     = 0,  // end of vector
            IGNORE   = 1,  // entry should be ignored
            EXECFD   = 2,  // file descriptor of program
            PHDR     = 3,  // program headers for program
            PHENT    = 4,  // size of program header entry
            PHNUM    = 5,  // number of program headers
            PAGESZ   = 6,  // system page size
            BASE     = 7,  // base address of interpreter
            FLAGS    = 8,  // flags
            ENTRY    = 9,  // entry point of program
            NOTELF   = 10, // program is not ELF
            UID      = 11, // real uid
            EUID     = 12, // effective uid
            GID      = 13, // real gid
            EGID     = 14, // effective gid
            PLATFORM = 15, // string identifying CPU for optimizations
            HWCAP    = 16, // arch dependent hints at CPU capabilities
            CLKTCK   = 17, // frequency at which times() increments
            SECURE   = 23, // secure mode boolean
        }

        /// <summary>
        /// sh_type
        /// </summary>
        public enum SHT : uint
        {
            NULL     = 0,
            PROGBITS = 1,
            SYMTAB   = 2,
            STRTAB   = 3,
            RELA     = 4,
            HASH     = 5,
            DYNAMIC  = 6,
            NOTE     = 7,
            NOBITS   = 8,
            REL      = 9,
            SHLIB    = 10,
            DYNSYM   = 11,
            NUM      = 12,
            LOPROC   = 0x70000000,
            HIPROC   = 0x7fffffff,
            LOUSER   = 0x80000000,
            HIUSER   = 0xffffffff,
            SCE_NID  = 0x61000001,
            SCE_IDK  = 0x09010102,
        }

        /// <summary>
        /// sh_flags
        /// </summary>
        public enum SHF : uint
        {
            WRITE     = 0x1,
            ALLOC     = 0x2,
            EXECINSTR = 0x4,
            MASKPROC  = 0xf0000000,
        }

        /// <summary>
        /// special section indexes
        /// </summary>
        public enum SHN : uint
        {
            UNDEF     = 0,
            LORESERVE = 0xff00,
            LOPROC    = 0xff00,
            HIPROC    = 0xff1f,
            ABS       = 0xfff1,
            COMMON    = 0xfff2,
            HIRESERVE = 0xffff,
        }

        /// <summary>
        /// Notes used in EType.CORE(ET_CORE)
        /// </summary>
        public enum NT : uint
        {
            PRSTATUS   = 1,
            PRFPREG    = 2,
            PRPSINFO   = 3,
            TASKSTRUCT = 4,
            AUXV       = 6,
            PRXFPREG   = 0x46e62b7f, // copied from gdb5.1/include/elf/common.h
        }
    }
}
