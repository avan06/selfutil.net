using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace selfutil
{
    public class SelfUtil
    {
        bool dryRun;
        bool alignSize;
        bool notPatchFirstSegDup;
        bool notPatchVerSeg;
        bool verbose;
        bool verboseV;
        public byte[] data;
        public byte[] save;
        public Self.Header seHead;
        public List<Self.Entry> entries;
        public ulong elfHdrOffset;
        public Elf.Header elfHdr;
        public List<Elf.ProgramHeader> phdrs;

        public SelfUtil(string filePath, bool dryRun, bool alignSize, bool notPatchFirstSegDup, bool notPatchVerSeg, bool verbose, bool verboseV)
        {
            this.dryRun = dryRun;
            this.alignSize = alignSize;
            this.notPatchFirstSegDup = notPatchFirstSegDup;
            this.notPatchVerSeg = notPatchVerSeg;
            this.verbose = verbose;
            this.verboseV = verboseV;

            data = new byte[] { };
            save = new byte[] { };
            entries = new List<Self.Entry>();
            phdrs = new List<Elf.ProgramHeader>();
            Load(filePath);
        }

        public bool Load(string filePath)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine("Failed to find file: \"{0}\" \n", filePath);
                return false;
            }

            try
            {
                FileInfo fi = new FileInfo(filePath);

                long fileSize = fi.Length;
                Array.Resize(ref data, (int)fileSize);

                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read)) fs.Read(data, 0, (int)fileSize);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to open file: \"{0}\" \n, {1}", filePath, ex);
                return false;
            }

            return Parse();
        }

        public bool Parse()
        {
            if (data.Length < Self.PS4_PAGE_SIZE) Console.WriteLine("Small file size! ({0})\nContinuing regardless.\n", data.Length); //return false;

            seHead = Utils.BytesToStruct<Self.Header>(data);

            if (Self.SELF_MAGIC != seHead.magic)
            {
                Console.WriteLine("Invalid Self Magic! (0x{0:X8})\n", seHead.magic);
                return false;
            }

            if (verbose)
                Console.WriteLine(
                    "   **Self head info**\n" +
                    " Head position: 0~{0:X}\n" +
                    " Magic        : 0x{1:X}\n" +
                    " Version      : 0x{2:X}\n" +
                    " Mode         : 0x{3:X}\n" +
                    " Endian       : 0x{4:X}\n" +
                    " Attribs      : 0x{5:X}\n" +
                    " KeyType      : 0x{6:X}\n" +
                    " Header size  : 0x{7:X}\n" +
                    " Meta size    : 0x{8:X}\n" +
                    " File size    : {9} Bytes\n" +
                    " Entries count: {10}\n" +
                    " Flags        : {11:X}\n", Self.SizeSHdr - 1, seHead.magic, seHead.version, seHead.mode, seHead.endian, seHead.attribs, seHead.keyType, seHead.headerSize, seHead.metaSize, seHead.fileSize, seHead.numEntries, seHead.flags);

            entries.Clear();
            for (ushort seIdx = 0; seIdx < seHead.numEntries; seIdx++)
            {
                var entryOffset = Self.SizeSHdr + Self.SizeSEntry * seIdx;
                Byte[] dataEntry = new Byte[Self.SizeSEntry];
                Buffer.BlockCopy(data, entryOffset, dataEntry, 0, dataEntry.Length);
                Self.Entry seEntry = Utils.BytesToStruct<Self.Entry>(dataEntry);
                entries.Add(seEntry);

                if (verbose) Console.Write("Entry{0:00}({1:X4}~{2:X4}) Offset: {3:X8} +{4,-8:X} (memSz: {5:X8}) Prop: {6:X8} SegID: {7,-2:X}\n",
                    seIdx, entryOffset, entryOffset + Self.SizeSEntry - 1, seEntry.offs, seEntry.fileSz, seEntry.memSz, seEntry.props, seEntry.props >> 20);
            }

            elfHdrOffset = (uint)Self.SizeSHdr + seHead.numEntries * (uint)Self.SizeSEntry;

            Byte[] dataEhdr = new Byte[Elf.SizeEhdr];
            Buffer.BlockCopy(data, (int)elfHdrOffset, dataEhdr, 0, dataEhdr.Length);
            elfHdr = Utils.BytesToStruct<Elf.Header>(dataEhdr);

            if (verbose)
                Console.WriteLine(
                    "\n   **Elf head info**\n" +
                    " Head position: {0:X}~{1:X}\n" +
                    " Magic        : 0x{2:X}\n" +
                    " Class        : {3}\n" +
                    " Data         : {4}\n" +
                    " Version      : {5}\n" +
                    " OS           : {6}\n" +
                    " Type         : 0x{7:X}\n" +
                    " Machine      : {8}\n" +
                    " Segment start: 0x{9:X}\n" +
                    " Header size  : 0x{10:X}\n" +
                    " Segment size : {11} Bytes\n" +
                    " Segment count: {12}\n",
                    elfHdrOffset, elfHdrOffset + (uint)Elf.SizeEhdr - 1, elfHdr.magic, elfHdr.cls, elfHdr.encoding, elfHdr.legacyVersion, elfHdr.osAbi,
                    elfHdr.type_, elfHdr.machine, elfHdr.phdrOffset, elfHdr.ehdrSize, elfHdr.phdrSize, elfHdr.phdrCount);

            if (!TestIdent())
            {
                Console.WriteLine("Elf e_ident invalid!");
                return false;
            }

            int pHdrOffset = 0;
            for (ulong phIdx = 0; phIdx < elfHdr.phdrCount; phIdx++)
            {
                pHdrOffset = (int)(elfHdrOffset + elfHdr.phdrOffset + phIdx * (ulong)Elf.SizePhdr);
                Byte[] dataPhdr = new Byte[Elf.SizePhdr];
                Buffer.BlockCopy(data, pHdrOffset, dataPhdr, 0, dataPhdr.Length);
                var pHdr = Utils.BytesToStruct<Elf.ProgramHeader>(dataPhdr);

                if (verbose) Console.Write("Segment{0:00}({1:X4}~{2:X4}) Offset: {3:X8} +{4,-8:X} (memSz: {5:X8}) Type:{6:X8}({7}) \n",
                        phIdx, pHdrOffset, pHdrOffset + Elf.SizePhdr - 1, pHdr.offset, pHdr.filesz, pHdr.memsz, (uint)pHdr.type_, pHdr.type_);

                phdrs.Add(pHdr);
            }

            var exInfoOffset = Utils.AlignUp((ulong)(pHdrOffset + Elf.SizePhdr), 0x10);
            Byte[] dataExInfo = new Byte[Elf.SizeExInfo];
            Buffer.BlockCopy(data, (int)exInfoOffset, dataExInfo, 0, dataExInfo.Length);
            var exInfo = Utils.BytesToStruct<Elf.ExInfo>(dataExInfo);

            if (verbose)
                Console.WriteLine(
                    "\n   **Elf Extended info**\n" +
                    " Head position: {0:X}~{1:X}\n" +
                    " Paid         : 0x{2:X}\n" +
                    " Ptype        : {3}\n" +
                    " AppVersion   : {4:X}\n" +
                    " FwVersion    : {5:X}\n" +
                    " Digest       : {6:X}\n",
                    exInfoOffset, exInfoOffset + (uint)Elf.SizeExInfo - 1, exInfo.paid, exInfo.ptype, exInfo.appVersion, exInfo.fwVersion, BitConverter.ToString(exInfo.digest).Replace("-", ""));

            return true;
        }

        public bool TestIdent()
        {
            if (Elf.ELF_MAGIC != elfHdr.magic)
            {
                Console.WriteLine("File is invalid! e_ident magic: {0:X8}", elfHdr.magic);
                return false;
            }

            if (!(
                (elfHdr.cls           == Elf.ECLASS.CLASS64) &&
                (elfHdr.encoding      == Elf.EDATA.DATA2LSB) &&
                (elfHdr.legacyVersion == Elf.ELV.CURRENT) &&
                (elfHdr.osAbi         == Elf.EOSABI.FREEBSD)))
                return false;

            if (((UInt16)elfHdr.type_ >> 8) != 0xFE) // != ET_SCE_EXEC)
                Console.Write(" Elf64::e_type: 0x{0:X4} \n", elfHdr.type_);

            if (!((elfHdr.machine == Elf.EMachine.X86_64) && (elfHdr.version == Elf.EVersion.CURRENT))) return false;

            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="savePath"></param>
        public bool SaveToELF(string savePath)
        {
            if (phdrs.Count == 0 || entries.Count == 0) return false;

            Console.WriteLine("\n\nSaveToELF(\"{0}\")\n", savePath);

            Elf.ProgramHeader dynamicPH = default, dynlibDataPH = default, sceVersionPH = default, phFirst = default, phLast = default;
            foreach (Elf.ProgramHeader ph in phdrs)
            {
                if (ph.type_ == Elf.PhdrType.DYNAMIC) dynamicPH = ph;
                else if (ph.type_ == Elf.PhdrType.SCE_DYNLIBDATA) dynlibDataPH = ph;
                else if (ph.type_ == Elf.PhdrType.SCE_VERSION) sceVersionPH = ph;

                if (phFirst.Equals(default) || phFirst.offset == 0 /* try to get away from offset 0 */ ||
                    ph.offset > 0 && ph.offset < phFirst.offset //if the current first ph is not null and its offset is bigger than 0, then replace it only with a smaller ph that its offset is also bigger than 0
                    ) phFirst = ph;
                if (phLast.Equals(default) || ph.offset > phLast.offset) phLast = ph;
            }

            UInt64 first   = phFirst.Equals(default) ? 0 : phFirst.offset;
            UInt64 last    = phLast.Equals(default) ? 0 : phLast.offset;
            ulong saveSize = phLast.Equals(default) ? 0 : phLast.offset + phLast.filesz;
            if (saveSize > 0 && alignSize) saveSize = Utils.AlignUp(saveSize, 0x10); // in the original selfutil it was an alignment of PS4_PAGE_SIZE

            if (verbose)
            {
                Console.WriteLine("Save Size: {0} bytes (0x{1:X})", saveSize, saveSize);
                Console.WriteLine("first offset: {0:X}, last offset: {1:X}\n\n", first, last);
            }

            Array.Clear(save, 0, save.Length);
            Array.Resize(ref save, (int)saveSize);
            Buffer.BlockCopy(data, (int)elfHdrOffset, save, 0, (int)first); //u8* pd = &save[0];//memcpy(pd, eHead, first); //＃eHead = elfHOffs
            // just copy everything from head to what should be first seg offs

            for (int seIdx = 0; seIdx < entries.Count; seIdx++)
            {
                Self.Entry se = entries[seIdx];
                ulong phIdx = (se.props >> 20) & 0xFFF;
                Elf.ProgramHeader ph = phdrs[(int)phIdx];

                if (0 == (se.props & 0x800)) continue;

                if (verbose && ph.filesz != 0 && ph.filesz != se.memSz) Console.WriteLine("idx: {0} SEGMENT size: {1} != phdr size: {2}", phIdx, se.memSz, ph.filesz);

                Buffer.BlockCopy(data, (int)se.offs, save, (int)ph.offset, (int)se.fileSz); //void* srcp = (void*)((ulong)&data[0] + ee.offs);void* dstp = (void*)((ulong)pd + ph.p_offset);memcpy(dstp, srcp, ee->fileSz);

                if (verbose)
                {
                    Console.WriteLine("Load self Entry{0:00}: 0x{1:X8}~{2:X8} Size: 0x{3,-8:X}", seIdx, se.offs, se.offs + se.fileSz, se.fileSz);
                    Console.WriteLine("Save to Segment{0:00}: 0x{1:X8}~{2:X8} Type:{3}\n", phIdx, ph.offset, ph.offset + se.fileSz, ph.type_);
                }
            }

            if (verboseV)
            {
                int dynamicTableCount = (int)dynamicPH.memsz / Elf.sizeDynamic;
                ulong dynamicTableAddr = dynamicPH.offset;
                ulong relaTableAddr = dynlibDataPH.offset;
                ulong symTableAddr = dynlibDataPH.offset;
                ulong relaTableSize = 0;
                ulong symTableSize = 0;
                int relaTableCount = 0;
                int symTableCount = 0;

                Console.WriteLine("Dynamic offset:{0:X}, SCE_DYNLIBDATA offset:{1:X}", dynamicPH.offset, dynlibDataPH.offset);
                for (int dIdx = 0; dIdx < dynamicTableCount; dIdx++)
                {
                    var dynaBytes = new byte[Elf.sizeDynamic];
                    Buffer.BlockCopy(save, (int)dynamicPH.offset + (dIdx * Elf.sizeDynamic), dynaBytes, 0, Elf.sizeDynamic);
                    var dyna = Utils.BytesToStruct<Elf.Dynamic>(dynaBytes);

                    if (dyna.tag == Elf.DTag.SCE_NEEDED_MODULE ||
                        dyna.tag == Elf.DTag.SCE_IMPORT_LIB ||
                        dyna.tag == Elf.DTag.SCE_IMPORT_LIB_ATTR ||
                        dyna.tag == Elf.DTag.SCE_EXPORT_LIB ||
                        dyna.tag == Elf.DTag.SCE_EXPORT_LIB_ATTR ||
                        dyna.tag == Elf.DTag.SCE_MODULE_INFO ||
                        dyna.tag == Elf.DTag.SCE_MODULE_ATTR ||
                        dyna.tag == Elf.DTag.SCE_FINGERPRINT ||
                        dyna.tag == Elf.DTag.SCE_ORIGINAL_FILENAME)
                    {
                        (ulong id, ulong versionMinor, ulong versionMajor, ulong index) = Utils.ParseSceModuleVersion(dyna.val);
                        Console.WriteLine(" Tag:{0,-20} id:{1,4} version(Minor:{2} Major:{3}) index:{4,5}", dyna.tag, id, versionMinor, versionMajor, index);
                    }
                    else Console.WriteLine(" Tag:{0,-20} Val:{1,20:X}", dyna.tag, dyna.val);

                    if (dyna.tag == Elf.DTag.SCE_JMPREL) relaTableAddr += dyna.val;
                    else if (dyna.tag == Elf.DTag.SCE_PLTRELSZ) relaTableSize += dyna.val;
                    else if (dyna.tag == Elf.DTag.SCE_RELASZ) relaTableSize += dyna.val;
                    else if (dyna.tag == Elf.DTag.SCE_SYMTAB) symTableAddr += dyna.val;
                    else if (dyna.tag == Elf.DTag.SCE_SYMTABSZ) symTableSize += dyna.val;
                }
                symTableCount = (int)symTableSize / Elf.sizeSymbol;
                ulong dynDataOffset = dynlibDataPH.offset + 16 + 8;
                var dynlibDataBytes = new byte[symTableAddr - dynDataOffset];
                Buffer.BlockCopy(save, (int)dynDataOffset, dynlibDataBytes, 0, dynlibDataBytes.Length);
                var name = Encoding.UTF8.GetString(dynlibDataBytes);
                var names = name.Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);

                var startIdx = names.Length - symTableCount;

                Console.WriteLine("\nFound symbol table, entries: {0}\n", symTableCount);

                for (int sIdx = 0; sIdx < startIdx; sIdx++) Console.WriteLine(names[sIdx]);
                for (int sIdx = 0; sIdx < symTableCount; sIdx++)
                {
                    var symbolBytes = new byte[Elf.sizeSymbol];
                    var symbolOffset = (int)symTableAddr + sIdx * Elf.sizeSymbol;
                    Buffer.BlockCopy(save, symbolOffset, symbolBytes, 0, Elf.sizeSymbol);
                    var sym = Utils.BytesToStruct<Elf.Symbol>(symbolBytes);
                    Console.WriteLine("nameOffset:{0,6:X} info:{1,-20} {2,-20} other:{3} shndx:{4} value:{5} size:{6}", sym.name, sym.info, names[startIdx + sIdx], sym.other, sym.shndx, sym.value, sym.size);
                }
                relaTableCount = (int)relaTableSize / Elf.sizeRela;
                Console.WriteLine("Found relocation section, entries: {0}", relaTableCount);
                for (int rIdx = 0; rIdx < relaTableCount; rIdx++)
                {
                    var relaBytes = new byte[Elf.sizeRela];
                    var relaOffset = (int)relaTableAddr + rIdx * Elf.sizeRela;
                    Buffer.BlockCopy(save, relaOffset, relaBytes, 0, Elf.sizeRela);
                    var rela = Utils.BytesToStruct<Elf.Relocation>(relaBytes);
                    if (rela.addend == 0x67052d || rela.offset == 0x67052d) Console.WriteLine("test");
                    if (rela.sym > 0) Console.WriteLine("offset:{0,6:X} info:{1,-20} sym:{2} {3}", rela.offset, rela.info, rela.sym, names[startIdx + rela.sym]);
                    //else Console.WriteLine("offset:{0,6:X} info:{1,-20} addend:{2:X}", rela.offset, rela.info, rela.addend);
                }
            }

            if (!notPatchVerSeg && !sceVersionPH.Equals(default))
            {
                Elf.ProgramHeader ph = sceVersionPH;
                Console.WriteLine("\npatching version segment");
                int srcOffset = data.Length - (int)ph.filesz;
                if (verbose)
                {
                    Console.WriteLine("Load self Entry: 0x{0:X8}~{1:X8} Size: 0x{2,-8:X}", srcOffset, (uint)srcOffset + ph.filesz, ph.filesz);
                    Console.WriteLine("Save to Segment: 0x{0:X8}~{1:X8} Type:{2}\n", ph.offset, ph.offset + ph.filesz, ph.type_);
                }

                Buffer.BlockCopy(data, srcOffset, save, (int)ph.offset, (int)ph.filesz); //void* srcp = (void*)((ulong)&data[0] + data.capacity() - ph->p_filesz);void* dstp = (void*)((ulong)pd + ph.p_offset);memcpy(dstp, srcp, ee->fileSz);
                Console.WriteLine("patched version segment\n");
            }

            if (!notPatchFirstSegDup)
            {
                ulong firstMinOffset = 0, patchFirstSegSafetyPercentage = 2;// min amount of cells (in percentage) that should fit in other words
                for (int entriesIdx = 0; entriesIdx < entries.Count; entriesIdx++)
                {
                    var offset = entries[entriesIdx].offs - elfHdrOffset;
                    if (offset >= 0 && offset < first && (firstMinOffset == 0 || offset > firstMinOffset)) firstMinOffset = offset;
                }

                if (firstMinOffset != 0 && save[firstMinOffset] == 0)
                { // go forward looking for data
                    for (ulong idx = 1; firstMinOffset + idx < first; idx++)
                    {
                        if (save[firstMinOffset + idx] == 0) continue;
                        firstMinOffset += idx - 1;// go 1 place before the zero
                        break;
                    }
                }

                ulong firstLen = 0xC0;
                var firstBytes = new byte[firstLen];
                Buffer.BlockCopy(save, (int)first, firstBytes, 0, firstBytes.Length);
                for (ulong firstIdx = 0;
                    (firstMinOffset == 0 || firstIdx < firstMinOffset) &&
                    firstIdx < (first * (100 - patchFirstSegSafetyPercentage) / 100) && first - firstIdx >= firstLen;
                    firstIdx++)
                {
                    var chkBytes = new byte[firstLen];
                    Buffer.BlockCopy(save, (int)firstIdx, chkBytes, 0, chkBytes.Length);
                    if (!Utils.BytesCompare(chkBytes, firstBytes)) continue;
                    // was first - first_index instead of 0xC0, 
                    // but usually the first section's important data is at the size of 0xC0 and that goes for all the modules
                    firstMinOffset = firstIdx;
                    break;
                }

                if (firstMinOffset != 0)
                {
                    var emptyLen = first - firstMinOffset;
                    Console.WriteLine("\npatching first segment duplicate");

                    if (verbose) Console.WriteLine("address: 0x{0:X8}\tsize: 0x{1:X8}", firstMinOffset, emptyLen);

                    var empty = new byte[emptyLen];
                    Buffer.BlockCopy(empty, 0, save, (int)firstMinOffset, empty.Length); //set_u8_array(pd + firstMinOffset, 0, emptyLen);
                    Console.WriteLine("patched first segment duplicate");
                }
            }

            if (!dryRun) using (FileStream fs = new FileStream(savePath, FileMode.Create, FileAccess.ReadWrite, FileShare.Read)) fs.Write(save, 0, save.Length);

            return true;
        }
    }
}
