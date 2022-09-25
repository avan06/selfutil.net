using System;
using System.Collections.Generic;
using System.IO;
using static selfutil.Argparse;

namespace selfutil
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Argparse parser = new Argparse("Selfutil.Net");

            parser.Add("input", "old file", true);
            parser.Add("output", "new file, save as <input>.elf file when not specified");
            parser.Add("--verbose|-v", "show details", ActionEnum.StoreTrue);
            parser.Add("-vv", "show very verbose details", ActionEnum.StoreTrue);
            parser.Add("--dry-run|-d", "dry run", ActionEnum.StoreTrue);
            parser.Add("--overwrite|-o", "overwrite input file when the output path is not specified", ActionEnum.StoreTrue);
            parser.Add("--align-size|-a", "make elf file align size", ActionEnum.StoreTrue);
            parser.Add("--not-patch-first-segment-duplicate|-nf", "not patch first segment duplicate", ActionEnum.StoreTrue);
            parser.Add("--not-patch-version-segment|-nv", "not patch version segment", ActionEnum.StoreTrue);

            parser.ParseArgs();

            Dictionary<string, Argument> argDict = parser.Arguments();
            bool verbose             = argDict["--verbose"].Value == "true";
            bool verboseV            = argDict["-vv"].Value == "true";
            bool dryRun              = argDict["--dry-run"].Value == "true";
            bool overwrite           = argDict["--overwrite"].Value == "true";
            bool alignSize           = argDict["--align-size"].Value == "true";
            bool notPatchFirstSegDup = argDict["--not-patch-first-segment-duplicate"].Value == "true";
            bool notPatchVerSeg      = argDict["--not-patch-version-segment"].Value == "true";
            if (verboseV) verbose = true;

            string inputFilePath = argDict["input"].Value;
            if (!File.Exists(inputFilePath)) parser.Error(string.Format("invalid input file: {0}", inputFilePath));

            string outputFilePath = argDict["output"].Value;
            if (outputFilePath == "") outputFilePath = overwrite ? inputFilePath : Path.ChangeExtension(inputFilePath, ".elf");

            SelfUtil util = new SelfUtil(inputFilePath, dryRun, alignSize, notPatchFirstSegDup, notPatchVerSeg, verbose, verboseV);

            if (!util.SaveToELF(outputFilePath)) Console.WriteLine("Error, Save to ELF failed!");
        }
    }
}