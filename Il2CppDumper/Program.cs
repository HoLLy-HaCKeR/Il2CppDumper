using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Il2CppDumper.ExecutableFormats;
using Newtonsoft.Json;
using static Il2CppDumper.DefineConstants;

namespace Il2CppDumper
{
    class Program
    {
        private static Config config = JsonConvert.DeserializeObject<Config>(File.ReadAllText(Path.Join(Environment.CurrentDirectory, @"config.json")));

        static void ShowHelp(string programName)
        {
            Console.WriteLine($"usage: {programName} path/to/global-metadata.dat path/to/libil2cpp.so");
            Environment.Exit(0);
        }

        [STAThread]
        static void Main(string[] args)
        {
            byte[] il2cppBytes = null;
            byte[] metadataBytes = null;

            if (args.Length == 1)
            {
                if (args[0] == "-h" || args[0] == "--help" || args[0] == "/?" || args[0] == "/h")
                {
                    ShowHelp(AppDomain.CurrentDomain.FriendlyName);
                    return;
                }
            }

            if (args.Length > 2)
            {
                ShowHelp(AppDomain.CurrentDomain.FriendlyName);
                return;
            }

            if (args.Length == 2)
            {
                var file1 = File.ReadAllBytes(args[0]);
                var file2 = File.ReadAllBytes(args[1]);
                if (BitConverter.ToUInt32(file1, 0) == 0xFAB11BAF)
                {
                    il2cppBytes = file2;
                    metadataBytes = file1;
                }
                else if (BitConverter.ToUInt32(file2, 0) == 0xFAB11BAF)
                {
                    il2cppBytes = file1;
                    metadataBytes = file2;
                }
            }
            if (il2cppBytes == null)
            {
                Console.WriteLine("Please pass an Il2CPP binary.");
                return;
            }
            if (Init(il2cppBytes, metadataBytes, out var metadata, out var il2cpp))
            {
                Dump(metadata, il2cpp);
            }
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey(true);
        }

        private static bool Init(byte[] il2cppBytes, byte[] metadataBytes, out Metadata metadata, out Il2Cpp il2cpp)
        {
            var sanity = BitConverter.ToUInt32(metadataBytes, 0);
            if (sanity != 0xFAB11BAF)
            {
                throw new Exception("ERROR: Metadata file supplied is not valid metadata file.");
            }

            float fixedMetadataVersion = GetFixedMetadataVersion(metadataBytes);

            Console.WriteLine("Initializing metadata...");
            metadata = new Metadata(new MemoryStream(metadataBytes), fixedMetadataVersion);

            Console.WriteLine("Initializing il2cpp file...");
            //判断il2cpp的magic
            var il2cppMagic = BitConverter.ToUInt32(il2cppBytes, 0);
            var version = config.ForceIl2CppVersion ? config.ForceVersion : metadata.version;
            il2cpp = GetIl2Cpp(il2cppBytes, il2cppMagic, version, metadata);

            Console.WriteLine("Select Mode: 1.Manual 2.Auto 3.Auto(Plus) 4.Auto(Symbol)");
            var modeKey = Console.ReadKey(true);
            if (modeKey.KeyChar != '1')
            {
                Console.WriteLine("Searching...");
            }
            try
            {
                bool success;
                switch (modeKey.KeyChar)
                {
                    case '1': //Manual
                        Console.Write("Input CodeRegistration: ");
                        var codeRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                        Console.Write("Input MetadataRegistration: ");
                        var metadataRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                        il2cpp.Init(codeRegistration, metadataRegistration);
                        success = true;
                        break;
                    case '2': //Auto
                        success = il2cpp.Search();
                        break;
                    case '3': //Auto(Plus)
                        success = il2cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length);
                        break;
                    case '4': //Auto(Symbol)
                        success = il2cpp.SymbolSearch();
                        break;
                    default:
                        Console.WriteLine("ERROR: You have to choose a mode.");
                        return false;
                }
                if (!success)
                    throw new Exception();
            }
            catch
            {
                throw new Exception("ERROR: Can't use this mode to process file, try another mode.");
            }

            return true;
        }

        private static Il2Cpp GetIl2Cpp(byte[] il2cppBytes, uint il2cppMagic, float version, Metadata metadata)
        {
            switch (il2cppMagic) {
                case 0x304F534E:
                    var nso = new NSO(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
                    return nso.UnCompress();
                case 0x905A4D: //PE
                    return new PE(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
                case 0x464c457f: //ELF
                    if (il2cppBytes[4] == 2) //ELF64
                        return new Elf64(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
                    else
                        return new Elf(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
                case 0xCAFEBABE: //FAT Mach-O
                case 0xBEBAFECA:
                    var machofat = new MachoFat(new MemoryStream(il2cppBytes));
                    Console.Write("Select Platform: ");
                    for (var i = 0; i < machofat.fats.Length; i++) {
                        var fat = machofat.fats[i];
                        Console.Write(fat.magic == 0xFEEDFACF ? $"{i + 1}.64bit " : $"{i + 1}.32bit ");
                    }

                    Console.WriteLine();
                    var key = Console.ReadKey(true);
                    var index = int.Parse(key.KeyChar.ToString()) - 1;
                    var magic = machofat.fats[index % 2].magic;
                    il2cppBytes = machofat.GetMacho(index % 2);
                    if (magic == 0xFEEDFACF)
                        goto case 0xFEEDFACF;
                    else
                        goto case 0xFEEDFACE;
                case 0xFEEDFACF: // 64bit Mach-O
                    return new Macho64(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
                case 0xFEEDFACE: // 32bit Mach-O
                    return new Macho(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
                default:
                    throw new Exception("ERROR: il2cpp file not supported.");
            }
        }

        private static float GetFixedMetadataVersion(byte[] metadataBytes)
        {
            var metadataVersion = BitConverter.ToInt32(metadataBytes, 4);
            if (metadataVersion != 24) return metadataVersion;

            Console.Write("Input Unity version: ");
            var stringVersion = Console.ReadLine();
            try {
                var versionSplit = Array.ConvertAll(Regex.Replace(stringVersion, @"\D", ".").Split(new[] { "." }, StringSplitOptions.RemoveEmptyEntries), int.Parse);
                var unityVersion = new Version(versionSplit[0], versionSplit[1]);
                if (unityVersion >= Unity20191) {
                    return 24.2f;
                } else if (unityVersion >= Unity20183) {
                    return 24.1f;
                } else {
                    return metadataVersion;
                }
            } catch {
                throw new Exception("You must enter the correct Unity version number");
            }
        }

        private static void Dump(Metadata metadata, Il2Cpp il2cpp)
        {
            Console.WriteLine("Dumping...");
            new ScriptGenerator(metadata, il2cpp, config).DumpScript();
            Console.WriteLine("Done !");
            //DummyDll
            if (config.DummyDll) {
                CreateDummyDll(metadata, il2cpp);
            }
        }

        private static void CreateDummyDll(Metadata metadata, Il2Cpp il2cpp)
        {
            Console.WriteLine("Create DummyDll...");
            if (Directory.Exists("DummyDll"))
                Directory.Delete("DummyDll", true);
            Directory.CreateDirectory("DummyDll");
            Directory.SetCurrentDirectory("DummyDll");

            using (Stream stream = typeof(DummyAssemblyCreator).Assembly.GetManifestResourceStream("Il2CppDumper.Resources.Il2CppDummyDll.dll"))
            using (var ms = new MemoryStream()) {
                stream.CopyTo(ms);
                File.WriteAllBytes("Il2CppDummyDll.dll", ms.ToArray());
            }

            var dummy = new DummyAssemblyCreator(metadata, il2cpp);
            foreach (var assembly in dummy.Assemblies) {
                var stream = new MemoryStream();
                assembly.Write(stream);
                File.WriteAllBytes(assembly.MainModule.Name, stream.ToArray());
            }

            Console.WriteLine("Done !");
        }
    }
}
