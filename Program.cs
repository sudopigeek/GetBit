using System;
using System.IO;
using System.Management;
using System.Diagnostics;

namespace getbit
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine("\n===== GetBit version 1.1 by Ferrell Technology =====\n");
                Console.WriteLine("\nSpecify an .exe or .dll file to analyze as an argument.");
                Console.WriteLine("\nExample Usage: getbit [C:\\Path\\To\\File]");
                var process = ParentProcess();
                if (process != "cmd")
                {
                    Console.WriteLine("\nPress any key to exit.");
                    Console.ReadKey(true);
                }
                Console.ResetColor();
            }
            else
            {
                if (args[0].StartsWith("\"") == true)
                {
                    string path = string.Join(" ", args, 0, args.Length);
                    if (!File.Exists(path))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\nThe file you specified doesn't exist.");
                        Console.ResetColor();
                    }
                    else
                    {
                        var output = UnmanagedDllIs64Bit(path);
                        if (output == "True")
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\nThe assembly is 64-bit.");
                            Console.ResetColor();
                        }
                        else if (output == "False")
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\nThe assembly is 32-bit.");
                            Console.ResetColor();
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("\nThe bit of this assembly is unknown.");
                            Console.ResetColor();
                        }
                    }
                }
                else if (args[0].StartsWith("\"") == false)
                {
                    if (!File.Exists(args[0]))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\nThe file you specified doesn't exist.");
                        Console.ResetColor();
                    }
                    else
                    {
                        var output = UnmanagedDllIs64Bit(args[0]);
                        if (output == "True")
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\nThe assembly is 64-bit.");
                            Console.ResetColor();
                        }
                        else if (output == "False")
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\nThe assembly is 32-bit.");
                            Console.ResetColor();
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("\nThe bit of this assembly is unknown.");
                            Console.ResetColor();
                        }
                    }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\nInvalid parameter.");
                    Console.ResetColor();
                }
            }
        }

        private static string ParentProcess()
        {
            var myId = Process.GetCurrentProcess().Id;
            var query = string.Format("SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {0}", myId);
            var search = new ManagementObjectSearcher("root\\CIMV2", query);
            var results = search.Get().GetEnumerator();
            results.MoveNext();
            var queryObj = results.Current;
            var parentId = (uint)queryObj["ParentProcessId"];
            return Process.GetProcessById((int)parentId).ProcessName;
        }

        private static string UnmanagedDllIs64Bit(string dllPath)
        {
            switch (GetDllMachineType(dllPath))
            {
                case MachineType.IMAGE_FILE_MACHINE_AMD64:
                case MachineType.IMAGE_FILE_MACHINE_IA64:
                    return "True";
                case MachineType.IMAGE_FILE_MACHINE_I386:
                    return "False";
                default:
                    return string.Empty;
            }
        }

        private enum MachineType : ushort
        {
            IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
            IMAGE_FILE_MACHINE_AM33 = 0x1d3,
            IMAGE_FILE_MACHINE_AMD64 = 0x8664,
            IMAGE_FILE_MACHINE_ARM = 0x1c0,
            IMAGE_FILE_MACHINE_EBC = 0xebc,
            IMAGE_FILE_MACHINE_I386 = 0x14c,
            IMAGE_FILE_MACHINE_IA64 = 0x200,
            IMAGE_FILE_MACHINE_M32R = 0x9041,
            IMAGE_FILE_MACHINE_MIPS16 = 0x266,
            IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
            IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
            IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
            IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
            IMAGE_FILE_MACHINE_R4000 = 0x166,
            IMAGE_FILE_MACHINE_SH3 = 0x1a2,
            IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
            IMAGE_FILE_MACHINE_SH4 = 0x1a6,
            IMAGE_FILE_MACHINE_SH5 = 0x1a8,
            IMAGE_FILE_MACHINE_THUMB = 0x1c2,
            IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169,
        }

        private static MachineType GetDllMachineType(string dllPath)
        {
            FileStream fs = new FileStream(dllPath, FileMode.Open, FileAccess.Read);
            BinaryReader br = new BinaryReader(fs);
            fs.Seek(0x3c, SeekOrigin.Begin);
            Int32 peOffset = br.ReadInt32();
            fs.Seek(peOffset, SeekOrigin.Begin);
            UInt32 peHead = br.ReadUInt32();

            if (peHead != 0x00004550) // "PE\0\0", little-endian
                throw new Exception("Can't find PE header");

            MachineType machineType = (MachineType)br.ReadUInt16();
            br.Close();
            fs.Close();
            return machineType;
        }
    }
}
