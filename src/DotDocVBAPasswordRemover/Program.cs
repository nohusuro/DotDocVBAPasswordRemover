using System;
using System.IO;
using System.Linq;

namespace DotDocVBAPasswordRemover
{
    public enum ExitErrorCode
    {
        OK = 0,
        FileNotFound = 1,
        FileSignatureMismatch = 2,
        CorruptFile = 3,
        SearchEndedWithNoResults = 4,
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return;
            }

            var file = args[0];

            if (!File.Exists(file))
            {
                Exit(ExitErrorCode.FileNotFound, "File passed on command line cannot be found.");
            }

            FileInfo file_info = new FileInfo(file);

            var cfbf_signature = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
            var doc_signature = new byte[cfbf_signature.Length];
            var find_bytes = new byte[] { 0x44, 0x50, 0x42 };     // DPB
            var replace_bytes = new byte[] { 0x44, 0x50, 0x78 };  // DPx

            using (var file_stream = new FileStream(file, FileMode.Open))
            {
                var bytes_read = file_stream.Read(doc_signature, 0, doc_signature.Length);

                if (bytes_read < doc_signature.Length)
                {
                    Exit(ExitErrorCode.CorruptFile, "File was too short. Corrupt file?");
                }

                if (!cfbf_signature.SequenceEqual(doc_signature))
                {
                    Exit(ExitErrorCode.FileSignatureMismatch, "File was not recognized as a valid format. Signature mismatch.");
                }

                Console.WriteLine("Searching for DPB pattern which indicates protected VBA project...");

                var search_index = 0;
                while (file_stream.Position < file_stream.Length)
                {
                    var b = file_stream.ReadByte();
                    
                    if (b.Equals(find_bytes[search_index]))
                    {
                        search_index++;
                    }
                    else
                    {
                        search_index = 0;
                    }

                    if (search_index == find_bytes.Length - 1)
                    {
                        Console.WriteLine("DPB pattern found. Corrupting...");
                        file_stream.Position = (file_stream.Position - find_bytes.Length) + 1;

                        foreach (var rb in replace_bytes)
                        {
                            file_stream.WriteByte(rb);
                        }

                        break;
                    }
                }

                if (search_index != find_bytes.Length - 1)
                {
                    Exit(ExitErrorCode.SearchEndedWithNoResults, "Search ended with no resulsts. Did not find DPB pattern within file.");
                }

                Exit(ExitErrorCode.OK, "Successfully bypassed VBA protection.");
            }
        }

        private static void Exit(ExitErrorCode exitCode, string exitMessage)
        {
            if (!string.IsNullOrEmpty(exitMessage))
            {
                if (exitCode != ExitErrorCode.OK)
                {
                    Console.WriteLine(exitMessage);
                }
                else
                {
                    Console.Error.WriteLine(exitMessage);
                }
            }

            Environment.Exit((int)exitCode);
        }

        public static void PrintUsage()
        {
            Console.WriteLine($"{Environment.GetCommandLineArgs()[0]} file");
        }
    }
}
