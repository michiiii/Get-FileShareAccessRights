// FileShareAccessScanner - Full version with collect/analyze support
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace FileShareAccessScanner
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  collect <NetworkSharePath> <OutputFile>");
                Console.WriteLine("  overview <InputFile>");
                Console.WriteLine("  filter <InputFile> <Username>");
                return;
            }

            string command = args[0].ToLower();

            switch (command)
            {
                case "collect":
                    if (args.Length < 3)
                    {
                        Console.WriteLine("Usage: collect <NetworkSharePath> <OutputFile>");
                        return;
                    }
                    var collected = GetFileShareCriticalPermissions(args[1]);
                    File.WriteAllText(args[2], JsonSerializer.Serialize(collected, new JsonSerializerOptions { WriteIndented = true }));
                    Console.WriteLine($"Permissions saved to {args[2]}");
                    break;

                case "overview":
                    if (args.Length < 2)
                    {
                        Console.WriteLine("Usage: overview <InputFile>");
                        return;
                    }
                    var overviewData = LoadAccessEntries(args[1]);
                    var grouped = overviewData.GroupBy(e => e.Username)
                                               .Select(g => new { Name = g.Key, Count = g.Count() });
                    Console.WriteLine("Username\tCount");
                    foreach (var g in grouped)
                        Console.WriteLine($"{g.Name}\t{g.Count}");
                    break;

                case "filter":
                    if (args.Length < 3)
                    {
                        Console.WriteLine("Usage: filter <InputFile> <Username>");
                        return;
                    }
                    var filterData = LoadAccessEntries(args[1]);
                    string usernameFilter = args[2];
                    var filtered = filterData.Where(e => e.Username != null && e.Username.IndexOf(usernameFilter, StringComparison.OrdinalIgnoreCase) >= 0);
                    Console.WriteLine("Path\tUsername\tAccessRight\tInherited");
                    foreach (var entry in filtered)
                        Console.WriteLine($"{entry.Path}\t{entry.Username}\t{entry.AccessRight}\t{entry.IsInherited}");
                    break;

                default:
                    Console.WriteLine("Unknown command.");
                    break;
            }
        }

        public static List<AccessEntry> GetFileShareCriticalPermissions(string networkSharePath)
        {
            var result = new List<AccessEntry>();
            RecursivelyEvaluate(networkSharePath, result);
            return result;
        }

        private static void RecursivelyEvaluate(string path, List<AccessEntry> output)
        {
            if (!Directory.Exists(path) && !File.Exists(path)) return;

            try
            {
                FileSystemSecurity acl;
                if (Directory.Exists(path))
                {
                    acl = new DirectoryInfo(path).GetAccessControl();
                }
                else if (File.Exists(path))
                {
                    acl = new FileInfo(path).GetAccessControl();
                }
                else
                {
                    return;
                }

                foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(NTAccount)))
                {
                    var sid = rule.IdentityReference.Translate(typeof(SecurityIdentifier)).ToString();

                    if (sid == "S-1-5-18" || sid == "S-1-3-0" ||
                        sid.EndsWith("-520") || sid.EndsWith("-512") || sid.EndsWith("-519") ||
                        sid == "S-1-5-32-544")
                        continue;

                    var rights = Enum.GetValues(typeof(FileSystemRights))
                        .Cast<FileSystemRights>()
                        .Where(r => rule.FileSystemRights.HasFlag(r));

                    foreach (var right in rights)
                    {
                        if (new[]
                        {
                            FileSystemRights.ChangePermissions,
                            FileSystemRights.TakeOwnership,
                            FileSystemRights.Write,
                            FileSystemRights.AppendData,
                            FileSystemRights.CreateFiles,
                            FileSystemRights.Delete,
                            FileSystemRights.WriteData,
                            FileSystemRights.WriteAttributes,
                            FileSystemRights.WriteExtendedAttributes
                        }.Contains(right))
                        {
                            output.Add(new AccessEntry
                            {
                                Path = path,
                                Username = rule.IdentityReference.Value,
                                SID = sid,
                                AccessRight = right.ToString(),
                                IsInherited = rule.IsInherited
                            });
                        }
                    }
                }

                if (Directory.Exists(path))
                {
                    foreach (var entry in Directory.GetFileSystemEntries(path))
                    {
                        RecursivelyEvaluate(entry, output);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] {path}: {ex.Message}");
            }
        }

        private static List<AccessEntry> LoadAccessEntries(string path)
        {
            return JsonSerializer.Deserialize<List<AccessEntry>>(File.ReadAllText(path));
        }

        public class AccessEntry
        {
            public string Path { get; set; }
            public string Username { get; set; }
            public string SID { get; set; }
            public string AccessRight { get; set; }
            public bool IsInherited { get; set; }
        }
    }
}
