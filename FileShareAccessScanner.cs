// FileShareAccessScanner - Performance-optimized with async/parallel processing and domain controller support
//
// This utility scans a Windows network share for files and directories,
// collects critical permissions, and outputs results to a JSON file.
// It provides overview and filtering capabilities with enhanced performance
// and proper SID-to-username translation for domain environments.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FileShareAccessScanner
{
    /// <summary>
    /// Main program class for the FileShareAccessScanner utility.
    /// Provides entry point and command dispatching with performance optimizations.
    /// </summary>
    public class Program
    {
        // Constants for usage messages
        private const string UsageCollect = "Usage: collect <NetworkSharePath> <OutputFile> [--dc <DomainController>] [--domain <Domain>]";
        private const string UsageOverview = "Usage: overview <InputFile>";
        private const string UsageFilter = "Usage: filter <InputFile> <Username>";

        // Performance tuning constants - Fixed to use static readonly instead of const
        private static readonly int MaxDegreeOfParallelism = Environment.ProcessorCount * 2;
        private const int ProgressUpdateInterval = 50; // Update progress every 50 items

        // Domain controller and domain settings
        private static string DomainController { get; set; }
        private static string Domain { get; set; }

        /// <summary>
        /// Program entry point. Parses command-line arguments and dispatches commands.
        /// </summary>
        /// <param name="args">Command-line arguments.</param>
        public static async Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return;
            }

            string command = args[0].ToLowerInvariant();

            try
            {
                switch (command)
                {
                    case "collect":
                        await HandleCollectCommandAsync(args);
                        break;
                    case "overview":
                        HandleOverviewCommand(args);
                        break;
                    case "filter":
                        HandleFilterCommand(args);
                        break;
                    default:
                        Console.WriteLine("Unknown command.");
                        PrintUsage();
                        break;
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"[Access Error] {ex.Message}");
            }
            catch (IOException ex)
            {
                Console.WriteLine($"[IO Error] {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Unexpected Error] {ex.Message}");
            }
        }

        /// <summary>
        /// Prints usage instructions for the program.
        /// </summary>
        private static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  collect <NetworkSharePath> <OutputFile> [--dc <DomainController>] [--domain <Domain>]");
            Console.WriteLine("  overview <InputFile>");
            Console.WriteLine("  filter <InputFile> <Username>");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --dc <DomainController>    Specify domain controller for SID resolution");
            Console.WriteLine("  --domain <Domain>          Specify domain name (e.g., essos.local)");
        }

        /// <summary>
        /// Handles the 'collect' command asynchronously: scans the share and saves permissions.
        /// </summary>
        /// <param name="args">Command-line arguments.</param>
        /// <exception cref="ArgumentException">Thrown if arguments are invalid.</exception>
        private static async Task HandleCollectCommandAsync(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine(UsageCollect);
                return;
            }

            string sharePath = args[1];
            string outputFile = args[2];

            // Parse optional arguments
            ParseOptionalArguments(args);

            Console.WriteLine("Estimating files and directories...");
            long totalItems = 0;

            try
            {
                totalItems = await CountFileSystemEntriesAsync(sharePath);
                Console.WriteLine($"Estimated items to scan: {totalItems}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error during counting] {ex.Message}");
                return;
            }

            Console.WriteLine("Scanning for permissions...");
            if (!string.IsNullOrEmpty(DomainController))
            {
                Console.WriteLine($"Using domain controller: {DomainController}");
            }
            if (!string.IsNullOrEmpty(Domain))
            {
                Console.WriteLine($"Using domain: {Domain}");
            }

            var progressTracker = new ProgressTracker(totalItems);
            var collected = await GetFileShareCriticalPermissionsAsync(sharePath, progressTracker);

            var jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            await WriteJsonToFileAsync(outputFile, collected, jsonOptions);
            Console.WriteLine($"\nPermissions saved to {outputFile}");
            Console.WriteLine($"Total entries collected: {collected.Count}");
        }

        /// <summary>
        /// Parses optional command-line arguments for domain controller and domain specification.
        /// </summary>
        /// <param name="args">Command-line arguments array.</param>
        private static void ParseOptionalArguments(string[] args)
        {
            for (int i = 0; i < args.Length - 1; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--dc":
                    case "-dc":
                        DomainController = args[i + 1];
                        break;
                    case "--domain":
                    case "-domain":
                        Domain = args[i + 1];
                        break;
                }
            }
        }

        /// <summary>
        /// Handles the 'overview' command: shows summary of permissions by user.
        /// </summary>
        /// <param name="args">Command-line arguments.</param>
        /// <exception cref="ArgumentException">Thrown if arguments are invalid.</exception>
        private static void HandleOverviewCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine(UsageOverview);
                return;
            }

            var overviewData = LoadAccessEntries(args[1]);
            var grouped = overviewData
                .Where(e => !string.IsNullOrEmpty(e.Username))
                .GroupBy(e => e.Username)
                .Select(g => new { Name = g.Key, Count = g.Count() })
                .OrderByDescending(g => g.Count);

            Console.WriteLine("Username\tCount");
            Console.WriteLine(new string('-', 50));
            foreach (var g in grouped)
                Console.WriteLine($"{g.Name}\t{g.Count}");
        }

        /// <summary>
        /// Handles the 'filter' command: shows permissions for a specific user.
        /// </summary>
        /// <param name="args">Command-line arguments.</param>
        /// <exception cref="ArgumentException">Thrown if arguments are invalid.</exception>
        private static void HandleFilterCommand(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine(UsageFilter);
                return;
            }

            var filterData = LoadAccessEntries(args[1]);
            string usernameFilter = args[2];
            var filtered = filterData.Where(e =>
                e.Username != null &&
                e.Username.IndexOf(usernameFilter, StringComparison.OrdinalIgnoreCase) >= 0);

            Console.WriteLine("Path\tUsername\tAccessRight\tInherited");
            Console.WriteLine(new string('-', 80));
            foreach (var entry in filtered)
                Console.WriteLine($"{entry.Path}\t{entry.Username}\t{entry.AccessRight}\t{entry.IsInherited}");
        }

        /// <summary>
        /// Writes JSON data to a file asynchronously with .NET Framework compatibility.
        /// </summary>
        /// <param name="filePath">Path to write the file.</param>
        /// <param name="data">Data to serialize.</param>
        /// <param name="options">JSON serialization options.</param>
        private static async Task WriteJsonToFileAsync(string filePath, object data, JsonSerializerOptions options)
        {
            var json = JsonSerializer.Serialize(data, options);
            var bytes = Encoding.UTF8.GetBytes(json);
            using (var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, useAsync: true))
            {
                await stream.WriteAsync(bytes, 0, bytes.Length);
            }
        }

        /// <summary>
        /// Counts all files and directories asynchronously using enumeration.
        /// </summary>
        /// <param name="path">Root directory or file path.</param>
        /// <returns>Total count of files and directories.</returns>
        /// <exception cref="UnauthorizedAccessException">Thrown if access is denied.</exception>
        /// <exception cref="IOException">Thrown if an IO error occurs.</exception>
        public static async Task<long> CountFileSystemEntriesAsync(string path)
        {
            return await Task.Run(() =>
            {
                long count = 0;
                var stack = new Stack<string>();
                stack.Push(path);

                while (stack.Count > 0)
                {
                    var currentPath = stack.Pop();
                    count++;

                    if (Directory.Exists(currentPath))
                    {
                        try
                        {
                            // Use EnumerateFileSystemEntries for better performance
                            foreach (var entry in Directory.EnumerateFileSystemEntries(currentPath))
                            {
                                stack.Push(entry);
                            }
                        }
                        catch (UnauthorizedAccessException)
                        {
                            // Skip inaccessible directories
                            continue;
                        }
                        catch (IOException)
                        {
                            // Skip problematic directories
                            continue;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[Count Error] {currentPath}: {ex.Message}");
                            continue;
                        }
                    }
                }

                return count;
            });
        }

        /// <summary>
        /// Scans for critical permissions asynchronously with parallel processing.
        /// </summary>
        /// <param name="networkSharePath">Network share root path.</param>
        /// <param name="progressTracker">Progress tracking instance.</param>
        /// <returns>List of <see cref="AccessEntry"/> objects with critical permissions.</returns>
        public static async Task<List<AccessEntry>> GetFileShareCriticalPermissionsAsync(
            string networkSharePath,
            ProgressTracker progressTracker)
        {
            var result = new ConcurrentBag<AccessEntry>();
            var semaphore = new SemaphoreSlim(MaxDegreeOfParallelism);

            await ProcessDirectoryAsync(networkSharePath, result, progressTracker, semaphore);

            progressTracker.Complete();
            return result.ToList();
        }

        /// <summary>
        /// Recursively processes directories and files asynchronously.
        /// </summary>
        /// <param name="path">Current path to process.</param>
        /// <param name="result">Concurrent collection for results.</param>
        /// <param name="progressTracker">Progress tracking instance.</param>
        /// <param name="semaphore">Semaphore to control parallelism.</param>
        private static async Task ProcessDirectoryAsync(
            string path,
            ConcurrentBag<AccessEntry> result,
            ProgressTracker progressTracker,
            SemaphoreSlim semaphore)
        {
            await semaphore.WaitAsync();

            try
            {
                // Process current item
                await ProcessItemAsync(path, result, progressTracker);

                if (Directory.Exists(path))
                {
                    var tasks = new List<Task>();

                    try
                    {
                        // Use EnumerateFileSystemEntries for better performance
                        var entries = Directory.EnumerateFileSystemEntries(path).ToList();

                        // Process files in parallel batches - Fixed for .NET Framework compatibility
                        var files = entries.Where(File.Exists).ToList();
                        if (files.Any())
                        {
                            tasks.Add(ProcessFilesInParallelAsync(files, result, progressTracker));
                        }

                        // Process subdirectories recursively
                        var directories = entries.Where(Directory.Exists).ToList();
                        foreach (var directory in directories)
                        {
                            tasks.Add(ProcessDirectoryAsync(directory, result, progressTracker, semaphore));
                        }

                        await Task.WhenAll(tasks);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // Skip inaccessible directories
                    }
                    catch (IOException)
                    {
                        // Skip problematic directories
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"\n[Error] {path}: {ex.Message}");
                    }
                }
            }
            finally
            {
                semaphore.Release();
            }
        }

        /// <summary>
        /// Processes files in parallel with .NET Framework compatibility.
        /// </summary>
        /// <param name="files">Collection of file paths to process.</param>
        /// <param name="result">Concurrent collection for results.</param>
        /// <param name="progressTracker">Progress tracking instance.</param>
        private static async Task ProcessFilesInParallelAsync(IEnumerable<string> files,
            ConcurrentBag<AccessEntry> result,
            ProgressTracker progressTracker)
        {
            var semaphore = new SemaphoreSlim(MaxDegreeOfParallelism);
            var tasks = files.Select(async file =>
            {
                await semaphore.WaitAsync();
                try
                {
                    await ProcessItemAsync(file, result, progressTracker);
                }
                finally
                {
                    semaphore.Release();
                }
            });
            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Processes a single file or directory item asynchronously.
        /// </summary>
        /// <param name="path">Path to process.</param>
        /// <param name="result">Concurrent collection for results.</param>
        /// <param name="progressTracker">Progress tracking instance.</param>
        private static async Task ProcessItemAsync(
            string path,
            ConcurrentBag<AccessEntry> result,
            ProgressTracker progressTracker)
        {
            await Task.Run(() =>
            {
                try
                {
                    if (!Directory.Exists(path) && !File.Exists(path))
                    {
                        progressTracker.Increment();
                        return;
                    }

                    FileSystemSecurity acl;
                    if (Directory.Exists(path))
                    {
                        acl = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
                    }
                    else
                    {
                        acl = new FileInfo(path).GetAccessControl(AccessControlSections.Access);
                    }

                    var rules = acl.GetAccessRules(true, true, typeof(NTAccount))
                        .Cast<FileSystemAccessRule>()
                        .Where(rule => !IsSystemAccount(rule.IdentityReference));

                    foreach (var rule in rules)
                    {
                        var criticalRights = GetCriticalRights(rule.FileSystemRights);

                        foreach (var right in criticalRights)
                        {
                            // Enhanced SID-to-username translation
                            string username = GetUsernameFromIdentity(rule.IdentityReference);
                            string sid = GetSafeIdentifier(rule.IdentityReference);

                            var entry = new AccessEntry
                            {
                                Path = path,
                                Username = username,
                                SID = sid,
                                AccessRight = right.ToString(),
                                IsInherited = rule.IsInherited
                            };

                            result.Add(entry);
                        }
                    }

                    progressTracker.Increment();
                }
                catch (UnauthorizedAccessException)
                {
                    progressTracker.Increment();
                }
                catch (IOException)
                {
                    progressTracker.Increment();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\n[Error] {path}: {ex.Message}");
                    progressTracker.Increment();
                }
            });
        }

        /// <summary>
        /// Enhanced username resolution with domain controller support.
        /// </summary>
        /// <param name="identity">Identity reference to resolve.</param>
        /// <returns>Resolved username or SID if resolution fails.</returns>
        private static string GetUsernameFromIdentity(IdentityReference identity)
        {
            try
            {
                // If it's already an NTAccount, return the value
                if (identity is NTAccount ntAccount)
                {
                    return ntAccount.Value;
                }

                // If it's a SecurityIdentifier, try multiple resolution methods
                if (identity is SecurityIdentifier sid)
                {
                    // First try: Standard translation
                    try
                    {
                        var translatedAccount = sid.Translate(typeof(NTAccount)) as NTAccount;
                        if (translatedAccount != null)
                        {
                            return translatedAccount.Value;
                        }
                    }
                    catch (IdentityNotMappedException)
                    {
                        // Continue to next method
                    }

                    // Second try: Use domain controller if specified
                    if (!string.IsNullOrEmpty(DomainController) && !string.IsNullOrEmpty(Domain))
                    {
                        string username = ResolveUsernameWithDomainController(sid.Value);
                        if (!string.IsNullOrEmpty(username))
                        {
                            return username;
                        }
                    }

                    // Third try: LDAP lookup
                    string ldapUsername = ResolveUsernameWithLDAP(sid.Value);
                    if (!string.IsNullOrEmpty(ldapUsername))
                    {
                        return ldapUsername;
                    }
                }

                // Try direct translation for other types
                var translated = identity.Translate(typeof(NTAccount)) as NTAccount;
                return translated?.Value ?? identity.Value;
            }
            catch (IdentityNotMappedException)
            {
                // Return SID if username cannot be resolved
                return identity.Value;
            }
            catch (SystemException)
            {
                // Handle other system exceptions
                return identity.Value;
            }
        }

        /// <summary>
        /// Resolves username using specified domain controller.
        /// </summary>
        /// <param name="sidValue">SID to resolve.</param>
        /// <returns>Resolved username or null if resolution fails.</returns>
        private static string ResolveUsernameWithDomainController(string sidValue)
        {
            try
            {
                using (var principalContext = new PrincipalContext(
                    ContextType.Domain,
                    DomainController,
                    $"DC={Domain.Replace(".", ",DC=")}"
                ))
                {
                    var userPrincipal = UserPrincipal.FindByIdentity(
                        principalContext,
                        IdentityType.Sid,
                        sidValue
                    );

                    if (userPrincipal != null)
                    {
                        return $"{Domain}\\{userPrincipal.SamAccountName}";
                    }

                    // Try group lookup
                    var groupPrincipal = GroupPrincipal.FindByIdentity(
                        principalContext,
                        IdentityType.Sid,
                        sidValue
                    );

                    if (groupPrincipal != null)
                    {
                        return $"{Domain}\\{groupPrincipal.SamAccountName}";
                    }
                }
            }
            catch (Exception)
            {
                // Fall back to other methods
            }

            return null;
        }

        /// <summary>
        /// Resolves username using LDAP lookup.
        /// </summary>
        /// <param name="sidValue">SID to resolve.</param>
        /// <returns>Resolved username or null if resolution fails.</returns>
        private static string ResolveUsernameWithLDAP(string sidValue)
        {
            try
            {
                string ldapPath = !string.IsNullOrEmpty(DomainController)
                    ? $"LDAP://{DomainController}/<SID={sidValue}>"
                    : $"LDAP://<SID={sidValue}>";

                using (var directoryEntry = new DirectoryEntry(ldapPath))
                {
                    directoryEntry.RefreshCache(new[] { "sAMAccountName", "distinguishedName" });
                    var samAccountName = directoryEntry.Properties["sAMAccountName"].Value?.ToString();
                    var distinguishedName = directoryEntry.Properties["distinguishedName"].Value?.ToString();

                    if (!string.IsNullOrEmpty(samAccountName) && !string.IsNullOrEmpty(distinguishedName))
                    {
                        // Extract domain from distinguished name
                        var domainParts = distinguishedName.Split(',')
                            .Where(part => part.Trim().StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                            .Select(part => part.Substring(3).Trim())
                            .ToArray();

                        string domainName = string.Join(".", domainParts);
                        return $"{domainName}\\{samAccountName}";
                    }
                }
            }
            catch (Exception)
            {
                // LDAP resolution failed
            }

            return null;
        }

        /// <summary>
        /// Safely gets the security identifier for an identity reference.
        /// </summary>
        /// <param name="identity">Identity reference to translate.</param>
        /// <returns>String representation of the SID, or the original value if translation fails.</returns>
        private static string GetSafeIdentifier(IdentityReference identity)
        {
            try
            {
                if (identity is SecurityIdentifier sid)
                {
                    return sid.Value;
                }
                return identity.Translate(typeof(SecurityIdentifier)).ToString();
            }
            catch
            {
                return identity.Value;
            }
        }

        /// <summary>
        /// Determines if an identity reference represents a system account that should be filtered out.
        /// </summary>
        /// <param name="identity">Identity reference to check.</param>
        /// <returns>True if the identity is a system account, false otherwise.</returns>
        private static bool IsSystemAccount(IdentityReference identity)
        {
            try
            {
                var sid = identity.Translate(typeof(SecurityIdentifier)).ToString();
                return SystemSids.Contains(sid) ||
                       sid.EndsWith("-520") ||
                       sid.EndsWith("-512") ||
                       sid.EndsWith("-519");
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Extracts critical rights from the given file system rights.
        /// </summary>
        /// <param name="rights">File system rights to analyze.</param>
        /// <returns>Enumerable of critical rights found.</returns>
        private static IEnumerable<FileSystemRights> GetCriticalRights(FileSystemRights rights)
        {
            return CriticalRights.Where(criticalRight => rights.HasFlag(criticalRight));
        }

        /// <summary>
        /// Loads access entries from a JSON file.
        /// </summary>
        /// <param name="path">Path to the JSON file.</param>
        /// <returns>List of <see cref="AccessEntry"/> objects.</returns>
        /// <exception cref="IOException">Thrown if the file cannot be read.</exception>
        private static List<AccessEntry> LoadAccessEntries(string path)
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<List<AccessEntry>>(json) ?? new List<AccessEntry>();
        }

        /// <summary>
        /// Represents a file or directory access entry.
        /// </summary>
        public class AccessEntry
        {
            /// <summary>
            /// Full path to the file or directory.
            /// </summary>
            public string Path { get; set; } = string.Empty;

            /// <summary>
            /// Username associated with the access rule.
            /// </summary>
            public string Username { get; set; } = string.Empty;

            /// <summary>
            /// Security Identifier (SID) of the user or group.
            /// </summary>
            public string SID { get; set; } = string.Empty;

            /// <summary>
            /// Name of the access right.
            /// </summary>
            public string AccessRight { get; set; } = string.Empty;

            /// <summary>
            /// Indicates whether the access rule is inherited.
            /// </summary>
            public bool IsInherited { get; set; }
        }

        /// <summary>
        /// Progress tracking utility for console output.
        /// </summary>
        public class ProgressTracker
        {
            private readonly long _total;
            private long _processed;
            private readonly object _lock = new object();
            private DateTime _lastUpdate = DateTime.Now;

            /// <summary>
            /// Initializes a new instance of the ProgressTracker class.
            /// </summary>
            /// <param name="total">Total number of items to process.</param>
            public ProgressTracker(long total)
            {
                _total = total;
                _processed = 0;
            }

            /// <summary>
            /// Increments the processed count and updates the progress display.
            /// </summary>
            public void Increment()
            {
                lock (_lock)
                {
                    _processed++;

                    // Throttle updates to improve performance
                    if (_processed % ProgressUpdateInterval == 0 ||
                        DateTime.Now - _lastUpdate > TimeSpan.FromSeconds(1))
                    {
                        UpdateProgress();
                        _lastUpdate = DateTime.Now;
                    }
                }
            }

            /// <summary>
            /// Marks processing as complete and shows final progress.
            /// </summary>
            public void Complete()
            {
                lock (_lock)
                {
                    _processed = _total;
                    UpdateProgress();
                    Console.WriteLine(); // New line after progress bar
                }
            }

            /// <summary>
            /// Updates the progress bar display.
            /// </summary>
            private void UpdateProgress()
            {
                const int width = 50;
                double percent = _total == 0 ? 1.0 : (double)_processed / _total;
                int progress = (int)(percent * width);

                Console.CursorLeft = 0;
                Console.Write("[");
                Console.Write(new string('#', progress));
                Console.Write(new string(' ', width - progress));
                Console.Write($"] {percent:P1} ({_processed:N0}/{_total:N0})");
            }
        }

        /// <summary>
        /// Set of critical file system rights to be collected.
        /// </summary>
        private static readonly HashSet<FileSystemRights> CriticalRights = new HashSet<FileSystemRights>
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
        };

        /// <summary>
        /// Set of system SIDs to filter out from results.
        /// </summary>
        private static readonly HashSet<string> SystemSids = new HashSet<string>
        {
            "S-1-5-18",  // Local System
            "S-1-3-0",   // Creator Owner
            "S-1-5-32-544" // Administrators
        };
    }
}
