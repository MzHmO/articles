using System;
using System.DirectoryServices;

namespace ADUserScriptPathUpdater
{
    class Program
    {
        static void Main(string[] args)
        {
            string userName = null;
            string scriptPath = null;
            string domainDn = null;  

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "/user" && i + 1 < args.Length)
                {
                    userName = args[i + 1];
                }
                else if (args[i] == "/value" && i + 1 < args.Length)
                {
                    scriptPath = args[i + 1];
                }
                else if (args[i] == "/domain" && i + 1 < args.Length)
                {
                    domainDn = ConvertDomainToDN(args[i + 1]); 
                }
            }

            if (userName == null || scriptPath == null || domainDn == null)
            {
                Console.WriteLine("Usage: Program.exe /user <UserName> /value <ScriptPath> /domain <DomainName>");
                return;
            }

            try
            {
                UpdateUserScriptPath(userName, scriptPath, domainDn);
                Console.WriteLine($"ScriptPath was successfully updated for user: {userName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating user: {ex.Message}");
            }
        }

        private static void UpdateUserScriptPath(string userName, string scriptPath, string domainDn)
        {
            try
            {
                using (DirectoryEntry de = new DirectoryEntry($"LDAP://{domainDn}"))
                {
                    // Search for the user
                    using (DirectorySearcher searcher = new DirectorySearcher(de))
                    {
                        searcher.Filter = $"(&(objectCategory=person)(objectClass=user)(sAMAccountName={userName}))";
                        SearchResult result = searcher.FindOne();

                    
                        if (result != null)
                        {
                            using (DirectoryEntry user = result.GetDirectoryEntry())
                            {
                    
                                user.Properties["scriptPath"].Value = scriptPath;
                                user.CommitChanges();
                                Console.WriteLine($"ScriptPath updated to '{scriptPath}' for user '{userName}'.");
                            }
                        }
                        else
                        {
                            Console.WriteLine($"User '{userName}' not found.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to update ScriptPath for {userName}. Error: {ex.Message}", ex);
            }
        }

        private static string ConvertDomainToDN(string domain)
        {
            string[] parts = domain.Split('.');
            string dn = "DC=" + string.Join(",DC=", parts);
            return dn;
        }
    }
}