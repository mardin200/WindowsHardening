using System.ServiceProcess;
using System.Runtime.InteropServices;
using Hardening.Core.Interfaces;
using Hardening.Core.Models;

namespace Hardening.Collectors.Windows;

public class WindowsSystemContextProvider : ISystemContextProvider
{
    public SystemContext Discover()
    {
        var context = new SystemContext
        {
            ComputerName = Environment.MachineName,

            OperatingSystem =
                Environment.OSVersion.VersionString,

            Architecture =
                RuntimeInformation.OSArchitecture.ToString()
        };

        DiscoverRoles(context);

        return context;
    }

    private static void DiscoverRoles(
        SystemContext context)
    {
        // IIS / Web Server detection.
        if (ServiceExists("W3SVC"))
        {
            context.ServerRoles.Add("WebServer");
        }

        // Print Server detection.
        //
        // We deliberately do NOT infer PrintServer
        // merely because the Spooler service exists.
        //
        // Spooler can exist on systems that are not
        // actually configured as Print Servers.
        //
        // PrintServer detection will be implemented
        // later using Windows Server feature discovery.
    }

    private static bool ServiceExists(
        string serviceName)
    {
        try
        {
            using var service =
                new ServiceController(serviceName);

            // Accessing Status forces ServiceController
            // to resolve the service.
            _ = service.Status;

            return true;
        }
        catch
        {
            return false;
        }
    }
}