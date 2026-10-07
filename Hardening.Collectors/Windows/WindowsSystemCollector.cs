using System.Runtime.InteropServices;
using Hardening.Core.Interfaces;
using Hardening.Core.Models;

namespace Hardening.Collectors.Windows;

public class WindowsSystemCollector : ICollector
{
    public string Name => nameof(WindowsSystemCollector);

    public List<Evidence> Collect()
    {
        var evidences = new List<Evidence>();

        evidences.Add(new Evidence
        {
            Collector = Name,
            Target = "Windows",
            Property = "ComputerName",
            Value = Environment.MachineName
        });

        evidences.Add(new Evidence
        {
            Collector = Name,
            Target = "Windows",
            Property = "OperatingSystem",
            Value = Environment.OSVersion.VersionString
        });

        evidences.Add(new Evidence
        {
            Collector = Name,
            Target = "Windows",
            Property = "Architecture",
            Value = RuntimeInformation.OSArchitecture.ToString()
        });

        return evidences;
    }
}