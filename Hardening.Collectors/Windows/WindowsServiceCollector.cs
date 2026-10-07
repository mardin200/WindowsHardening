using System.ServiceProcess;
using Hardening.Core.Interfaces;
using Hardening.Core.Models;

namespace Hardening.Collectors.Windows;

public class WindowsServiceCollector : ICollector
{
    public string Name => nameof(WindowsServiceCollector);

    public List<Evidence> Collect()
    {
        var evidences = new List<Evidence>();

        foreach (var service in ServiceController.GetServices())
        {
            var serviceId = Guid.NewGuid().ToString();

            // Service Name
            evidences.Add(new Evidence
            {
                Id = serviceId,
                Collector = Name,
                Target = "WindowsService",
                Property = "Name",
                Value = service.ServiceName
            });

            // Display Name
            evidences.Add(new Evidence
            {
                Collector = Name,
                Target = "WindowsService",
                Property = "DisplayName",
                Value = service.DisplayName,
                ParentId = serviceId
            });

            // Status
            evidences.Add(new Evidence
            {
                Collector = Name,
                Target = "WindowsService",
                Property = "Status",
                Value = service.Status.ToString(),
                ParentId = serviceId
            });

            // Startup Type
            evidences.Add(new Evidence
            {
                Collector = Name,
                Target = "WindowsService",
                Property = "StartType",
                Value = service.StartType.ToString(),
                ParentId = serviceId
            });
        }

        return evidences;
    }
}