using Hardening.Core.Interfaces;
using Hardening.Core.Models;

namespace Hardening.Collectors.Managers;

public class CollectorManager : ICollectorManager
{
    private readonly List<ICollector> _collectors;

    public CollectorManager(IEnumerable<ICollector> collectors)
    {
        _collectors = collectors.ToList();
    }

    public List<Evidence> CollectAll()
    {
        var evidences = new List<Evidence>();

        foreach (var collector in _collectors)
        {
            Console.WriteLine(
                $"[COLLECT] {collector.Name}");

            try
            {
                var collected =
                    collector.Collect();

                Console.WriteLine(
                    $"[OK] {collector.Name}: {collected.Count} evidence");

                evidences.AddRange(collected);
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[ERROR] {collector.Name}: {ex.Message}");

                evidences.Add(new Evidence
                {
                    Collector = collector.Name,
                    Target = "Collector",
                    Property = "Error",
                    Value = ex.ToString()
                });
            }
        }

        return evidences;
    }
}