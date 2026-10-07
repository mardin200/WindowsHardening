using Microsoft.Win32;
using Hardening.Core.Interfaces;
using Hardening.Core.Models;

namespace Hardening.Collectors.Windows;

public class WindowsRegistryCollector : ICollector
{
    private readonly List<RegistryQuery> _queries;

    public string Name => nameof(WindowsRegistryCollector);

    public WindowsRegistryCollector(
        IEnumerable<RegistryQuery> queries)
    {
        _queries = queries.ToList();
    }

    public List<Evidence> Collect()
    {
        var evidences = new List<Evidence>();

        foreach (var query in _queries)
        {
            try
            {
                using var baseKey =
                    RegistryKey.OpenBaseKey(
                        query.Hive,
                        RegistryView.Default);

                using var subKey =
                    baseKey.OpenSubKey(
                        query.SubKey);

                if (subKey == null)
                {
                    evidences.Add(
                        CreateEvidence(
                            query,
                            value: null));

                    continue;
                }

                var value =
                    subKey.GetValue(
                        query.ValueName,
                        null,
                        RegistryValueOptions.DoNotExpandEnvironmentNames);

                evidences.Add(
                    CreateEvidence(
                        query,
                        value));
            }
            catch (Exception ex)
            {
                evidences.Add(
                    CreateEvidence(
                        query,
                        value: $"ERROR: {ex.Message}"));
            }
        }

        return evidences;
    }

    private Evidence CreateEvidence(
        RegistryQuery query,
        object? value)
    {
        return new Evidence
        {
            // IMPORTANT:
            // Evidence gets its own unique ID.
            // It must NOT use query.Id.
            Id = Guid.NewGuid().ToString(),

            Collector = Name,

            Target = "Registry",

            Property = query.ValueName,

            Value = value,

            // Query.Id is retained as a relationship
            // identifier, not as the Evidence.Id.
            ParentId = query.Id
        };
    }
}

public class RegistryQuery
{
    public string Id { get; set; } =
        Guid.NewGuid().ToString();

    public RegistryHive Hive { get; set; }

    public string SubKey { get; set; } =
        string.Empty;

    public string ValueName { get; set; } =
        string.Empty;
}