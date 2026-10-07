using Hardening.Core.Models;

namespace Hardening.Collectors.Helpers;

public static class WindowsServiceEvidenceHelper
{
    public static (
        Evidence? NameEvidence,
        Evidence? StatusEvidence)
        FindService(
            List<Evidence> evidences,
            string serviceName)
    {
        var nameEvidence = evidences.FirstOrDefault(e =>
            e.Target == "WindowsService" &&
            e.Property == "Name" &&
            string.Equals(
                e.Value?.ToString(),
                serviceName,
                StringComparison.OrdinalIgnoreCase));

        if (nameEvidence == null)
        {
            return (null, null);
        }

        var statusEvidence = evidences.FirstOrDefault(e =>
            e.Target == "WindowsService" &&
            e.Property == "Status" &&
            e.ParentId == nameEvidence.Id);

        return (nameEvidence, statusEvidence);
    }
}