using Hardening.Core.Models;
using Hardening.Core.Rules;

namespace Hardening.Collectors.Rules;

public class ServiceStartupTypeHandler : IRuleHandler
{
    public string RuleType => "ServiceStartupType";

    public Finding Evaluate(
        RuleDefinition rule,
        List<Evidence> evidences)
    {
        var serviceName =
            GetStringParameter(
                rule,
                "serviceName");

        var expectedStartType =
            GetStringParameter(
                rule,
                "expectedStartType");

        var nameEvidence =
            evidences.FirstOrDefault(e =>
                e.Target == "WindowsService" &&
                e.Property == "Name" &&
                string.Equals(
                    e.Value?.ToString(),
                    serviceName,
                    StringComparison.OrdinalIgnoreCase));

        if (nameEvidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.NotAssessed,
                Severity = rule.Severity,
                Expected = expectedStartType,
                Description =
                    $"Service '{serviceName}' was not found."
            };
        }

        var startupEvidence =
            evidences.FirstOrDefault(e =>
                e.Target == "WindowsService" &&
                e.Property == "StartType" &&
                e.ParentId == nameEvidence.Id);

        if (startupEvidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.NotAssessed,
                Severity = rule.Severity,
                Expected = expectedStartType,
                Description =
                    $"Startup type evidence for service '{serviceName}' was not found.",
                EvidenceIds =
                {
                    nameEvidence.Id
                }
            };
        }

        var actualStartType =
            startupEvidence.Value?.ToString()
            ?? string.Empty;

        var passed =
            string.Equals(
                actualStartType,
                expectedStartType,
                StringComparison.OrdinalIgnoreCase);

        return new Finding
        {
            RuleId = rule.Id,
            Title = rule.Title,

            Status = passed
                ? FindingStatus.Pass
                : FindingStatus.Fail,

            Severity = rule.Severity,

            Expected = expectedStartType,

            Actual = actualStartType,

            Description = passed
                ? $"Service '{serviceName}' has the expected startup type."
                : $"Service '{serviceName}' does not have the expected startup type.",

            EvidenceIds =
            {
                nameEvidence.Id,
                startupEvidence.Id
            }
        };
    }

    private static string GetStringParameter(
        RuleDefinition rule,
        string name)
    {
        if (!rule.Parameters.TryGetValue(
                name,
                out var value))
        {
            throw new InvalidOperationException(
                $"Parameter '{name}' is missing from rule '{rule.Id}'.");
        }

        return value.GetString()
            ?? throw new InvalidOperationException(
                $"Parameter '{name}' must be a string.");
    }
}