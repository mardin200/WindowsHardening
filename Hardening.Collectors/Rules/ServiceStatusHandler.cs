using System.Text.Json;
using Hardening.Core.Models;
using Hardening.Core.Rules;

namespace Hardening.Collectors.Rules;

public class ServiceStatusHandler : IRuleHandler
{
    public string RuleType => "ServiceStatus";

    public Finding Evaluate(
        RuleDefinition rule,
        List<Evidence> evidences)
    {
        var serviceName = GetStringParameter(
            rule,
            "serviceName");

        var expectedStatus = GetStringParameter(
            rule,
            "expectedStatus");

        var nameEvidence = evidences.FirstOrDefault(e =>
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
                Expected = expectedStatus,
                Description =
                    $"Service '{serviceName}' was not found."
            };
        }

        var statusEvidence = evidences.FirstOrDefault(e =>
            e.Target == "WindowsService" &&
            e.Property == "Status" &&
            e.ParentId == nameEvidence.Id);

        if (statusEvidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.NotAssessed,
                Severity = rule.Severity,
                Expected = expectedStatus,
                Description =
                    $"Status evidence for service '{serviceName}' was not found.",
                EvidenceIds = new List<string>
                {
                    nameEvidence.Id
                }
            };
        }

        var actualStatus =
            statusEvidence.Value?.ToString() ?? string.Empty;

        var passed = string.Equals(
            actualStatus,
            expectedStatus,
            StringComparison.OrdinalIgnoreCase);

        return new Finding
        {
            RuleId = rule.Id,
            Title = rule.Title,

            Status = passed
                ? FindingStatus.Pass
                : FindingStatus.Fail,

            Severity = rule.Severity,

            Expected = expectedStatus,

            Actual = actualStatus,

            Description = passed
                ? $"Service '{serviceName}' satisfies the requirement."
                : $"Service '{serviceName}' does not satisfy the requirement.",

            EvidenceIds = new List<string>
            {
                nameEvidence.Id,
                statusEvidence.Id
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