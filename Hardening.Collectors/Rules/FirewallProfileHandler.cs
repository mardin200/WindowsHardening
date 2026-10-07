using System.Text.Json;
using Hardening.Core.Models;
using Hardening.Core.Rules;

namespace Hardening.Collectors.Rules;

public class FirewallProfileHandler : IRuleHandler
{
    public string RuleType => "FirewallProfile";

    public Finding Evaluate(
        RuleDefinition rule,
        List<Evidence> evidences)
    {
        var profileName =
            GetStringParameter(
                rule,
                "profile");

        var property =
            GetStringParameter(
                rule,
                "property");

        var expectedValue =
            GetStringParameter(
                rule,
                "expectedValue");

        var nameEvidence =
            evidences.FirstOrDefault(e =>
                e.Target == "WindowsFirewallProfile" &&
                e.Property == "Name" &&
                string.Equals(
                    e.Value?.ToString(),
                    profileName,
                    StringComparison.OrdinalIgnoreCase));

        if (nameEvidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.NotAssessed,
                Severity = rule.Severity,
                Expected = expectedValue,
                Description =
                    $"Firewall profile '{profileName}' was not found."
            };
        }

        var propertyEvidence =
            evidences.FirstOrDefault(e =>
                e.Target == "WindowsFirewallProfile" &&
                e.Property == property &&
                e.ParentId == nameEvidence.Id);

        if (propertyEvidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.NotAssessed,
                Severity = rule.Severity,
                Expected = expectedValue,
                Description =
                    $"Property '{property}' for firewall profile '{profileName}' was not found.",
                EvidenceIds =
                {
                    nameEvidence.Id
                }
            };
        }

        var actualValue =
            propertyEvidence.Value?.ToString()
            ?? string.Empty;

        var passed =
            string.Equals(
                actualValue,
                expectedValue,
                StringComparison.OrdinalIgnoreCase);

        return new Finding
        {
            RuleId = rule.Id,
            Title = rule.Title,

            Status = passed
                ? FindingStatus.Pass
                : FindingStatus.Fail,

            Severity = rule.Severity,

            Expected = expectedValue,

            Actual = actualValue,

            Description = passed
                ? $"Firewall profile '{profileName}' satisfies the requirement."
                : $"Firewall profile '{profileName}' does not satisfy the requirement.",

            EvidenceIds =
            {
                nameEvidence.Id,
                propertyEvidence.Id
            }
        };
    }

    private static string GetStringParameter(
        RuleDefinition rule,
        string name)
    {
        if (!rule.Parameters.TryGetValue(
                name,
                out JsonElement value))
        {
            throw new InvalidOperationException(
                $"Parameter '{name}' is missing from rule '{rule.Id}'.");
        }

        return value.GetString()
            ?? throw new InvalidOperationException(
                $"Parameter '{name}' must be a string.");
    }
}