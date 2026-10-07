using System.Text.Json;
using Hardening.Core.Models;
using Hardening.Core.Rules;

namespace Hardening.Collectors.Rules;

public class LocalUserPropertyHandler : IRuleHandler
{
    public string RuleType => "LocalUserProperty";

    public Finding Evaluate(
        RuleDefinition rule,
        List<Evidence> evidences)
    {
        var userName = GetStringParameter(rule, "userName");
        var property = GetStringParameter(rule, "property");
        var expectedValue = GetStringParameter(rule, "expectedValue");

        var userNameEvidence =
            evidences.FirstOrDefault(e =>
                e.Target == "WindowsLocalAccount" &&
                e.Property == "Name" &&
                string.Equals(
                    e.Value?.ToString(),
                    userName,
                    StringComparison.OrdinalIgnoreCase));

        if (userNameEvidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.NotAssessed,
                Severity = rule.Severity,
                Expected = expectedValue,
                Description =
                    $"Local user '{userName}' was not found."
            };
        }

        var propertyEvidence =
            evidences.FirstOrDefault(e =>
                e.Target == "WindowsLocalAccount" &&
                e.Property == property &&
                e.ParentId == userNameEvidence.ParentId);

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
                    $"Property '{property}' for local user '{userName}' was not found.",
                EvidenceIds =
                {
                    userNameEvidence.Id
                }
            };
        }

        var actualValue =
            propertyEvidence.Value?.ToString() ?? string.Empty;

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
            Description =
                passed
                    ? $"Local user '{userName}' satisfies the requirement."
                    : $"Local user '{userName}' does not satisfy the requirement.",
            EvidenceIds =
            {
                userNameEvidence.Id,
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