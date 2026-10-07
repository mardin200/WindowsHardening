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
        var relativeIdentifier =
            GetStringParameter(
                rule,
                "relativeIdentifier");

        var property =
            GetStringParameter(
                rule,
                "property");

        var expectedValue =
            GetStringParameter(
                rule,
                "expectedValue");

        var relativeIdentifierEvidence =
            evidences.FirstOrDefault(e =>
                e.Target == "WindowsLocalAccount" &&
                e.Property == "RelativeIdentifier" &&
                string.Equals(
                    e.Value?.ToString(),
                    relativeIdentifier,
                    StringComparison.OrdinalIgnoreCase));

        if (relativeIdentifierEvidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.NotAssessed,
                Severity = rule.Severity,
                Expected =
                    $"Local account with RelativeIdentifier '{relativeIdentifier}' must exist.",
                Actual = "Account not found.",
                Description =
                    $"No local account with RelativeIdentifier '{relativeIdentifier}' was found."
            };
        }

        var userId =
            relativeIdentifierEvidence.ParentId;

        if (string.IsNullOrWhiteSpace(userId))
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.Error,
                Severity = rule.Severity,
                Expected = expectedValue,
                Actual = "",
                Description =
                    $"RelativeIdentifier evidence for '{relativeIdentifier}' has no parent user identifier.",
                EvidenceIds =
                    new List<string>
                    {
                        relativeIdentifierEvidence.Id
                    }
            };
        }

        var nameEvidence =
            evidences.FirstOrDefault(e =>
                e.Id == userId &&
                e.Target == "WindowsLocalAccount" &&
                e.Property == "Name");

        var accountName =
            nameEvidence?.Value?.ToString()
            ?? $"RID {relativeIdentifier}";

        var propertyEvidence =
            evidences.FirstOrDefault(e =>
                e.Target == "WindowsLocalAccount" &&
                e.Property == property &&
                e.ParentId == userId);

        if (propertyEvidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.NotAssessed,
                Severity = rule.Severity,
                Expected = expectedValue,
                Actual = "",
                Description =
                    $"Property '{property}' for local account '{accountName}' (RID {relativeIdentifier}) was not found.",
                EvidenceIds =
                    new List<string>
                    {
                        relativeIdentifierEvidence.Id,
                        nameEvidence?.Id
                    }
                    .Where(id => !string.IsNullOrWhiteSpace(id))
                    .Cast<string>()
                    .ToList()
            };
        }

        var actualValue =
            propertyEvidence.Value?.ToString() ?? "";

        var passed =
            string.Equals(
                actualValue,
                expectedValue,
                StringComparison.OrdinalIgnoreCase);

        return new Finding
        {
            RuleId = rule.Id,
            Title = rule.Title,
            Status =
                passed
                    ? FindingStatus.Pass
                    : FindingStatus.Fail,
            Severity = rule.Severity,
            Expected = expectedValue,
            Actual = actualValue,
            Description =
                passed
                    ? $"Local account '{accountName}' (RID {relativeIdentifier}) satisfies the requirement."
                    : $"Local account '{accountName}' (RID {relativeIdentifier}) does not satisfy the requirement.",
            EvidenceIds =
                new List<string>
                {
                    relativeIdentifierEvidence.Id,
                    propertyEvidence.Id
                }
                .Concat(
                    nameEvidence == null
                        ? Enumerable.Empty<string>()
                        : new[] { nameEvidence.Id })
                .ToList()
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