using Hardening.Core.Models;
using Hardening.Core.Rules;

namespace Hardening.Collectors.Rules;

public class RegistryValueHandler : IRuleHandler
{
    public string RuleType => "RegistryValue";

    public Finding Evaluate(
        RuleDefinition rule,
        List<Evidence> evidences)
    {
        var subKey =
            GetStringParameter(
                rule,
                "subKey");

        var valueName =
            GetStringParameter(
                rule,
                "valueName");

        var expectedValue =
            GetStringParameter(
                rule,
                "expectedValue");

        var evidence =
            FindRegistryEvidence(
                rule,
                evidences,
                subKey,
                valueName);

        if (evidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,

                Title = rule.Title,

                Status =
                    FindingStatus.NotAssessed,

                Severity = rule.Severity,

                Expected = expectedValue,

                Description =
                    $"Registry value '{subKey}\\{valueName}' was not found."
            };
        }

        if (evidence.Value == null)
        {
            return new Finding
            {
                RuleId = rule.Id,

                Title = rule.Title,

                Status =
                    FindingStatus.NotAssessed,

                Severity = rule.Severity,

                Expected = expectedValue,

                Description =
                    $"Registry value '{subKey}\\{valueName}' does not exist.",

                EvidenceIds =
                    new List<string>
                    {
                        evidence.Id
                    }
            };
        }

        var actualValue =
            evidence.Value.ToString()
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

            Status =
                passed
                    ? FindingStatus.Pass
                    : FindingStatus.Fail,

            Severity = rule.Severity,

            Expected = expectedValue,

            Actual = actualValue,

            Description =
                passed
                    ? $"Registry value '{subKey}\\{valueName}' satisfies the requirement."
                    : $"Registry value '{subKey}\\{valueName}' does not satisfy the requirement.",

            EvidenceIds =
                new List<string>
                {
                    evidence.Id
                }
        };
    }

    private static Evidence? FindRegistryEvidence(
        RuleDefinition rule,
        List<Evidence> evidences,
        string subKey,
        string valueName)
    {
        /*
         * The RegistryQuery ID is currently stored
         * in Evidence.ParentId.
         *
         * We first try to find the query ID from
         * the rule's optional "queryId" parameter.
         */

        if (rule.Parameters.TryGetValue(
                "queryId",
                out var queryIdElement))
        {
            var queryId =
                queryIdElement.GetString();

            if (!string.IsNullOrWhiteSpace(queryId))
            {
                var evidenceByQuery =
                    evidences.FirstOrDefault(e =>
                        e.Target == "Registry" &&
                        e.Property == valueName &&
                        e.ParentId == queryId);

                if (evidenceByQuery != null)
                {
                    return evidenceByQuery;
                }
            }
        }

        /*
         * Backward-compatible fallback.
         *
         * Until all registry rules contain queryId,
         * use the registry value name.
         */

        return evidences.FirstOrDefault(e =>
            e.Target == "Registry" &&
            e.Property == valueName &&
            e.Collector == "WindowsRegistryCollector");
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