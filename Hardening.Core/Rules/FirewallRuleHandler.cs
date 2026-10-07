using System.Text.Json;
using Hardening.Core.Models;
using Hardening.Core.Rules;

namespace Hardening.Collectors.Rules;

public class FirewallRuleHandler : IRuleHandler
{
    public string RuleType => "FirewallRule";

    public Finding Evaluate(
        RuleDefinition rule,
        List<Evidence> evidences)
    {
        var protocol = GetOptionalString(rule, "protocol");
        var localPort = GetOptionalString(rule, "localPort");
        var remotePort = GetOptionalString(rule, "remotePort");
        var profile = GetOptionalString(rule, "profile");
        var direction = GetOptionalString(rule, "direction");
        var action = GetOptionalString(rule, "action");
        var enabled = GetOptionalString(rule, "enabled");

        var maxMatches =
            GetOptionalInt(rule, "maxMatches");

        var firewallRules =
            evidences
                .Where(e =>
                    e.Target == "WindowsFirewallRule" &&
                    e.Property == "Name")
                .ToList();

        var matchedRules = new List<(string Id, string Name)>();

        foreach (var nameEvidence in firewallRules)
        {
            var ruleEvidence =
                evidences
                    .Where(e =>
                        e.Target == "WindowsFirewallRule" &&
                        e.ParentId == nameEvidence.Id)
                    .ToList();

            if (!Matches(
         ruleEvidence,
         profile,
         direction,
         action,
         enabled,
         protocol,
         localPort,
         remotePort))
            {
                continue;
            }

            matchedRules.Add(
                (
                    nameEvidence.Id,
                    nameEvidence.Value?.ToString() ?? string.Empty
                ));
        }

        var passed =
            maxMatches.HasValue
                ? matchedRules.Count <= maxMatches.Value
                : matchedRules.Count == 0;

        return new Finding
        {
            RuleId = rule.Id,
            Title = rule.Title,
            Status = passed
                ? FindingStatus.Pass
                : FindingStatus.Fail,
            Severity = rule.Severity,

            Expected =
                maxMatches.HasValue
                    ? $"Matching firewall rules <= {maxMatches.Value}"
                    : "No matching firewall rules",

            Actual =
                $"Matching firewall rules = {matchedRules.Count}",

            Description =
                passed
                    ? "No firewall rule violates the defined condition."
                    : $"Found {matchedRules.Count} firewall rule(s) matching the defined condition.",

            EvidenceIds =
                matchedRules
                    .SelectMany(x =>
                        evidences
                            .Where(e =>
                                e.Target == "WindowsFirewallRule" &&
                                (e.Id == x.Id ||
                                 e.ParentId == x.Id))
                            .Select(e => e.Id))
                    .ToList()
        };
    }

    private static bool Matches(
        List<Evidence> evidences,
        string? profile,
        string? direction,
        string? action,
        string? enabled,
        string? protocol,
        string? localPort,
        string? remotePort)
    {
        return
            MatchesProperty(evidences, "Profile", profile) &&
            MatchesProperty(evidences, "Direction", direction) &&
            MatchesProperty(evidences, "Action", action) &&
            MatchesProperty(evidences, "Enabled", enabled) &&
            MatchesProperty(evidences, "Protocol", protocol) &&
            MatchesProperty(evidences, "LocalPort", localPort) &&
            MatchesProperty(evidences, "RemotePort", remotePort);
    }
    private static bool MatchesProperty(
        List<Evidence> evidences,
        string property,
        string? expected)
    {
        if (string.IsNullOrWhiteSpace(expected))
        {
            return true;
        }

        var evidence =
            evidences.FirstOrDefault(
                e => e.Property == property);

        if (evidence == null)
        {
            return false;
        }

        return string.Equals(
            evidence.Value?.ToString(),
            expected,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string? GetOptionalString(
        RuleDefinition rule,
        string name)
    {
        if (!rule.Parameters.TryGetValue(
                name,
                out JsonElement value))
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : value.ToString();
    }

    private static int? GetOptionalInt(
        RuleDefinition rule,
        string name)
    {
        if (!rule.Parameters.TryGetValue(
                name,
                out JsonElement value))
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number &&
            value.TryGetInt32(out var number))
        {
            return number;
        }

        return int.Parse(value.ToString());
    }
}