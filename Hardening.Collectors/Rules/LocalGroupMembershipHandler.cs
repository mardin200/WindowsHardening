using System.Text.Json;
using Hardening.Core.Models;
using Hardening.Core.Rules;

namespace Hardening.Collectors.Rules;

public class LocalGroupMembershipHandler : IRuleHandler
{
    public string RuleType => "LocalGroupMembership";

    public Finding Evaluate(
        RuleDefinition rule,
        List<Evidence> evidences)
    {
        var groupName =
            GetStringParameter(rule, "groupName");

        var allowedMembers =
            GetStringListParameter(rule, "allowedMembers");

        var groupNameEvidence =
            evidences.FirstOrDefault(e =>
                e.Target == "WindowsLocalGroup" &&
                e.Property == "Name" &&
                string.Equals(
                    e.Value?.ToString(),
                    groupName,
                    StringComparison.OrdinalIgnoreCase));

        if (groupNameEvidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.NotAssessed,
                Severity = rule.Severity,
                Expected =
                    $"Local group '{groupName}' must exist.",
                Actual =
                    "Group not found.",
                Description =
                    $"Local group '{groupName}' was not found."
            };
        }

        // The group evidence itself carries the group ID.
        // Members reference that ID through ParentId.
        var groupId = groupNameEvidence.Id;

        var members =
            evidences
                .Where(e =>
                    e.Target == "WindowsLocalGroupMember" &&
                    e.Property == "Name" &&
                    e.ParentId == groupId)
                .ToList();

        var unexpectedMembers =
            members
                .Where(member =>
                    !allowedMembers.Any(
                        allowed =>
                            string.Equals(
                                allowed,
                                member.Value?.ToString(),
                                StringComparison.OrdinalIgnoreCase)))
                .ToList();

        var passed =
            unexpectedMembers.Count == 0;

        return new Finding
        {
            RuleId = rule.Id,
            Title = rule.Title,
            Status = passed
                ? FindingStatus.Pass
                : FindingStatus.Fail,
            Severity = rule.Severity,

            Expected =
                allowedMembers.Count == 0
                    ? "No members"
                    : $"Allowed members: {string.Join(", ", allowedMembers)}",

            Actual =
                members.Count == 0
                    ? "No members"
                    : string.Join(
                        ", ",
                        members.Select(
                            x => x.Value?.ToString())),

            Description =
                passed
                    ? $"All members of local group '{groupName}' are allowed."
                    : $"Local group '{groupName}' contains {unexpectedMembers.Count} unexpected member(s).",

            EvidenceIds =
                new[]
                {
                    groupNameEvidence.Id
                }
                .Concat(
                    members.Select(
                        x => x.Id))
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

    private static List<string> GetStringListParameter(
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

        if (value.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(
                $"Parameter '{name}' must be an array.");
        }

        return value
            .EnumerateArray()
            .Select(x => x.GetString() ?? string.Empty)
            .ToList();
    }
}