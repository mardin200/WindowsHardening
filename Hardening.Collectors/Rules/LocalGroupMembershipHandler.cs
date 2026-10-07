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
        var groupSid =
            GetStringParameter(
                rule,
                "groupSid");

        var allowedLocalAccountRids =
            GetStringListParameter(
                rule,
                "allowedLocalAccountRids");

        var allowedMemberSids =
            GetStringListParameter(
                rule,
                "allowedMemberSids",
                required: false);

        var groupSidEvidence =
            evidences.FirstOrDefault(e =>
                e.Target == "WindowsLocalGroup" &&
                e.Property == "SID" &&
                string.Equals(
                    e.Value?.ToString(),
                    groupSid,
                    StringComparison.OrdinalIgnoreCase));

        if (groupSidEvidence == null)
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.NotAssessed,
                Severity = rule.Severity,
                Expected =
                    "Required local group must exist.",
                Actual = "Group not found.",
                Description =
                    $"Local group with SID '{groupSid}' was not found."
            };
        }

        var groupId =
            groupSidEvidence.ParentId;

        if (string.IsNullOrWhiteSpace(groupId))
        {
            return new Finding
            {
                RuleId = rule.Id,
                Title = rule.Title,
                Status = FindingStatus.Error,
                Severity = rule.Severity,
                Expected =
                    "Local group evidence must have a parent group identifier.",
                Actual = "",
                Description =
                    $"Group SID evidence for '{groupSid}' has no parent group identifier.",
                EvidenceIds =
                    new List<string>
                    {
                        groupSidEvidence.Id
                    }
            };
        }

        var groupNameEvidence =
            evidences.FirstOrDefault(e =>
                e.Id == groupId &&
                e.Target == "WindowsLocalGroup" &&
                e.Property == "Name");

        var groupName =
            groupNameEvidence?.Value?.ToString()
            ?? $"Group SID {groupSid}";

        var memberNameEvidences =
            evidences
                .Where(e =>
                    e.Target == "WindowsLocalGroupMember" &&
                    e.Property == "Name" &&
                    e.ParentId == groupId)
                .ToList();

        var members =
            memberNameEvidences
                .Select(nameEvidence =>
                {
                    var memberSidEvidence =
                        evidences.FirstOrDefault(e =>
                            e.Target == "WindowsLocalGroupMember" &&
                            e.Property == "SID" &&
                            e.ParentId == nameEvidence.Id);

                    return new MemberIdentity
                    {
                        NameEvidence = nameEvidence,
                        SidEvidence = memberSidEvidence
                    };
                })
                .ToList();

        var allowedRids =
            new HashSet<string>(
                allowedLocalAccountRids,
                StringComparer.OrdinalIgnoreCase);

        var allowedSids =
            new HashSet<string>(
                allowedMemberSids,
                StringComparer.OrdinalIgnoreCase);

        // Resolve local account RIDs to their actual machine-specific SIDs.
        var allowedLocalAccountSids =
            evidences
                .Where(e =>
                    e.Target == "WindowsLocalAccount" &&
                    e.Property == "RelativeIdentifier" &&
                    e.Value != null &&
                    allowedRids.Contains(
                        e.Value.ToString() ?? string.Empty))
                .SelectMany(ridEvidence =>
                {
                    var userId = ridEvidence.ParentId;

                    if (string.IsNullOrWhiteSpace(userId))
                        return Enumerable.Empty<string>();

                    return evidences
                        .Where(e =>
                            e.Target == "WindowsLocalAccount" &&
                            e.Property == "SID" &&
                            e.ParentId == userId &&
                            e.Value != null)
                        .Select(e => e.Value!.ToString()!);
                })
                .ToHashSet(
                    StringComparer.OrdinalIgnoreCase);

        allowedSids.UnionWith(
            allowedLocalAccountSids);

        var unexpectedMembers =
            members
                .Where(member =>
                {
                    var sid =
                        member.SidEvidence?.Value?.ToString();

                    if (string.IsNullOrWhiteSpace(sid))
                        return true;

                    return !allowedSids.Contains(sid);
                })
                .ToList();

        var passed =
            unexpectedMembers.Count == 0;

        var actualMembers =
            members
                .Select(member =>
                {
                    var name =
                        member.NameEvidence.Value?.ToString()
                        ?? "<unknown>";

                    var sid =
                        member.SidEvidence?.Value?.ToString()
                        ?? "<SID unavailable>";

                    return $"{name} [{sid}]";
                })
                .ToList();

        var allowedDescription =
            allowedLocalAccountRids.Count == 0 &&
            allowedMemberSids.Count == 0
                ? "No members"
                : string.Join(
                    ", ",
                    allowedLocalAccountRids
                        .Select(rid => $"LocalAccount RID {rid}")
                        .Concat(
                            allowedMemberSids
                                .Select(sid => $"SID {sid}")));

        return new Finding
        {
            RuleId = rule.Id,
            Title = rule.Title,
            Status =
                passed
                    ? FindingStatus.Pass
                    : FindingStatus.Fail,
            Severity = rule.Severity,
            Expected =
                $"Allowed members: {allowedDescription}",
            Actual =
                actualMembers.Count == 0
                    ? "No members"
                    : string.Join(
                        ", ",
                        actualMembers),
            Description =
                passed
                    ? $"Local group '{groupName}' ({groupSid}) contains only approved members."
                    : $"Local group '{groupName}' ({groupSid}) contains {unexpectedMembers.Count} unexpected member(s).",
            EvidenceIds =
                new[]
                {
                    groupSidEvidence.Id
                }
                .Concat(
                    groupNameEvidence == null
                        ? Enumerable.Empty<string>()
                        : new[] { groupNameEvidence.Id })
                .Concat(
                    members.SelectMany(member =>
                        new[]
                        {
                            member.NameEvidence.Id,
                            member.SidEvidence?.Id
                        }
                        .Where(id =>
                            !string.IsNullOrWhiteSpace(id))
                        .Cast<string>()))
                .Distinct()
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
        string name,
        bool required = true)
    {
        if (!rule.Parameters.TryGetValue(
                name,
                out JsonElement value))
        {
            if (!required)
                return new List<string>();

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
            .Select(x =>
                x.GetString() ?? string.Empty)
            .ToList();
    }

    private sealed class MemberIdentity
    {
        public Evidence NameEvidence { get; set; } = null!;
        public Evidence? SidEvidence { get; set; }
    }
}