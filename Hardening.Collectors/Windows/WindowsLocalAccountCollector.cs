using System.DirectoryServices.AccountManagement;
using Hardening.Core.Interfaces;
using Hardening.Core.Models;

namespace Hardening.Collectors.Windows;

public class WindowsLocalAccountCollector : ICollector
{
    public string Name => nameof(WindowsLocalAccountCollector);

    public List<Evidence> Collect()
    {
        var evidences = new List<Evidence>();

        using var context =
            new PrincipalContext(ContextType.Machine);

        CollectUsers(context, evidences);
        CollectGroups(context, evidences);

        return evidences;
    }

    private void CollectUsers(
        PrincipalContext context,
        List<Evidence> evidences)
    {
        using var searcher =
            new PrincipalSearcher(
                new UserPrincipal(context));

        foreach (var principal in searcher.FindAll())
        {
            using var user =
                UserPrincipal.FindByIdentity(
                    context,
                    principal.SamAccountName);

            if (user == null)
                continue;

            // Name evidence acts as the parent/entity anchor
            // for the remaining properties of this user.
            var userId =
                AddEvidence(
                    evidences,
                    "WindowsLocalAccount",
                    "Name",
                    user.SamAccountName);

            AddEvidence(
                evidences,
                "WindowsLocalAccount",
                "SID",
                user.Sid?.Value,
                userId);

            AddEvidence(
                evidences,
                "WindowsLocalAccount",
                "RelativeIdentifier",
                GetRelativeIdentifier(user.Sid?.Value),
                userId);

            AddEvidence(
                evidences,
                "WindowsLocalAccount",
                "DisplayName",
                user.DisplayName,
                userId);

            AddEvidence(
                evidences,
                "WindowsLocalAccount",
                "Enabled",
                user.Enabled,
                userId);

            AddEvidence(
                evidences,
                "WindowsLocalAccount",
                "Description",
                user.Description,
                userId);

            AddEvidence(
                evidences,
                "WindowsLocalAccount",
                "PasswordRequired",
                user.PasswordNotRequired == false,
                userId);

            AddEvidence(
                evidences,
                "WindowsLocalAccount",
                "PasswordNeverExpires",
                user.PasswordNeverExpires,
                userId);

            AddEvidence(
                evidences,
                "WindowsLocalAccount",
                "LastLogon",
                user.LastLogon,
                userId);
        }
    }

    private void CollectGroups(
        PrincipalContext context,
        List<Evidence> evidences)
    {
        using var searcher =
            new PrincipalSearcher(
                new GroupPrincipal(context));

        foreach (var principal in searcher.FindAll())
        {
            using var group =
                GroupPrincipal.FindByIdentity(
                    context,
                    principal.SamAccountName);

            if (group == null)
                continue;

            // Name evidence acts as the group entity anchor.
            var groupId =
                AddEvidence(
                    evidences,
                    "WindowsLocalGroup",
                    "Name",
                    group.SamAccountName);

            AddEvidence(
                evidences,
                "WindowsLocalGroup",
                "SID",
                group.Sid?.Value,
                groupId);

            AddEvidence(
                evidences,
                "WindowsLocalGroup",
                "Description",
                group.Description,
                groupId);

            foreach (var member in group.GetMembers())
            {
                // Name evidence acts as the member entity anchor.
                var memberId =
                    AddEvidence(
                        evidences,
                        "WindowsLocalGroupMember",
                        "Name",
                        member.SamAccountName,
                        groupId);

                AddEvidence(
                    evidences,
                    "WindowsLocalGroupMember",
                    "SID",
                    member.Sid?.Value,
                    memberId);

                AddEvidence(
                    evidences,
                    "WindowsLocalGroupMember",
                    "ObjectClass",
                    member.StructuralObjectClass,
                    memberId);

                AddEvidence(
                    evidences,
                    "WindowsLocalGroupMember",
                    "PrincipalSource",
                    member.ContextType.ToString(),
                    memberId);
            }
        }
    }

    private static string AddEvidence(
        List<Evidence> evidences,
        string target,
        string property,
        object? value,
        string? parentId = null)
    {
        var evidenceId =
            Guid.NewGuid().ToString();

        evidences.Add(
            new Evidence
            {
                Id = evidenceId,
                Collector = nameof(WindowsLocalAccountCollector),
                Target = target,
                Property = property,
                Value = value,
                ParentId = parentId
            });

        return evidenceId;
    }

    private static string? GetRelativeIdentifier(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
            return null;

        var lastSeparator =
            sid.LastIndexOf('-');

        if (lastSeparator < 0 ||
            lastSeparator == sid.Length - 1)
        {
            return null;
        }

        return sid[(lastSeparator + 1)..];
    }
}