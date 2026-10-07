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

            var userId = Guid.NewGuid().ToString();

            AddEvidence(
                evidences,
                userId,
                "Name",
                user.SamAccountName,
                "WindowsLocalAccount");

            AddEvidence(
                evidences,
                userId,
                "SID",
                user.Sid?.Value,
                "WindowsLocalAccount");

            AddEvidence(
                evidences,
                userId,
                "DisplayName",
                user.DisplayName,
                "WindowsLocalAccount");

            AddEvidence(
                evidences,
                userId,
                "Enabled",
                user.Enabled,
                "WindowsLocalAccount");

            AddEvidence(
                evidences,
                userId,
                "Description",
                user.Description,
                "WindowsLocalAccount");

            AddEvidence(
                evidences,
                userId,
                "PasswordRequired",
                user.PasswordNotRequired == false,
                "WindowsLocalAccount");

            AddEvidence(
                evidences,
                userId,
                "PasswordNeverExpires",
                user.PasswordNeverExpires,
                "WindowsLocalAccount");

            AddEvidence(
                evidences,
                userId,
                "LastLogon",
                user.LastLogon,
                "WindowsLocalAccount");
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

            var groupId = Guid.NewGuid().ToString();

            AddEvidence(
                evidences,
                groupId,
                "Name",
                group.SamAccountName,
                "WindowsLocalGroup");

            AddEvidence(
                evidences,
                groupId,
                "SID",
                group.Sid?.Value,
                "WindowsLocalGroup");

            AddEvidence(
                evidences,
                groupId,
                "Description",
                group.Description,
                "WindowsLocalGroup");

            foreach (var member in group.GetMembers())
            {
                var memberId = Guid.NewGuid().ToString();

                AddEvidence(
                    evidences,
                    memberId,
                    "Name",
                    member.SamAccountName,
                    "WindowsLocalGroupMember",
                    groupId);

                AddEvidence(
                    evidences,
                    memberId,
                    "SID",
                    member.Sid?.Value,
                    "WindowsLocalGroupMember",
                    groupId);

                AddEvidence(
                    evidences,
                    memberId,
                    "ObjectClass",
                    member.StructuralObjectClass,
                    "WindowsLocalGroupMember",
                    groupId);

                AddEvidence(
                    evidences,
                    memberId,
                    "PrincipalSource",
                    member.ContextType.ToString(),
                    "WindowsLocalGroupMember",
                    groupId);
            }
        }
    }

    private static void AddEvidence(
        List<Evidence> evidences,
        string id,
        string property,
        object? value,
        string target,
        string? parentId = null)
    {
        evidences.Add(new Evidence
        {
            Id = id,
            Collector = nameof(WindowsLocalAccountCollector),
            Target = target,
            Property = property,
            Value = value,
            ParentId = parentId
        });
    }
}