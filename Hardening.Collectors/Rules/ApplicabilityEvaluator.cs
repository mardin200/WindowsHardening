using Hardening.Core.Models;
using Hardening.Core.Rules;

namespace Hardening.Collectors.Rules;

public class ApplicabilityEvaluator : IApplicabilityEvaluator
{
    public bool IsApplicable(
        RuleDefinition rule,
        SystemContext context)
    {
        // No applicability section means
        // the rule applies universally.
        if (rule.Applicability == null)
        {
            return true;
        }

        var requiredRoles = rule.Applicability.ServerRoles;

        // Empty role list means universally applicable.
        if (requiredRoles.Count == 0)
        {
            return true;
        }

        // The rule is applicable if the system
        // has at least one of the required roles.
        return context.ServerRoles.Any(
            actualRole =>
                requiredRoles.Any(
                    requiredRole =>
                        string.Equals(
                            actualRole,
                            requiredRole,
                            StringComparison.OrdinalIgnoreCase)));
    }
}