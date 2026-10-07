using Hardening.Core.Models;

namespace Hardening.Core.Rules;

public interface IApplicabilityEvaluator
{
    bool IsApplicable(
        RuleDefinition rule,
        SystemContext context);
}