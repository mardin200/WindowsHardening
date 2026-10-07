using Hardening.Core.Models;

namespace Hardening.Core.Rules;

public interface IRuleEvaluator
{
    List<Finding> Evaluate(
        List<Evidence> evidences,
        IEnumerable<RuleDefinition> rules,
        SystemContext context);
}