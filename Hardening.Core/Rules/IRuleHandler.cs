using Hardening.Core.Models;

namespace Hardening.Core.Rules;

public interface IRuleHandler
{
    string RuleType { get; }

    Finding Evaluate(
        RuleDefinition rule,
        List<Evidence> evidences);
}