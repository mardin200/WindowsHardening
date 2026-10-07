using Hardening.Core.Models;
using Hardening.Core.Rules;

namespace Hardening.Collectors.Engine;

public class RuleEvaluator : IRuleEvaluator
{
    private readonly Dictionary<string, IRuleHandler> _handlers;

    private readonly IApplicabilityEvaluator
        _applicabilityEvaluator;

    public RuleEvaluator(
        IEnumerable<IRuleHandler> handlers,
        IApplicabilityEvaluator applicabilityEvaluator)
    {
        _handlers = handlers.ToDictionary(
            h => h.RuleType,
            StringComparer.OrdinalIgnoreCase);

        _applicabilityEvaluator =
            applicabilityEvaluator;
    }

    public List<Finding> Evaluate(
        List<Evidence> evidences,
        IEnumerable<RuleDefinition> rules,
        SystemContext context)
    {
        var findings = new List<Finding>();

        foreach (var rule in rules)
        {
            try
            {
                // -----------------------------------------
                // 1. Check rule applicability
                // -----------------------------------------

                var applicable =
                    _applicabilityEvaluator.IsApplicable(
                        rule,
                        context);

                if (!applicable)
                {
                    findings.Add(new Finding
                    {
                        RuleId = rule.Id,

                        Title = rule.Title,

                        Status =
                            FindingStatus.NotApplicable,

                        Severity = rule.Severity,

                        Description =
                            "The rule is not applicable to the current system context."
                    });

                    continue;
                }

                // -----------------------------------------
                // 2. Find handler
                // -----------------------------------------

                if (!_handlers.TryGetValue(
                        rule.RuleType,
                        out var handler))
                {
                    findings.Add(new Finding
                    {
                        RuleId = rule.Id,

                        Title = rule.Title,

                        Status =
                            FindingStatus.Error,

                        Severity = rule.Severity,

                        Description =
                            $"No handler registered for rule type '{rule.RuleType}'."
                    });

                    continue;
                }

                // -----------------------------------------
                // 3. Evaluate rule
                // -----------------------------------------

                var finding =
                    handler.Evaluate(
                        rule,
                        evidences);

                findings.Add(finding);
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    RuleId = rule.Id,

                    Title = rule.Title,

                    Status =
                        FindingStatus.Error,

                    Severity = rule.Severity,

                    Description = ex.Message
                });
            }
        }

        return findings;
    }
}