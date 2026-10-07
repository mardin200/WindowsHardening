using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

using Hardening.Collectors.Engine;
using Hardening.Collectors.Managers;
using Hardening.Collectors.Providers;
using Hardening.Collectors.Rules;
using Hardening.Collectors.Windows;

using Hardening.Core.Interfaces;
using Hardening.Core.Models;
using Hardening.Core.Rules;

// ------------------------------------------------------------
// 1. Load rule definitions
// ------------------------------------------------------------

var rulesFilePath = Path.Combine(
    AppContext.BaseDirectory,
    "Profiles",
    "rules.json");

IRuleDefinitionProvider ruleProvider =
    new JsonRuleDefinitionProvider(
        rulesFilePath);

var rules =
    ruleProvider.Load();


// ------------------------------------------------------------
// 2. Discover system context
// ------------------------------------------------------------

ISystemContextProvider contextProvider =
    new WindowsSystemContextProvider();

var systemContext =
    contextProvider.Discover();


// ------------------------------------------------------------
// 3. Create collectors
// ------------------------------------------------------------

ICollector[] collectors =
{
    new WindowsSystemCollector(),

    new WindowsServiceCollector(),

    new WindowsFirewallCollector(),

    new WindowsFirewallRuleCollector(),

    new WindowsLocalAccountCollector(),

    new WindowsRegistryCollector(
        new[]
        {
            new RegistryQuery
            {
                Id = "REG-001",
                Hive = RegistryHive.LocalMachine,
                SubKey =
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                ValueName = "EnableLUA"
            }
        })
};


// ------------------------------------------------------------
// 4. Collect evidence
// ------------------------------------------------------------

var collectorManager =
    new CollectorManager(collectors);

var evidences =
    collectorManager.CollectAll();


// ------------------------------------------------------------
// 5. Create rule handlers
// ------------------------------------------------------------

IRuleHandler[] handlers =
{
    new ServiceStatusHandler(),
    new ServiceStartupTypeHandler(),
    new FirewallProfileHandler(),
    new FirewallRuleHandler(),
    new RegistryValueHandler(),
    new LocalUserPropertyHandler(),
    new LocalGroupMembershipHandler()
};


// ------------------------------------------------------------
// 6. Create applicability evaluator
// ------------------------------------------------------------

IApplicabilityEvaluator applicabilityEvaluator =
    new ApplicabilityEvaluator();


// ------------------------------------------------------------
// 7. Create rule evaluator
// ------------------------------------------------------------

IRuleEvaluator ruleEvaluator =
    new RuleEvaluator(
        handlers,
        applicabilityEvaluator);


// ------------------------------------------------------------
// 8. Evaluate rules
// ------------------------------------------------------------

var findings =
    ruleEvaluator.Evaluate(
        evidences,
        rules,
        systemContext);


// ------------------------------------------------------------
// 9. Build assessment result
// ------------------------------------------------------------

var result = new AssessmentResult
{
    AssessedAt =
        DateTime.UtcNow,

    EvidenceCount =
        evidences.Count,

    RuleCount =
        rules.Count,

    PassCount =
        findings.Count(
            f => f.Status ==
                 FindingStatus.Pass),

    FailCount =
        findings.Count(
            f => f.Status ==
                 FindingStatus.Fail),

    NotApplicableCount =
        findings.Count(
            f => f.Status ==
                 FindingStatus.NotApplicable),

    NotAssessedCount =
        findings.Count(
            f => f.Status ==
                 FindingStatus.NotAssessed),

    ErrorCount =
        findings.Count(
            f => f.Status ==
                 FindingStatus.Error),

    Findings =
        findings
};


// ------------------------------------------------------------
// 10. Output
// ------------------------------------------------------------

var output = new
{
    SystemContext = systemContext,

    Assessment = result
};

var json =
    JsonSerializer.Serialize(
        output,
        new JsonSerializerOptions
        {
            WriteIndented = true,

            Converters =
            {
                new JsonStringEnumConverter()
            }
        });

Console.WriteLine(json);