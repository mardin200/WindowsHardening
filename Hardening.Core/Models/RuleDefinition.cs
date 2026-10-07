using System.Text.Json;

namespace Hardening.Core.Models;

public class RuleDefinition
{
    public string Id { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string RuleType { get; set; } = string.Empty;

    public Severity Severity { get; set; }

    public RuleApplicability? Applicability { get; set; }

    public Dictionary<string, JsonElement> Parameters { get; set; } = new();
}