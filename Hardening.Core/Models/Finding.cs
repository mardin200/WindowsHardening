namespace Hardening.Core.Models;

public enum FindingStatus
{
    Pass,
    Fail,
    NotApplicable,
    NotAssessed,
    Error
}

public enum Severity
{
    Low,
    Medium,
    High,
    Critical
}

public class Finding
{
    public string RuleId { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public FindingStatus Status { get; set; }

    public Severity Severity { get; set; }

    public string Expected { get; set; } = string.Empty;

    public string Actual { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public List<string> EvidenceIds { get; set; } = new();
}