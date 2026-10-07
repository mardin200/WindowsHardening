namespace Hardening.Core.Models;

public class AssessmentResult
{
    public DateTime AssessedAt { get; set; } = DateTime.UtcNow;

    public int EvidenceCount { get; set; }

    public int RuleCount { get; set; }

    public int PassCount { get; set; }

    public int FailCount { get; set; }

    public int NotApplicableCount { get; set; }

    public int NotAssessedCount { get; set; }

    public int ErrorCount { get; set; }

    public List<Finding> Findings { get; set; } = new();
}