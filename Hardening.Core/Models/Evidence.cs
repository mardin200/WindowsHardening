namespace Hardening.Core.Models;

public class Evidence
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    public string Collector { get; set; } = string.Empty;

    public string Target { get; set; } = string.Empty;

    public string Property { get; set; } = string.Empty;

    public object? Value { get; set; }

    public string? ParentId { get; set; }

    public DateTime CollectedAt { get; set; } = DateTime.UtcNow;
}