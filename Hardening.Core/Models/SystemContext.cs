namespace Hardening.Core.Models;

public class SystemContext
{
    public string ComputerName { get; set; } = string.Empty;

    public string OperatingSystem { get; set; } = string.Empty;

    public string Architecture { get; set; } = string.Empty;

    public List<string> ServerRoles { get; set; } = new();
}