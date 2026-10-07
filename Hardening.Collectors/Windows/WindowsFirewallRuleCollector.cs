using System.Diagnostics;
using System.Text.Json;
using Hardening.Core.Interfaces;
using Hardening.Core.Models;

namespace Hardening.Collectors.Windows;

public class WindowsFirewallRuleCollector : ICollector
{
    public string Name => nameof(WindowsFirewallRuleCollector);

    public List<Evidence> Collect()
    {
        var evidences = new List<Evidence>();

        var rules = GetFirewallRules();

        foreach (var rule in rules)
        {
            var ruleId = Guid.NewGuid().ToString();

            AddEvidence(evidences, ruleId, "Name", rule.Name);
            AddEvidence(evidences, ruleId, "DisplayName", rule.DisplayName);
            AddEvidence(evidences, ruleId, "Enabled", rule.Enabled);
            AddEvidence(evidences, ruleId, "Direction", rule.Direction);
            AddEvidence(evidences, ruleId, "Action", rule.Action);
            AddEvidence(evidences, ruleId, "Profile", rule.Profile);
            AddEvidence(evidences, ruleId, "Protocol", rule.Protocol);
            AddEvidence(evidences, ruleId, "LocalPort", rule.LocalPort);
            AddEvidence(evidences, ruleId, "RemotePort", rule.RemotePort);
        }

        return evidences;
    }

    private static void AddEvidence(
        List<Evidence> evidences,
        string parentId,
        string property,
        object? value)
    {
        evidences.Add(new Evidence
        {
            Id = Guid.NewGuid().ToString(),
            Collector = nameof(WindowsFirewallRuleCollector),
            Target = "WindowsFirewallRule",
            Property = property,
            Value = value,
            ParentId = parentId
        });
    }

    private static List<FirewallRuleInfo> GetFirewallRules()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",

            Arguments =
                "-NoProfile -NonInteractive -Command " +
                "\"$rules = Get-NetFirewallRule; " +
                "$ports = Get-NetFirewallPortFilter; " +
                "$result = foreach ($r in $rules) { " +
                "$p = $ports | Where-Object { $_.InstanceID -eq $r.InstanceID }; " +
                "[PSCustomObject]@{ " +
                "Name=$r.Name; " +
                "DisplayName=$r.DisplayName; " +
                "Enabled=$r.Enabled.ToString(); " +
                "Direction=$r.Direction.ToString(); " +
                "Action=$r.Action.ToString(); " +
                "Profile=$r.Profile.ToString(); " +
                "Protocol=if ($p) { $p.Protocol.ToString() } else { '' }; " +
                "LocalPort=if ($p) { $p.LocalPort.ToString() } else { '' }; " +
                "RemotePort=if ($p) { $p.RemotePort.ToString() } else { '' } " +
                "} " +
                "}; " +
                "$result | ConvertTo-Json -Compress\"",

            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process =
            Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Failed to start PowerShell.");

        var output =
            process.StandardOutput.ReadToEnd();

        var error =
            process.StandardError.ReadToEnd();

        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Failed to collect Windows Firewall rules: {error}");
        }

        if (string.IsNullOrWhiteSpace(output))
        {
            return new List<FirewallRuleInfo>();
        }

        var json =
            JsonSerializer.Deserialize<JsonElement>(output);

        var rules =
            new List<FirewallRuleInfo>();

        if (json.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in json.EnumerateArray())
            {
                rules.Add(ParseRule(item));
            }
        }
        else if (json.ValueKind == JsonValueKind.Object)
        {
            rules.Add(ParseRule(json));
        }

        return rules;
    }

    private static FirewallRuleInfo ParseRule(
        JsonElement item)
    {
        return new FirewallRuleInfo
        {
            Name = GetValue(item, "Name"),
            DisplayName = GetValue(item, "DisplayName"),
            Enabled = GetValue(item, "Enabled"),
            Direction = GetValue(item, "Direction"),
            Action = GetValue(item, "Action"),
            Profile = GetValue(item, "Profile"),
            Protocol = GetValue(item, "Protocol"),
            LocalPort = GetValue(item, "LocalPort"),
            RemotePort = GetValue(item, "RemotePort")
        };
    }

    private static string GetValue(
        JsonElement item,
        string property)
    {
        if (!item.TryGetProperty(
                property,
                out var value))
        {
            return string.Empty;
        }

        return value.ToString();
    }

    private class FirewallRuleInfo
    {
        public string Name { get; set; } = string.Empty;

        public string DisplayName { get; set; } = string.Empty;

        public string Enabled { get; set; } = string.Empty;

        public string Direction { get; set; } = string.Empty;

        public string Action { get; set; } = string.Empty;

        public string Profile { get; set; } = string.Empty;

        public string Protocol { get; set; } = string.Empty;

        public string LocalPort { get; set; } = string.Empty;

        public string RemotePort { get; set; } = string.Empty;
    }
}