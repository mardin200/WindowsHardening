using System.Diagnostics;
using System.Text.Json;
using Hardening.Core.Interfaces;
using Hardening.Core.Models;

namespace Hardening.Collectors.Windows;

public class WindowsFirewallCollector : ICollector
{
    public string Name => nameof(WindowsFirewallCollector);

    public List<Evidence> Collect()
    {
        var evidences = new List<Evidence>();

        var profiles = GetFirewallProfiles();

        foreach (var profile in profiles)
        {
            var profileId = Guid.NewGuid().ToString();

            // Profile Name
            evidences.Add(new Evidence
            {
                Id = profileId,
                Collector = Name,
                Target = "WindowsFirewallProfile",
                Property = "Name",
                Value = profile.Name
            });

            // Enabled
            evidences.Add(new Evidence
            {
                Collector = Name,
                Target = "WindowsFirewallProfile",
                Property = "Enabled",
                Value = profile.Enabled,
                ParentId = profileId
            });

            // Default Inbound Action
            evidences.Add(new Evidence
            {
                Collector = Name,
                Target = "WindowsFirewallProfile",
                Property = "DefaultInboundAction",
                Value = profile.DefaultInboundAction,
                ParentId = profileId
            });

            // Default Outbound Action
            evidences.Add(new Evidence
            {
                Collector = Name,
                Target = "WindowsFirewallProfile",
                Property = "DefaultOutboundAction",
                Value = profile.DefaultOutboundAction,
                ParentId = profileId
            });
        }

        return evidences;
    }

    private static List<FirewallProfileInfo> GetFirewallProfiles()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",

            Arguments =
    "-NoProfile -NonInteractive -Command " +
    "\"Get-NetFirewallProfile | " +
    "Select-Object " +
    "Name," +
    "@{Name='Enabled';Expression={$_.Enabled.ToString()}}," +
    "@{Name='DefaultInboundAction';Expression={$_.DefaultInboundAction.ToString()}}," +
    "@{Name='DefaultOutboundAction';Expression={$_.DefaultOutboundAction.ToString()}} " +
    "| ConvertTo-Json -Compress\"",

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
                $"Failed to collect Windows Firewall profiles: {error}");
        }

        if (string.IsNullOrWhiteSpace(output))
        {
            return new List<FirewallProfileInfo>();
        }

        var json =
            JsonSerializer.Deserialize<JsonElement>(output);

        var profiles =
            new List<FirewallProfileInfo>();

        if (json.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in json.EnumerateArray())
            {
                profiles.Add(
                    ParseProfile(item));
            }
        }
        else if (json.ValueKind == JsonValueKind.Object)
        {
            profiles.Add(
                ParseProfile(json));
        }

        return profiles;
    }

    private static FirewallProfileInfo ParseProfile(
        JsonElement item)
    {
        return new FirewallProfileInfo
        {
            Name =
                item.GetProperty("Name").ToString(),

            Enabled =
                item.GetProperty("Enabled").ToString(),

            DefaultInboundAction =
                item.GetProperty("DefaultInboundAction").ToString(),

            DefaultOutboundAction =
                item.GetProperty("DefaultOutboundAction").ToString()
        };
    }

    private static string ParseBoolean(
        JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.True)
        {
            return "True";
        }

        if (value.ValueKind == JsonValueKind.False)
        {
            return "False";
        }

        if (value.ValueKind == JsonValueKind.Number)
        {
            return value.GetInt32() != 0
                ? "True"
                : "False";
        }

        var text =
            value.ToString();

        if (string.Equals(
                text,
                "1",
                StringComparison.OrdinalIgnoreCase))
        {
            return "True";
        }

        if (string.Equals(
                text,
                "0",
                StringComparison.OrdinalIgnoreCase))
        {
            return "False";
        }

        return text;
    }

    private static string ParseFirewallAction(
        JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Number)
        {
            return value.GetInt32() switch
            {
                1 => "Allow",
                2 => "Block",
                _ => "Unknown"
            };
        }

        var text =
            value.ToString();

        if (string.Equals(
                text,
                "1",
                StringComparison.OrdinalIgnoreCase))
        {
            return "Allow";
        }

        if (string.Equals(
                text,
                "2",
                StringComparison.OrdinalIgnoreCase))
        {
            return "Block";
        }

        return text;
    }

    private class FirewallProfileInfo
    {
        public string Name { get; set; } = string.Empty;

        public string Enabled { get; set; } = string.Empty;

        public string DefaultInboundAction { get; set; }
            = string.Empty;

        public string DefaultOutboundAction { get; set; }
            = string.Empty;
    }
}