using System.Text.Json;
using System.Text.Json.Serialization;
using Hardening.Core.Interfaces;
using Hardening.Core.Models;

namespace Hardening.Collectors.Providers;

public class JsonRuleDefinitionProvider : IRuleDefinitionProvider
{
    private readonly string _filePath;

    public JsonRuleDefinitionProvider(string filePath)
    {
        _filePath = filePath;
    }

    public List<RuleDefinition> Load()
    {
        if (!File.Exists(_filePath))
        {
            throw new FileNotFoundException(
                "Rule definition file was not found.",
                _filePath);
        }

        var json = File.ReadAllText(_filePath);

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        options.Converters.Add(
            new JsonStringEnumConverter());

        var rules = JsonSerializer.Deserialize<List<RuleDefinition>>(
            json,
            options);

        return rules ?? new List<RuleDefinition>();
    }
}