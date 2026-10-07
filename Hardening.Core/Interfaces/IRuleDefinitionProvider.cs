using Hardening.Core.Models;

namespace Hardening.Core.Interfaces;

public interface IRuleDefinitionProvider
{
    List<RuleDefinition> Load();
}