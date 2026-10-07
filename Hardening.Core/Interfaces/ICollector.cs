using Hardening.Core.Models;

namespace Hardening.Core.Interfaces;

public interface ICollector
{
    string Name { get; }

    List<Evidence> Collect();
}