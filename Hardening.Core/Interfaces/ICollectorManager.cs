using Hardening.Core.Models;

namespace Hardening.Core.Interfaces;

public interface ICollectorManager
{
    List<Evidence> CollectAll();
}