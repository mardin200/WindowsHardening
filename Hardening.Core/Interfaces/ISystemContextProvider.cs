using Hardening.Core.Models;

namespace Hardening.Core.Interfaces;

public interface ISystemContextProvider
{
    SystemContext Discover();
}