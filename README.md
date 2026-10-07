# WindowsHardening

WindowsHardening is a read-only Windows security hardening assessment tool built with .NET 8.

The project collects system security evidence, evaluates the collected evidence against configurable rules, and produces traceable assessment findings.

## Architecture

The assessment pipeline is based on an evidence-driven architecture:

Collectors → Evidence → Rule Evaluation → Findings → Assessment Result

### Projects

- `Hardening.Core`
  - Core models
  - Interfaces
  - Rule abstractions

- `Hardening.Collectors`
  - Windows evidence collectors
  - Rule handlers
  - Rule evaluation
  - System context discovery

- `Hardening.Cli`
  - Command-line application
  - Rule profiles
  - Assessment execution

## Current Capabilities

The current implementation can collect and assess:

- Windows services
- Service status
- Service startup type
- Windows Firewall profiles
- Windows Firewall rules
- Local user accounts
- Local group membership
- Selected Windows Registry settings
- Basic system information
- Server-role applicability

## Read-Only Assessment

The current assessment engine is read-only.

It does not:

- change Windows services
- modify firewall configuration
- modify registry settings
- create or delete accounts
- modify group membership
- change security policies

The tool collects evidence and evaluates it against defined rules.

## Rule Profiles

Rules are currently defined using JSON profiles.

The initial rules are development/demo rules and should not be considered an official implementation of CIS Benchmarks, Microsoft Security Baselines, or any other security standard.

## Requirements

- Windows
- .NET 8 SDK
- Administrator privileges may be required for some Windows security information

## Running

Build the solution:

```powershell
dotnet build