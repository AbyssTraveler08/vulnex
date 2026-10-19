# Vulnex Endpoint Agent

Vulnex generates a self-contained direct-run agent for authorized endpoints.

## Supported launchers

- **macOS:** `.sh`
- **Linux:** `.sh`
- **Windows:** `.ps1` (PowerShell, the native Windows shell)

No native EXE, PKG, or binary build is required.

## Running the generated agent

### macOS

```bash
chmod +x vulnex_agent_<name>_macos.sh
./vulnex_agent_<name>_macos.sh
```

### Linux

```bash
chmod +x vulnex_agent_<name>_linux.sh
./vulnex_agent_<name>_linux.sh
```

### Windows PowerShell

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\vulnex_agent_<name>_windows.ps1
```

The generated launcher embeds the one-time enrollment token and the endpoint collector. It creates an isolated Python environment and starts the agent.

## Inventory collected

The read-only collector reports:

- OS and identity
- CPU, cores, RAM, disks, system model
- Network interfaces, MAC addresses, IPv4 addresses, gateway and DNS
- Installed software/packages
- Services and their state/configuration
- Local users and account metadata

The agent periodically sends the complete profile to the Vulnex Agent API.
