# Vulnex Endpoint Agent — Direct Run

Vulnex uses self-contained, direct-run endpoint launchers. There is no EXE/PKG/native installer build workflow.

## Supported launchers

| Endpoint | Launcher | Run with |
|---|---|---|
| macOS | `.sh` | Terminal / Bash |
| Linux | `.sh` | Terminal / Bash |
| Windows | `.ps1` | PowerShell |

## macOS

```bash
chmod +x vulnex_agent_<name>_macos.sh
./vulnex_agent_<name>_macos.sh
```

## Linux

```bash
chmod +x vulnex_agent_<name>_linux.sh
./vulnex_agent_<name>_linux.sh
```

## Windows

Run PowerShell and execute:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\vulnex_agent_<name>_windows.ps1
```

The launcher embeds the one-time enrollment token, installs the required Python environment, and starts the agent.

## Endpoint inventory

The read-only agent collects and periodically sends:

- OS and system identity
- CPU, cores, RAM, model and disk information
- Network interfaces, MAC addresses, IPv4 addresses, gateway and DNS
- Installed software/packages and versions where available
- Services and their state/configuration
- Local user/account metadata

The Vulnex dashboard displays these under **Overview, Hardware, Network, Software, Services, and Users**.

## Background service and automatic restart

The generated launcher now installs the Vulnex Agent as a persistent background service:

- macOS: `launchd` LaunchDaemon (`com.vulnex.endpoint-agent`)
- Linux: `systemd` service (`vulnex-agent.service`)
- Windows: Task Scheduler task (`Vulnex Endpoint Agent`)

The installer must be run with administrator/root privileges. After installation, the agent starts in the background, continues after user logout, starts automatically after a system reboot, and retries communication when the Vulnex server is temporarily unavailable.

The agent sends a lightweight authenticated heartbeat every 60 seconds and refreshes the full endpoint inventory every 5 minutes. The dashboard's **Collect Data Again** button queues an immediate inventory refresh; the agent receives the request on its next heartbeat and sends a fresh full profile.

The enrollment token is one-time. After successful registration, the agent persists its agent ID and secret locally and uses those credentials for future heartbeats/restarts.
