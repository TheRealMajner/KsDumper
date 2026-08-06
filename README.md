# KsDumper

![Demo](https://i.imgur.com/6XyMDxa.gif)

A Windows kernel-level process memory dumper with a GUI client and an MCP (Model Context Protocol) server for AI-assisted reverse engineering.

## Features

### Kernel Driver
- Custom kernel driver for reading process memory without `OpenProcess`
- Bypasses handle stripping by anti-cheats (EAC, BattlEye, etc.)
- Supports both x86 and x64 process dumping from an x64 system

### Client (GUI)
- **Process Dumping** — dump any process main module, including protected/system processes
- **PE Rebuilding** — reconstructs PE32/PE64 headers, sections, and import tables
- **Unity / IL2CPP Analysis** — Il2Cpp metadata dumping, SDK generation, string literal extraction, Ghidra script export, Mono runtime inspection
- **Memory Tools** — memory scanner, signature scanner, pointer scan engine, memory map visualizer, watchpoints
- **Process Inspection** — handle viewer, token/privilege viewer, thread priority manager, environment variables, command-line args, VAD tree, kernel callbacks
- **Security Analysis** — DLL injection detection, IAT hook detection, APC injection detection, anti-cheat detection, integrity modifier
- **ReClass-style Inspector** — live memory node editor with structure definitions
- **.NET Inspector** — CLI header parsing, metadata tables, IL disassembler, decompiler, deobfuscation
- **Dark Theme** — full dark-mode UI

### MCP Server
An MCP server (`KsMcpServer`) that exposes the driver's capabilities to AI assistants (Claude, etc.) via the Model Context Protocol:
- **ProcessTools** — list processes, query process info
- **MemoryTools** — read/write process memory
- **ModuleTools** — enumerate loaded modules
- **DumpTools** — dump process modules to disk
- **PatternTools** — pattern/signature scanning
- **ThreadTools** — thread enumeration and inspection
- **Il2CppTools** — Il2Cpp metadata analysis
- **KernelTools** — kernel-level operations
- **DebugTools** — debugging utilities
- **DeobfuscationTools** — .NET deobfuscation

## Download

Pre-built binaries are available on the [Releases](https://github.com/TheRealMajner/KsDumper/releases) page:
- **KsDumper-Driver.zip** — compiled kernel driver (`KsDumperDriver.sys`)
- **KsDumper-Client.zip** — GUI client application
- **KsDumper-McpServer.zip** — MCP server for AI integration

## Usage

### Loading the Driver

The driver is unsigned, so you need to load it using a manual mapper or enable test-signing:

**Option A — Test Signing (recommended for development):**
```
bcdedit /set testsigning on
```
Then reboot and load the driver via `sc create` / `sc start` or a driver loader.

**Option B — Manual mapping:**
Use a driver mapper of your choice to load `KsDumperDriver.sys`.

### Running the Client
1. Load the KsDumper driver (see above)
2. Run `KsDumperClient.exe` as Administrator
3. The process list populates automatically — right-click a process to dump it

> **Note**: The driver stays loaded until reboot. You can close and reopen the client freely.

### Running the MCP Server

Add to your Claude Desktop / MCP client config:
```json
{
  "mcpServers": {
    "ksdumper": {
      "command": "KsMcpServer.exe",
      "args": ["--auto-restart"]
    }
  }
}
```

The server connects to the loaded kernel driver automatically. If the driver isn't available, it falls back to user-mode memory reading.

## Building from Source

### Requirements
- Visual Studio 2022 (or 2017+)
- Windows Driver Kit (WDK) — for the kernel driver
- .NET Framework 4.8 — for the client
- .NET 8.0 SDK — for the MCP server

### Build
```bash
# Open the solution
KsDumper.sln

# Or build from command line:
msbuild KsDumper.sln /p:Configuration=Release /p:Platform=x64
dotnet build KsMcpServer/KsMcpServer.csproj -c Release
```

## Disclaimer

This project is for **informational and educational purposes only**.

It is highly recommended to run it in a **Virtual Environment**. I am not responsible for any crash or damage that could happen to your system.

**Important**: This tool makes no attempt at hiding itself. If you target protected games, the anti-cheat might flag this and ban you. Use a **Virtual Environment**!

## License

[MIT License](LICENSE) — Copyright (c) 2019 Nicolas Tremblay

## References

- [drvmap](https://github.com/not-wlan/drvmap)
- [KernelBhop](https://github.com/Zer0Mem0ry/KernelBhop)
- [Scylla](https://github.com/NtQuery/Scylla/)
- [KsDumper-11](https://github.com/mastercodeon314/KsDumper-11) — Windows 11 port by mastercodeon314
