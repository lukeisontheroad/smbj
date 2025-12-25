# SMBJ-Swift

A Swift port of [SMBJ](https://github.com/hierynomus/smbj), the SMB2/SMB3 client library for Java.

## Features

- SMB 2.x and SMB 3.x protocol support
- NTLM authentication
- File and directory operations
- iOS, macOS, tvOS, watchOS compatible
- Modern Swift async/await API
- Network.framework-based transport

## Requirements

- iOS 14.0+ / macOS 11.0+ / tvOS 14.0+ / watchOS 7.0+
- Swift 5.9+
- Xcode 15.0+

## Installation

### Swift Package Manager

Add the following to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/hierynomus/smbj.git", from: "0.1.0")
]
```

Or add it through Xcode:
1. File > Add Package Dependencies...
2. Enter the repository URL
3. Select the version

## Usage

### Basic Connection

```swift
import SMBJ

// Create client
let client = SMBClient()

// Connect to server
let connection = try await client.connect(host: "192.168.1.100")

// Authenticate
let auth = AuthenticationContext(username: "user", password: "password", domain: "DOMAIN")
let session = try await connection.authenticate(auth)

// Connect to share
let share = try await session.connectShare("ShareName")

// List files
let files = try await share.list("Documents")
for file in files {
    print("\(file.fileName) - \(file.fileSize) bytes")
}

// Read a file
let file = try await share.openFile(path: "Documents/test.txt")
let data = try await file.readAll()
try await file.close()

// Write a file
let writeFile = try await share.openFile(
    path: "Documents/output.txt",
    accessMask: .fileWrite,
    createDisposition: .overwriteIf
)
try await writeFile.write("Hello, World!".data(using: .utf8)!)
try await writeFile.close()

// Cleanup
try await share.close()
await connection.close()
```

### Convenience Methods

```swift
// Connect directly to a share
let share = try await client.connectToShare(
    host: "192.168.1.100",
    shareName: "Documents",
    username: "user",
    password: "password"
)

// Using SMB URL
let share = try await client.connect(url: URL(string: "smb://user:password@192.168.1.100/Documents")!)
```

### Configuration

```swift
let config = try SMBConfigBuilder()
    .dialects(.smb_3_0, .smb_3_1_1)
    .signingRequired(true)
    .encryptData(true)
    .timeout(30)
    .build()

let client = SMBClient(config: config)
```

## Supported Operations

### File Operations
- `openFile(path:accessMask:attributes:shareAccess:createDisposition:createOptions:)` - Open a file
- `read(offset:length:)` - Read data from file
- `readAll()` - Read entire file
- `write(_:offset:)` - Write data to file
- `flush()` - Flush file buffers
- `close()` - Close file handle

### Directory Operations
- `openDirectory(path:accessMask:shareAccess:)` - Open a directory
- `list(pattern:)` - List directory contents
- `close()` - Close directory handle

### Share Operations
- `list(_:pattern:)` - List files in a path
- `exists(_:)` - Check if file/directory exists
- `mkdir(_:)` - Create directory
- `rm(_:)` - Remove file
- `rmdir(_:)` - Remove directory

## Architecture

The library is organized into the following modules:

- **Core** - Configuration, errors, and fundamental types
- **Protocol** - SMB2/SMB3 packet structures and messages
- **Transport** - Network communication layer
- **Auth** - Authentication (NTLM, SPNEGO)
- **Share** - Share access (DiskShare, File, Directory)

## Comparison with Java SMBJ

| Feature | Java SMBJ | Swift SMBJ |
|---------|-----------|------------|
| SMB 2.x | ✅ | ✅ |
| SMB 3.x | ✅ | ✅ |
| NTLM Auth | ✅ | ✅ |
| SPNEGO/Kerberos | ✅ | 🚧 |
| Signing | ✅ | ✅ |
| Encryption | ✅ | 🚧 |
| DFS | ✅ | 🚧 |
| Named Pipes | ✅ | 🚧 |

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](../LICENSE) file for details.

## Credits

This is a Swift port of the original [SMBJ](https://github.com/hierynomus/smbj) Java library by Jeroen van Erp and contributors.
