// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Logging

/// Main entry point for SMB client operations
public final class SMBClient: @unchecked Sendable {
    /// Client configuration
    public let config: SMBConfig

    /// Active connections
    private var connections: [String: SMBConnection] = [:]
    private let connectionsLock = NSLock()

    /// Logger
    private let logger: Logger

    /// Create a new SMB client with default configuration
    public init() {
        self.config = .default()
        self.logger = Logger(label: "com.smbj.client")
    }

    /// Create a new SMB client with custom configuration
    public init(config: SMBConfig) {
        self.config = config
        self.logger = Logger(label: "com.smbj.client")
    }

    /// Connect to an SMB server
    /// - Parameters:
    ///   - host: The hostname or IP address
    ///   - port: The port number (default: 445)
    /// - Returns: An SMBConnection to the server
    public func connect(host: String, port: UInt16 = 445) async throws -> SMBConnection {
        let key = "\(host):\(port)"

        // Check for existing connection
        connectionsLock.lock()
        if let existing = connections[key], await existing.isConnected {
            connectionsLock.unlock()
            return existing
        }
        connectionsLock.unlock()

        logger.info("Creating new connection to \(host):\(port)")

        let connection = SMBConnection(host: host, port: port, config: config)
        try await connection.connect()

        connectionsLock.lock()
        connections[key] = connection
        connectionsLock.unlock()

        return connection
    }

    /// Close all connections
    public func closeAll() async {
        connectionsLock.lock()
        let allConnections = Array(connections.values)
        connections.removeAll()
        connectionsLock.unlock()

        for connection in allConnections {
            await connection.close()
        }
    }

    /// Remove a connection from the pool
    func removeConnection(_ connection: SMBConnection) async {
        let key = "\(await connection.host):\(await connection.port)"
        connectionsLock.lock()
        connections.removeValue(forKey: key)
        connectionsLock.unlock()
    }
}

// MARK: - Convenience Extensions

extension SMBClient {
    /// Connect to a server, authenticate, and return a session
    public func connect(
        host: String,
        port: UInt16 = 445,
        username: String,
        password: String,
        domain: String? = nil
    ) async throws -> SMBSession {
        let connection = try await connect(host: host, port: port)
        let context = AuthenticationContext(username: username, password: password, domain: domain)
        return try await connection.authenticate(context)
    }

    /// Connect to a share directly
    public func connectToShare(
        host: String,
        shareName: String,
        username: String,
        password: String,
        domain: String? = nil,
        port: UInt16 = 445
    ) async throws -> DiskShare {
        let session = try await connect(
            host: host,
            port: port,
            username: username,
            password: password,
            domain: domain
        )
        return try await session.connectShare(shareName)
    }
}

// MARK: - SMB URL Parsing

extension SMBClient {
    /// Parse an SMB URL and connect
    /// Format: smb://[domain;]user:password@host[:port]/share
    public func connect(url: URL) async throws -> DiskShare {
        guard url.scheme == "smb" else {
            throw SMBError.protocolError(reason: "URL scheme must be 'smb'")
        }

        guard let host = url.host else {
            throw SMBError.protocolError(reason: "URL must contain a host")
        }

        let port = url.port.map { UInt16($0) } ?? 445

        // Parse username and password
        var username = url.user ?? ""
        var domain: String? = nil
        let password = url.password ?? ""

        // Check for domain in username (domain;username format)
        if let semicolonIndex = username.firstIndex(of: ";") {
            domain = String(username[..<semicolonIndex])
            username = String(username[username.index(after: semicolonIndex)...])
        }

        // Parse share name from path
        let pathComponents = url.pathComponents.filter { $0 != "/" }
        guard let shareName = pathComponents.first else {
            throw SMBError.protocolError(reason: "URL must contain a share name")
        }

        return try await connectToShare(
            host: host,
            shareName: shareName,
            username: username,
            password: password,
            domain: domain,
            port: port
        )
    }
}
