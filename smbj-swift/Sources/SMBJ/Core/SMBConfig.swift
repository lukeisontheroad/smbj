// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Configuration for SMB client connections
public struct SMBConfig: Sendable {
    /// Default buffer size (1 MB)
    public static let defaultBufferSize = 1024 * 1024

    /// Default timeout in seconds
    public static let defaultTimeout: TimeInterval = 60

    /// SMB dialects to negotiate
    public var dialects: Set<SMB2Dialect>

    /// Client GUID
    public var clientGuid: UUID

    /// Whether signing is required
    public var signingRequired: Bool

    /// Whether signing is enabled
    public var signingEnabled: Bool

    /// Whether DFS is enabled
    public var dfsEnabled: Bool

    /// Whether to encrypt data (SMB 3.x only)
    public var encryptData: Bool

    /// Read buffer size
    public var readBufferSize: Int

    /// Write buffer size
    public var writeBufferSize: Int

    /// Transaction buffer size
    public var transactBufferSize: Int

    /// Socket timeout
    public var socketTimeout: TimeInterval

    /// Read/write/transaction timeout
    public var timeout: TimeInterval

    /// Create a default configuration
    public static func `default`() -> SMBConfig {
        return SMBConfig(
            dialects: [.smb_3_1_1, .smb_3_0_2, .smb_3_0, .smb_2_1, .smb_2_0_2],
            clientGuid: UUID(),
            signingRequired: false,
            signingEnabled: true,
            dfsEnabled: false,
            encryptData: false,
            readBufferSize: defaultBufferSize,
            writeBufferSize: defaultBufferSize,
            transactBufferSize: defaultBufferSize,
            socketTimeout: 0,
            timeout: defaultTimeout
        )
    }

    public init(
        dialects: Set<SMB2Dialect> = [.smb_3_1_1, .smb_3_0_2, .smb_3_0, .smb_2_1, .smb_2_0_2],
        clientGuid: UUID = UUID(),
        signingRequired: Bool = false,
        signingEnabled: Bool = true,
        dfsEnabled: Bool = false,
        encryptData: Bool = false,
        readBufferSize: Int = defaultBufferSize,
        writeBufferSize: Int = defaultBufferSize,
        transactBufferSize: Int = defaultBufferSize,
        socketTimeout: TimeInterval = 0,
        timeout: TimeInterval = defaultTimeout
    ) {
        self.dialects = dialects
        self.clientGuid = clientGuid
        self.signingRequired = signingRequired
        self.signingEnabled = signingEnabled
        self.dfsEnabled = dfsEnabled
        self.encryptData = encryptData
        self.readBufferSize = readBufferSize
        self.writeBufferSize = writeBufferSize
        self.transactBufferSize = transactBufferSize
        self.socketTimeout = socketTimeout
        self.timeout = timeout
    }

    /// Validate the configuration
    public func validate() throws {
        if dialects.isEmpty {
            throw SMBError.protocolError(reason: "At least one SMB dialect must be specified")
        }

        if signingRequired && !signingEnabled {
            throw SMBError.protocolError(reason: "If signing is required, it must also be enabled")
        }

        if !signingEnabled && SMB2Dialect.supportsSmb3x(dialects) {
            throw SMBError.protocolError(reason: "Signing cannot be disabled when using SMB 3.x dialects")
        }

        if encryptData && !SMB2Dialect.supportsSmb3x(dialects) {
            throw SMBError.protocolError(reason: "Encryption requires at least one SMB 3.x dialect")
        }
    }
}

/// Builder for SMBConfig
public class SMBConfigBuilder {
    private var config: SMBConfig

    public init() {
        self.config = .default()
    }

    public init(baseConfig: SMBConfig) {
        self.config = baseConfig
    }

    @discardableResult
    public func dialects(_ dialects: Set<SMB2Dialect>) -> SMBConfigBuilder {
        config.dialects = dialects
        return self
    }

    @discardableResult
    public func dialects(_ dialects: SMB2Dialect...) -> SMBConfigBuilder {
        config.dialects = Set(dialects)
        return self
    }

    @discardableResult
    public func clientGuid(_ guid: UUID) -> SMBConfigBuilder {
        config.clientGuid = guid
        return self
    }

    @discardableResult
    public func signingRequired(_ required: Bool) -> SMBConfigBuilder {
        config.signingRequired = required
        return self
    }

    @discardableResult
    public func signingEnabled(_ enabled: Bool) -> SMBConfigBuilder {
        config.signingEnabled = enabled
        return self
    }

    @discardableResult
    public func dfsEnabled(_ enabled: Bool) -> SMBConfigBuilder {
        config.dfsEnabled = enabled
        return self
    }

    @discardableResult
    public func encryptData(_ encrypt: Bool) -> SMBConfigBuilder {
        config.encryptData = encrypt
        return self
    }

    @discardableResult
    public func bufferSize(_ size: Int) -> SMBConfigBuilder {
        config.readBufferSize = size
        config.writeBufferSize = size
        config.transactBufferSize = size
        return self
    }

    @discardableResult
    public func timeout(_ timeout: TimeInterval) -> SMBConfigBuilder {
        config.timeout = timeout
        return self
    }

    @discardableResult
    public func socketTimeout(_ timeout: TimeInterval) -> SMBConfigBuilder {
        config.socketTimeout = timeout
        return self
    }

    public func build() throws -> SMBConfig {
        try config.validate()
        return config
    }
}
