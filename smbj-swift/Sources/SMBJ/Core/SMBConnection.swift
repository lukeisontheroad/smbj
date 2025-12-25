// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Logging

/// Represents a connection to an SMB server
public actor SMBConnection {
    private let transport: DirectTCPTransport
    private let config: SMBConfig
    private let logger: Logger

    private var negotiatedDialect: SMB2Dialect = .unknown
    private var serverGuid: UUID?
    private var maxTransactSize: UInt32 = 0
    private var maxReadSize: UInt32 = 0
    private var maxWriteSize: UInt32 = 0
    private var signingRequired: Bool = false
    private var messageIdCounter: UInt64 = 0
    private var sessions: [UInt64: SMBSession] = [:]

    /// The negotiated SMB dialect
    public var dialect: SMB2Dialect {
        return negotiatedDialect
    }

    /// Whether the connection is active
    public var isConnected: Bool {
        return transport.isConnected
    }

    /// The remote host
    public let host: String

    /// The remote port
    public let port: UInt16

    init(host: String, port: UInt16, config: SMBConfig) {
        self.host = host
        self.port = port
        self.config = config
        self.transport = DirectTCPTransport(host: host, port: port)
        self.logger = Logger(label: "com.smbj.connection")
    }

    /// Connect and negotiate protocol
    func connect() async throws {
        logger.info("Connecting to \(host):\(port)")
        try await transport.connect()
        try await negotiate()
    }

    /// Close the connection
    public func close() async {
        logger.info("Closing connection to \(host)")

        // Close all sessions
        for (_, session) in sessions {
            await session.close()
        }
        sessions.removeAll()

        await transport.disconnect()
    }

    /// Authenticate and create a session
    public func authenticate(_ context: AuthenticationContext) async throws -> SMBSession {
        logger.info("Authenticating user: \(context.username)")

        // For now, implement simple session setup
        // Full NTLM/SPNEGO authentication would be implemented here
        let session = SMBSession(connection: self, context: context)
        try await session.setup()

        sessions[session.sessionId] = session
        return session
    }

    /// Get the next message ID
    func nextMessageId() -> UInt64 {
        messageIdCounter += 1
        return messageIdCounter
    }

    /// Send a request and receive response
    func sendAndReceive(_ request: SMB2Request) async throws -> SMB2Response {
        var buffer = SMBBuffer()
        request.write(to: &buffer)

        let responseData = try await transport.sendAndReceive(buffer.bytes, messageId: request.header.messageId)
        return try SMB2Response.read(from: responseData)
    }

    /// Negotiate SMB protocol
    private func negotiate() async throws {
        logger.debug("Negotiating SMB protocol")

        let request = SMB2NegotiateRequest(
            dialects: Array(config.dialects),
            clientGuid: config.clientGuid,
            signingRequired: config.signingRequired,
            signingEnabled: config.signingEnabled
        )
        request.header.messageId = nextMessageId()

        var buffer = SMBBuffer()
        request.write(to: &buffer)

        let responseData = try await transport.sendAndReceive(buffer.bytes, messageId: request.header.messageId)
        let response = try SMB2NegotiateResponse.read(from: responseData)

        guard response.header.status == .statusSuccess else {
            throw SMBApiException(status: response.header.status, command: .negotiate)
        }

        negotiatedDialect = response.dialect
        serverGuid = response.serverGuid
        maxTransactSize = response.maxTransactSize
        maxReadSize = response.maxReadSize
        maxWriteSize = response.maxWriteSize
        signingRequired = response.signingRequired

        logger.info("Negotiated dialect: \(negotiatedDialect)")
    }
}

// MARK: - SMB2 Request/Response Base

/// Base class for SMB2 requests
public class SMB2Request {
    public var header: SMB2PacketHeader

    public init(command: SMB2MessageCommandCode) {
        self.header = SMB2PacketHeader()
        self.header.command = command
    }

    public func write(to buffer: inout SMBBuffer) {
        header.write(to: &buffer)
    }
}

/// Base class for SMB2 responses
public struct SMB2Response {
    public var header: SMB2PacketHeader
    public var data: Data

    public static func read(from data: Data) throws -> SMB2Response {
        var buffer = SMBBuffer(data: data)
        let header = try SMB2PacketHeader.read(from: &buffer)
        return SMB2Response(header: header, data: buffer.readRemaining())
    }
}

// MARK: - Negotiate Request/Response

/// SMB2 Negotiate Request
public class SMB2NegotiateRequest: SMB2Request {
    public var dialects: [SMB2Dialect]
    public var clientGuid: UUID
    public var signingRequired: Bool
    public var signingEnabled: Bool

    public init(dialects: [SMB2Dialect], clientGuid: UUID, signingRequired: Bool, signingEnabled: Bool) {
        self.dialects = dialects
        self.clientGuid = clientGuid
        self.signingRequired = signingRequired
        self.signingEnabled = signingEnabled
        super.init(command: .negotiate)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        // Structure size (36)
        buffer.appendUInt16(36)

        // Dialect count
        buffer.appendUInt16(UInt16(dialects.count))

        // Security mode
        var securityMode: UInt16 = 0
        if signingEnabled { securityMode |= 0x01 }
        if signingRequired { securityMode |= 0x02 }
        buffer.appendUInt16(securityMode)

        // Reserved
        buffer.appendUInt16(0)

        // Capabilities (will be filled based on dialects)
        buffer.appendUInt32(0)

        // Client GUID
        let guidBytes = withUnsafeBytes(of: clientGuid.uuid) { Data($0) }
        buffer.append(guidBytes)

        // Negotiate context offset/count (SMB 3.1.1)
        buffer.appendUInt32(0) // NegotiateContextOffset
        buffer.appendUInt16(0) // NegotiateContextCount
        buffer.appendUInt16(0) // Reserved2

        // Dialects
        for dialect in dialects.sorted(by: { $0.rawValue > $1.rawValue }) {
            buffer.appendUInt16(dialect.rawValue)
        }
    }
}

/// SMB2 Negotiate Response
public struct SMB2NegotiateResponse {
    public var header: SMB2PacketHeader
    public var dialect: SMB2Dialect
    public var serverGuid: UUID
    public var maxTransactSize: UInt32
    public var maxReadSize: UInt32
    public var maxWriteSize: UInt32
    public var signingRequired: Bool

    public static func read(from data: Data) throws -> SMB2NegotiateResponse {
        var buffer = SMBBuffer(data: data)
        let header = try SMB2PacketHeader.read(from: &buffer)

        // Structure size
        let _ = try buffer.readUInt16()

        // Security mode
        let securityMode = try buffer.readUInt16()
        let signingRequired = (securityMode & 0x02) != 0

        // Dialect revision
        let dialectValue = try buffer.readUInt16()
        let dialect = SMB2Dialect(rawValue: dialectValue) ?? .unknown

        // Negotiate context count (SMB 3.1.1)
        let _ = try buffer.readUInt16()

        // Server GUID
        let guidBytes = try buffer.readBytes(count: 16)
        let serverGuid = guidBytes.withUnsafeBytes { ptr -> UUID in
            let tuple = ptr.load(as: uuid_t.self)
            return UUID(uuid: tuple)
        }

        // Capabilities
        let _ = try buffer.readUInt32()

        // Max transact size
        let maxTransactSize = try buffer.readUInt32()

        // Max read size
        let maxReadSize = try buffer.readUInt32()

        // Max write size
        let maxWriteSize = try buffer.readUInt32()

        return SMB2NegotiateResponse(
            header: header,
            dialect: dialect,
            serverGuid: serverGuid,
            maxTransactSize: maxTransactSize,
            maxReadSize: maxReadSize,
            maxWriteSize: maxWriteSize,
            signingRequired: signingRequired
        )
    }
}
