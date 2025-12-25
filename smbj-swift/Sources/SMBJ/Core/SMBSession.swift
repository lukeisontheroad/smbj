// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Logging

/// Represents an authenticated session on an SMB connection
public actor SMBSession {
    private weak var connection: SMBConnection?
    private let context: AuthenticationContext
    private let logger: Logger

    /// The session ID assigned by the server
    public private(set) var sessionId: UInt64 = 0

    /// Session key for signing/encryption
    private var sessionKey: Data?

    /// Connected shares
    private var shares: [UInt32: SMBShare] = [:]

    /// Whether the session is established
    public var isEstablished: Bool {
        return sessionId != 0
    }

    init(connection: SMBConnection, context: AuthenticationContext) {
        self.connection = connection
        self.context = context
        self.logger = Logger(label: "com.smbj.session")
    }

    /// Setup the session (perform authentication)
    func setup() async throws {
        logger.info("Setting up session for user: \(context.username)")

        // Send SESSION_SETUP request
        // For now, this is a simplified implementation
        // Full NTLM would involve multiple round-trips

        guard let connection = connection else {
            throw SMBError.connectionFailed(reason: "Connection lost")
        }

        let request = SMB2SessionSetupRequest(context: context)
        request.header.messageId = await connection.nextMessageId()
        request.header.dialect = await connection.dialect

        let response = try await connection.sendAndReceive(request)

        // Check for success or more processing required
        if response.header.status != .statusSuccess &&
           response.header.status != .statusMoreProcessingRequired {
            throw SMBApiException(status: response.header.status, command: .sessionSetup)
        }

        sessionId = response.header.sessionId
        logger.info("Session established with ID: \(sessionId)")
    }

    /// Connect to a share
    public func connectShare(_ shareName: String) async throws -> DiskShare {
        guard let connection = connection else {
            throw SMBError.connectionFailed(reason: "Connection lost")
        }

        logger.info("Connecting to share: \(shareName)")

        let request = SMB2TreeConnectRequest(sharePath: "\\\\\(await connection.host)\\\(shareName)")
        request.header.messageId = await connection.nextMessageId()
        request.header.sessionId = sessionId
        request.header.dialect = await connection.dialect

        let response = try await connection.sendAndReceive(request)

        guard response.header.status == .statusSuccess else {
            throw SMBApiException(status: response.header.status, command: .treeConnect)
        }

        let treeId = response.header.treeId
        let share = DiskShare(session: self, treeId: treeId, shareName: shareName)
        shares[treeId] = share

        logger.info("Connected to share: \(shareName) with tree ID: \(treeId)")
        return share
    }

    /// Disconnect from a share
    func disconnectShare(_ share: SMBShare) async throws {
        guard let connection = connection else {
            throw SMBError.connectionFailed(reason: "Connection lost")
        }

        let request = SMB2TreeDisconnectRequest()
        request.header.messageId = await connection.nextMessageId()
        request.header.sessionId = sessionId
        request.header.treeId = share.treeId
        request.header.dialect = await connection.dialect

        let response = try await connection.sendAndReceive(request)

        if response.header.status != .statusSuccess {
            logger.warning("Tree disconnect returned status: \(response.header.status)")
        }

        shares.removeValue(forKey: share.treeId)
    }

    /// Close the session
    func close() async {
        logger.info("Closing session \(sessionId)")

        // Disconnect all shares
        for (_, share) in shares {
            try? await share.close()
        }
        shares.removeAll()

        // Send logoff if connected
        guard let connection = connection else { return }

        let request = SMB2LogoffRequest()
        request.header.messageId = await connection.nextMessageId()
        request.header.sessionId = sessionId
        request.header.dialect = await connection.dialect

        _ = try? await connection.sendAndReceive(request)
    }

    /// Send a request through this session
    func sendAndReceive(_ request: SMB2Request) async throws -> SMB2Response {
        guard let connection = connection else {
            throw SMBError.connectionFailed(reason: "Connection lost")
        }

        request.header.sessionId = sessionId
        request.header.dialect = await connection.dialect
        request.header.messageId = await connection.nextMessageId()

        return try await connection.sendAndReceive(request)
    }
}

// MARK: - Session Setup Request/Response

/// SMB2 Session Setup Request
public class SMB2SessionSetupRequest: SMB2Request {
    public var context: AuthenticationContext

    public init(context: AuthenticationContext) {
        self.context = context
        super.init(command: .sessionSetup)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        // Structure size (25)
        buffer.appendUInt16(25)

        // Flags
        buffer.append(0)

        // Security mode
        buffer.append(0x01) // Signing enabled

        // Capabilities
        buffer.appendUInt32(0)

        // Channel
        buffer.appendUInt32(0)

        // Security buffer offset (will be calculated)
        let securityBufferOffset = UInt16(SMB2PacketHeader.structureSize + 24)
        buffer.appendUInt16(securityBufferOffset)

        // Security buffer length (placeholder)
        let securityBuffer = buildNTLMNegotiateMessage()
        buffer.appendUInt16(UInt16(securityBuffer.count))

        // Previous session ID
        buffer.appendUInt64(0)

        // Security buffer
        buffer.append(securityBuffer)
    }

    private func buildNTLMNegotiateMessage() -> Data {
        // Simplified NTLM Type 1 (Negotiate) message
        var buffer = SMBBuffer()

        // Signature "NTLMSSP\0"
        buffer.append(Data([0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00]))

        // Message type (1 = Negotiate)
        buffer.appendUInt32(1)

        // Negotiate flags
        let flags: UInt32 = 0xE2088297 // Standard NTLM flags
        buffer.appendUInt32(flags)

        // Domain name fields (len, max len, offset) - empty
        buffer.appendUInt16(0)
        buffer.appendUInt16(0)
        buffer.appendUInt32(0)

        // Workstation name fields (len, max len, offset) - empty
        buffer.appendUInt16(0)
        buffer.appendUInt16(0)
        buffer.appendUInt32(0)

        return buffer.bytes
    }
}

// MARK: - Tree Connect Request

/// SMB2 Tree Connect Request
public class SMB2TreeConnectRequest: SMB2Request {
    public var sharePath: String

    public init(sharePath: String) {
        self.sharePath = sharePath
        super.init(command: .treeConnect)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        // Structure size (9)
        buffer.appendUInt16(9)

        // Flags
        buffer.appendUInt16(0)

        // Path offset
        let pathOffset = UInt16(SMB2PacketHeader.structureSize + 8)
        buffer.appendUInt16(pathOffset)

        // Path length
        let pathData = sharePath.data(using: .utf16LittleEndian) ?? Data()
        buffer.appendUInt16(UInt16(pathData.count))

        // Path
        buffer.append(pathData)
    }
}

// MARK: - Tree Disconnect Request

/// SMB2 Tree Disconnect Request
public class SMB2TreeDisconnectRequest: SMB2Request {
    public init() {
        super.init(command: .treeDisconnect)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        // Structure size (4)
        buffer.appendUInt16(4)

        // Reserved
        buffer.appendUInt16(0)
    }
}

// MARK: - Logoff Request

/// SMB2 Logoff Request
public class SMB2LogoffRequest: SMB2Request {
    public init() {
        super.init(command: .logoff)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        // Structure size (4)
        buffer.appendUInt16(4)

        // Reserved
        buffer.appendUInt16(0)
    }
}
