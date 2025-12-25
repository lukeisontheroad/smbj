// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// [MS-SMB2] 2.2.1 SMB2 Packet Header
public struct SMB2PacketHeader: Sendable {
    /// SMB2 Protocol ID: 0xFE 'S' 'M' 'B'
    public static let protocolId: [UInt8] = [0xFE, 0x53, 0x4D, 0x42]

    /// Header structure size (always 64)
    public static let structureSize: UInt16 = 64

    /// Offset of signature in header
    public static let signatureOffset = 48

    /// Size of signature
    public static let signatureSize = 16

    /// Empty signature (all zeros)
    public static let emptySignature = Data(repeating: 0, count: 16)

    /// Negotiated dialect
    public var dialect: SMB2Dialect = .unknown

    /// Credit charge for this request
    public var creditCharge: UInt16 = 1

    /// Number of credits requested
    public var creditRequest: UInt16 = 0

    /// Number of credits granted (response)
    public var creditResponse: UInt16 = 0

    /// Command code
    public var command: SMB2MessageCommandCode = .negotiate

    /// Message ID
    public var messageId: UInt64 = 0

    /// Async ID (for async operations)
    public var asyncId: UInt64 = 0

    /// Session ID
    public var sessionId: UInt64 = 0

    /// Tree ID
    public var treeId: UInt32 = 0

    /// NT Status code
    public var statusCode: UInt32 = 0

    /// Header flags
    public var flags: SMB2MessageFlag = []

    /// Next command offset (for compounded requests)
    public var nextCommandOffset: UInt32 = 0

    /// Signature (16 bytes)
    public var signature: Data = SMB2PacketHeader.emptySignature

    /// Position of header start in buffer
    public var headerStartPosition: Int = 0

    /// Position of message end in buffer
    public var messageEndPosition: Int = 0

    public init() {}

    /// Write header to buffer
    public func write(to buffer: inout SMBBuffer) {
        // Protocol ID (4 bytes)
        buffer.append(Data(Self.protocolId))

        // StructureSize (2 bytes)
        buffer.appendUInt16(Self.structureSize)

        // CreditCharge (2 bytes)
        if dialect == .unknown || dialect == .smb_2_0_2 {
            buffer.appendUInt16(0) // Reserved
        } else {
            buffer.appendUInt16(creditCharge)
        }

        // ChannelSequence/Reserved or Status (4 bytes)
        if dialect.isSmb3x {
            buffer.appendUInt16(0) // ChannelSequence
            buffer.appendUInt16(0) // Reserved
        } else {
            buffer.appendUInt32(0) // Status (reserved on request)
        }

        // Command (2 bytes)
        buffer.appendUInt16(command.rawValue)

        // CreditRequest (2 bytes) - request credits we use plus additional
        buffer.appendUInt16(creditRequest + creditCharge)

        // Flags (4 bytes)
        buffer.appendUInt32(flags.rawValue)

        // NextCommand (4 bytes)
        buffer.appendUInt32(nextCommandOffset)

        // MessageId (8 bytes)
        buffer.appendUInt64(messageId)

        // Async or TreeId
        if flags.contains(.asyncCommand) {
            buffer.appendUInt64(asyncId)
        } else {
            buffer.appendUInt32(0) // Reserved
            buffer.appendUInt32(treeId)
        }

        // SessionId (8 bytes)
        buffer.appendUInt64(sessionId)

        // Signature (16 bytes)
        buffer.append(Self.emptySignature)
    }

    /// Read header from buffer
    public static func read(from buffer: inout SMBBuffer) throws -> SMB2PacketHeader {
        var header = SMB2PacketHeader()
        header.headerStartPosition = buffer.position

        // Protocol ID (4 bytes)
        let protocolIdData = try buffer.readBytes(count: 4)
        guard Array(protocolIdData) == protocolId else {
            throw SMBError.protocolError(reason: "Invalid SMB2 protocol ID")
        }

        // StructureSize (2 bytes)
        let _ = try buffer.readUInt16()

        // CreditCharge (2 bytes)
        header.creditCharge = try buffer.readUInt16()

        // Status (4 bytes)
        header.statusCode = try buffer.readUInt32()

        // Command (2 bytes)
        let commandValue = try buffer.readUInt16()
        header.command = SMB2MessageCommandCode(rawValue: commandValue) ?? .negotiate

        // CreditResponse (2 bytes)
        header.creditResponse = try buffer.readUInt16()

        // Flags (4 bytes)
        header.flags = SMB2MessageFlag(rawValue: try buffer.readUInt32())

        // NextCommand (4 bytes)
        header.nextCommandOffset = try buffer.readUInt32()

        // MessageId (8 bytes)
        header.messageId = try buffer.readUInt64()

        // Async or TreeId
        if header.flags.contains(.asyncCommand) {
            header.asyncId = try buffer.readUInt64()
        } else {
            try buffer.skip(4) // Reserved
            header.treeId = try buffer.readUInt32()
        }

        // SessionId (8 bytes)
        header.sessionId = try buffer.readUInt64()

        // Signature (16 bytes)
        header.signature = try buffer.readBytes(count: 16)

        return header
    }

    /// Get the NT Status as an NtStatus enum
    public var status: NtStatus {
        return NtStatus(rawValue: statusCode)
    }

    /// Check if the message is a response
    public var isResponse: Bool {
        return flags.contains(.serverToRedir)
    }

    /// Check if a flag is set
    public func isFlagSet(_ flag: SMB2MessageFlag) -> Bool {
        return flags.contains(flag)
    }

    /// Set a flag
    public mutating func setFlag(_ flag: SMB2MessageFlag) {
        flags.insert(flag)
    }
}

extension SMB2PacketHeader: CustomStringConvertible {
    public var description: String {
        return "SMB2PacketHeader(command=\(command), messageId=\(messageId), sessionId=\(sessionId), treeId=\(treeId), status=0x\(String(statusCode, radix: 16, uppercase: true)))"
    }
}
