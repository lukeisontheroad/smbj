// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// [MS-SMB2].pdf 2.2.14.1 SMB2_FILEID
/// A unique identifier for an open file or directory
public struct SMB2FileId: Sendable, Hashable {
    /// Persistent portion of the file ID (8 bytes)
    public let persistentHandle: Data

    /// Volatile portion of the file ID (8 bytes)
    public let volatileHandle: Data

    /// Total size of SMB2FileId in bytes
    public static let size = 16

    /// Sentinel value indicating no file ID
    public static let sentinel: SMB2FileId = SMB2FileId(
        persistentHandle: Data(repeating: 0xFF, count: 8),
        volatileHandle: Data(repeating: 0xFF, count: 8)
    )

    public init(persistentHandle: Data, volatileHandle: Data) {
        precondition(persistentHandle.count == 8, "Persistent handle must be 8 bytes")
        precondition(volatileHandle.count == 8, "Volatile handle must be 8 bytes")
        self.persistentHandle = persistentHandle
        self.volatileHandle = volatileHandle
    }

    public init() {
        self = .sentinel
    }

    /// Write the file ID to a buffer
    public func write(to buffer: inout SMBBuffer) {
        buffer.append(persistentHandle)
        buffer.append(volatileHandle)
    }

    /// Read a file ID from a buffer
    public static func read(from buffer: inout SMBBuffer) throws -> SMB2FileId {
        let persistent = try buffer.readBytes(count: 8)
        let volatile = try buffer.readBytes(count: 8)
        return SMB2FileId(persistentHandle: persistent, volatileHandle: volatile)
    }
}

extension SMB2FileId: CustomStringConvertible {
    public var description: String {
        let hexString = persistentHandle.map { String(format: "%02X", $0) }.joined()
        return "SMB2FileId{\(hexString)}"
    }
}
