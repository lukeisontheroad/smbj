// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// SMB2 Create 2.2.13 - SMB2ShareAccess
/// Specifies the sharing mode for the open
public struct SMB2ShareAccess: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Other opens can read the file
    public static let read = SMB2ShareAccess(rawValue: 0x00000001)

    /// Other opens can write to the file
    public static let write = SMB2ShareAccess(rawValue: 0x00000002)

    /// Other opens can delete the file
    public static let delete = SMB2ShareAccess(rawValue: 0x00000004)

    /// Allow all sharing modes
    public static let all: SMB2ShareAccess = [.read, .write, .delete]

    /// No sharing allowed
    public static let none = SMB2ShareAccess([])
}

extension SMB2ShareAccess: CustomStringConvertible {
    public var description: String {
        var parts: [String] = []
        if contains(.read) { parts.append("Read") }
        if contains(.write) { parts.append("Write") }
        if contains(.delete) { parts.append("Delete") }
        if parts.isEmpty { return "SMB2ShareAccess.none" }
        return "SMB2ShareAccess[\(parts.joined(separator: ", "))]"
    }
}
