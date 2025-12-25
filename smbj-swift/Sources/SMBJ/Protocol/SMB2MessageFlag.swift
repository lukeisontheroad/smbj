// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// SMB2 Packet Header Flags
public struct SMB2MessageFlag: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// When set, indicates the message is a response
    public static let serverToRedir = SMB2MessageFlag(rawValue: 0x00000001)

    /// When set, indicates that this is an async SMB2 header
    public static let asyncCommand = SMB2MessageFlag(rawValue: 0x00000002)

    /// When set, indicates that this packet is a related operation in a compounded request chain
    public static let relatedOperations = SMB2MessageFlag(rawValue: 0x00000004)

    /// When set, indicates that this packet has been signed
    public static let signed = SMB2MessageFlag(rawValue: 0x00000008)

    /// Priority mask (3 bits)
    public static let priorityMask = SMB2MessageFlag(rawValue: 0x00000070)

    /// When set, indicates that this command is a DFS operation
    public static let dfsOperations = SMB2MessageFlag(rawValue: 0x10000000)

    /// When set, indicates this is a replay operation
    public static let replayOperation = SMB2MessageFlag(rawValue: 0x20000000)
}

extension SMB2MessageFlag: CustomStringConvertible {
    public var description: String {
        var parts: [String] = []
        if contains(.serverToRedir) { parts.append("ServerToRedir") }
        if contains(.asyncCommand) { parts.append("AsyncCommand") }
        if contains(.relatedOperations) { parts.append("RelatedOperations") }
        if contains(.signed) { parts.append("Signed") }
        if contains(.dfsOperations) { parts.append("DfsOperations") }
        if contains(.replayOperation) { parts.append("ReplayOperation") }
        if parts.isEmpty { return "SMB2MessageFlag.none" }
        return "SMB2MessageFlag[\(parts.joined(separator: ", "))]"
    }
}
