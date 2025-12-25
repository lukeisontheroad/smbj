// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// SMB2 Protocol Dialect versions
public enum SMB2Dialect: UInt16, Sendable, CaseIterable, Comparable {
    case unknown = 0x0000
    case smb_2_0_2 = 0x0202
    case smb_2_1 = 0x0210
    case smb_2_xx = 0x02FF
    case smb_3_0 = 0x0300
    case smb_3_0_2 = 0x0302
    case smb_3_1_1 = 0x0311

    /// Whether this dialect is an SMB 3.x dialect
    public var isSmb3x: Bool {
        return self == .smb_3_0 || self == .smb_3_0_2 || self == .smb_3_1_1
    }

    /// Default dialects to negotiate (latest preferred)
    public static let defaultDialects: Set<SMB2Dialect> = [.smb_2_0_2, .smb_2_1, .smb_3_0, .smb_3_0_2, .smb_3_1_1]

    /// Check if any of the dialects in the set is an SMB 3.x dialect
    public static func supportsSmb3x(_ dialects: Set<SMB2Dialect>) -> Bool {
        return dialects.contains { $0.isSmb3x }
    }

    public static func < (lhs: SMB2Dialect, rhs: SMB2Dialect) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }

    public init?(rawValue: UInt16) {
        switch rawValue {
        case 0x0000: self = .unknown
        case 0x0202: self = .smb_2_0_2
        case 0x0210: self = .smb_2_1
        case 0x02FF: self = .smb_2_xx
        case 0x0300: self = .smb_3_0
        case 0x0302: self = .smb_3_0_2
        case 0x0311: self = .smb_3_1_1
        default: return nil
        }
    }
}

extension SMB2Dialect: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unknown: return "Unknown"
        case .smb_2_0_2: return "SMB 2.0.2"
        case .smb_2_1: return "SMB 2.1"
        case .smb_2_xx: return "SMB 2.x"
        case .smb_3_0: return "SMB 3.0"
        case .smb_3_0_2: return "SMB 3.0.2"
        case .smb_3_1_1: return "SMB 3.1.1"
        }
    }
}
