// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// [MS-SMB2].pdf 2.2.13 SMB2 CREATE Request - CreateDisposition
/// Defines the action the server MUST take if the file already exists
public enum SMB2CreateDisposition: UInt32, Sendable {
    /// If the file already exists, supersede it. Otherwise, create the file.
    /// This value SHOULD NOT be used for a printer object.
    case supersede = 0x00000000

    /// If the file already exists, return success; otherwise, fail the operation.
    /// MUST NOT be used for a printer object.
    case open = 0x00000001

    /// If the file already exists, fail the operation; otherwise, create the file.
    case create = 0x00000002

    /// Open the file if it already exists; otherwise, create the file.
    /// This value SHOULD NOT be used for a printer object.
    case openIf = 0x00000003

    /// Overwrite the file if it already exists; otherwise, fail the operation.
    /// MUST NOT be used for a printer object.
    case overwrite = 0x00000004

    /// Overwrite the file if it already exists; otherwise, create the file.
    /// This value SHOULD NOT be used for a printer object.
    case overwriteIf = 0x00000005
}

extension SMB2CreateDisposition: CustomStringConvertible {
    public var description: String {
        switch self {
        case .supersede: return "FILE_SUPERSEDE"
        case .open: return "FILE_OPEN"
        case .create: return "FILE_CREATE"
        case .openIf: return "FILE_OPEN_IF"
        case .overwrite: return "FILE_OVERWRITE"
        case .overwriteIf: return "FILE_OVERWRITE_IF"
        }
    }
}
