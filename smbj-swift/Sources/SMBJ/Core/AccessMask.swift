// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// MS-DTYP 2.4.3 ACCESS_MASK
/// Access rights for files, directories, and other objects
public struct AccessMask: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    // MARK: - File/Pipe/Printer Access Mask (2.2.13.1.1)

    /// Read data from the file
    public static let fileReadData = AccessMask(rawValue: 0x00000001)

    /// Write data to the file
    public static let fileWriteData = AccessMask(rawValue: 0x00000002)

    /// Append data to the file
    public static let fileAppendData = AccessMask(rawValue: 0x00000004)

    /// Read extended attributes
    public static let fileReadEA = AccessMask(rawValue: 0x00000008)

    /// Write extended attributes
    public static let fileWriteEA = AccessMask(rawValue: 0x00000010)

    /// Execute the file
    public static let fileExecute = AccessMask(rawValue: 0x00000020)

    /// Read file attributes
    public static let fileReadAttributes = AccessMask(rawValue: 0x00000080)

    /// Write file attributes
    public static let fileWriteAttributes = AccessMask(rawValue: 0x00000100)

    // MARK: - Directory Access Mask (2.2.13.1.2)

    /// List directory contents (same value as fileReadData)
    public static let fileListDirectory = AccessMask(rawValue: 0x00000001)

    /// Add file to directory (same value as fileWriteData)
    public static let fileAddFile = AccessMask(rawValue: 0x00000002)

    /// Add subdirectory (same value as fileAppendData)
    public static let fileAddSubdirectory = AccessMask(rawValue: 0x00000004)

    /// Traverse directory (same value as fileExecute)
    public static let fileTraverse = AccessMask(rawValue: 0x00000020)

    /// Delete child entries
    public static let fileDeleteChild = AccessMask(rawValue: 0x00000040)

    // MARK: - Standard Rights

    /// Delete the object
    public static let delete = AccessMask(rawValue: 0x00010000)

    /// Read the security descriptor
    public static let readControl = AccessMask(rawValue: 0x00020000)

    /// Write the discretionary ACL
    public static let writeDAC = AccessMask(rawValue: 0x00040000)

    /// Write the owner
    public static let writeOwner = AccessMask(rawValue: 0x00080000)

    /// Synchronize access
    public static let synchronize = AccessMask(rawValue: 0x00100000)

    /// Access system security
    public static let accessSystemSecurity = AccessMask(rawValue: 0x01000000)

    /// Maximum allowed access
    public static let maximumAllowed = AccessMask(rawValue: 0x02000000)

    // MARK: - Generic Rights

    /// Generic all access
    public static let genericAll = AccessMask(rawValue: 0x10000000)

    /// Generic execute
    public static let genericExecute = AccessMask(rawValue: 0x20000000)

    /// Generic write
    public static let genericWrite = AccessMask(rawValue: 0x40000000)

    /// Generic read
    public static let genericRead = AccessMask(rawValue: 0x80000000)

    // MARK: - Common Combinations

    /// Read access for files
    public static let fileRead: AccessMask = [.fileReadData, .fileReadEA, .fileReadAttributes, .readControl, .synchronize]

    /// Write access for files
    public static let fileWrite: AccessMask = [.fileWriteData, .fileAppendData, .fileWriteEA, .fileWriteAttributes, .readControl, .synchronize]

    /// Full control
    public static let fileFullControl: AccessMask = [.genericAll]
}

extension AccessMask: CustomStringConvertible {
    public var description: String {
        return "AccessMask(0x\(String(rawValue, radix: 16, uppercase: true)))"
    }
}
