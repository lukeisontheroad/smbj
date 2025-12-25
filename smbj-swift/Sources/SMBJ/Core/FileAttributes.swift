// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// [MS-FSCC].pdf 2.6 File Attributes
/// File and directory attributes that can be used in any combination unless noted.
public struct FileAttributes: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// A file or directory that is read-only
    public static let readOnly = FileAttributes(rawValue: 0x00000001)

    /// A file or directory that is hidden
    public static let hidden = FileAttributes(rawValue: 0x00000002)

    /// A file or directory that the operating system uses
    public static let system = FileAttributes(rawValue: 0x00000004)

    /// This item is a directory
    public static let directory = FileAttributes(rawValue: 0x00000010)

    /// A file or directory that requires to be archived
    public static let archive = FileAttributes(rawValue: 0x00000020)

    /// A file that does not have other attributes set
    public static let normal = FileAttributes(rawValue: 0x00000080)

    /// A file that is being used for temporary storage
    public static let temporary = FileAttributes(rawValue: 0x00000100)

    /// A file that is a sparse file
    public static let sparseFile = FileAttributes(rawValue: 0x00000200)

    /// A file or directory that has an associated reparse point
    public static let reparsePoint = FileAttributes(rawValue: 0x00000400)

    /// A file or directory that is compressed
    public static let compressed = FileAttributes(rawValue: 0x00000800)

    /// The data in this file is not available immediately (offline storage)
    public static let offline = FileAttributes(rawValue: 0x00001000)

    /// A file or directory that is not indexed by the content indexing service
    public static let notContentIndexed = FileAttributes(rawValue: 0x00002000)

    /// A file or directory that is encrypted
    public static let encrypted = FileAttributes(rawValue: 0x00004000)

    /// A file or directory with integrity support
    public static let integrityStream = FileAttributes(rawValue: 0x00008000)

    /// A file or directory excluded from data integrity scan
    public static let noScrubData = FileAttributes(rawValue: 0x00020000)
}

extension FileAttributes: CustomStringConvertible {
    public var description: String {
        var parts: [String] = []
        if contains(.readOnly) { parts.append("ReadOnly") }
        if contains(.hidden) { parts.append("Hidden") }
        if contains(.system) { parts.append("System") }
        if contains(.directory) { parts.append("Directory") }
        if contains(.archive) { parts.append("Archive") }
        if contains(.normal) { parts.append("Normal") }
        if contains(.temporary) { parts.append("Temporary") }
        if contains(.sparseFile) { parts.append("SparseFile") }
        if contains(.reparsePoint) { parts.append("ReparsePoint") }
        if contains(.compressed) { parts.append("Compressed") }
        if contains(.offline) { parts.append("Offline") }
        if contains(.notContentIndexed) { parts.append("NotContentIndexed") }
        if contains(.encrypted) { parts.append("Encrypted") }
        if contains(.integrityStream) { parts.append("IntegrityStream") }
        if contains(.noScrubData) { parts.append("NoScrubData") }
        return "FileAttributes[\(parts.joined(separator: ", "))]"
    }
}
