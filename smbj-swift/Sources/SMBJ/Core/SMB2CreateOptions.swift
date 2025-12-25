// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// SMB2 Create 2.2.13 - CreateOptions
/// Specifies the options to be applied when creating or opening the file
public struct SMB2CreateOptions: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// The file being created or opened is a directory file
    public static let directoryFile = SMB2CreateOptions(rawValue: 0x00000001)

    /// Writes should be propagated to persistent storage before returning success
    public static let writeThrough = SMB2CreateOptions(rawValue: 0x00000002)

    /// The application intends to read or write at sequential offsets
    public static let sequentialOnly = SMB2CreateOptions(rawValue: 0x00000004)

    /// The server should not cache data at intermediate layers
    public static let noIntermediateBuffering = SMB2CreateOptions(rawValue: 0x00000008)

    /// If the file exists and is not a directory, fail with STATUS_FILE_IS_A_DIRECTORY
    public static let nonDirectoryFile = SMB2CreateOptions(rawValue: 0x00000040)

    /// The caller does not understand how to handle extended attributes
    public static let noEAKnowledge = SMB2CreateOptions(rawValue: 0x00000200)

    /// The application intends to read or write at random offsets
    public static let randomAccess = SMB2CreateOptions(rawValue: 0x00000800)

    /// The file MUST be automatically deleted when the last open request is closed
    public static let deleteOnClose = SMB2CreateOptions(rawValue: 0x00001000)

    /// The file is being opened for backup intent
    public static let openForBackupIntent = SMB2CreateOptions(rawValue: 0x00004000)

    /// The file cannot be compressed
    public static let noCompression = SMB2CreateOptions(rawValue: 0x00008000)

    /// Open the reparse point itself rather than the target
    public static let openReparsePoint = SMB2CreateOptions(rawValue: 0x00200000)

    /// The file SHOULD NOT be recalled from tertiary storage
    public static let openNoRecall = SMB2CreateOptions(rawValue: 0x00400000)
}

extension SMB2CreateOptions: CustomStringConvertible {
    public var description: String {
        var parts: [String] = []
        if contains(.directoryFile) { parts.append("DirectoryFile") }
        if contains(.writeThrough) { parts.append("WriteThrough") }
        if contains(.sequentialOnly) { parts.append("SequentialOnly") }
        if contains(.noIntermediateBuffering) { parts.append("NoIntermediateBuffering") }
        if contains(.nonDirectoryFile) { parts.append("NonDirectoryFile") }
        if contains(.noEAKnowledge) { parts.append("NoEAKnowledge") }
        if contains(.randomAccess) { parts.append("RandomAccess") }
        if contains(.deleteOnClose) { parts.append("DeleteOnClose") }
        if contains(.openForBackupIntent) { parts.append("OpenForBackupIntent") }
        if contains(.noCompression) { parts.append("NoCompression") }
        if contains(.openReparsePoint) { parts.append("OpenReparsePoint") }
        if contains(.openNoRecall) { parts.append("OpenNoRecall") }
        if parts.isEmpty { return "SMB2CreateOptions.none" }
        return "SMB2CreateOptions[\(parts.joined(separator: ", "))]"
    }
}
