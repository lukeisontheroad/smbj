// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Logging

/// Represents an open directory on an SMB share
public class SMBDirectory: @unchecked Sendable {
    private weak var share: DiskShare?
    internal let fileId: SMB2FileId
    public let path: String
    private let logger: Logger

    init(share: DiskShare, fileId: SMB2FileId, path: String) {
        self.share = share
        self.fileId = fileId
        self.path = path
        self.logger = Logger(label: "com.smbj.directory")
    }

    /// List files in the directory
    public func list(pattern: String = "*") async throws -> [FileDirectoryInfo] {
        guard let share = share, let session = share.session else {
            throw SMBError.fileError(reason: "Share not available")
        }

        var results: [FileDirectoryInfo] = []
        var isFirstRequest = true

        while true {
            let request = SMB2QueryDirectoryRequest(
                fileId: fileId,
                pattern: isFirstRequest ? pattern : "",
                flags: isFirstRequest ? [] : [.restart]
            )
            request.header.treeId = share.treeId
            isFirstRequest = false

            let response = try await session.sendAndReceive(request)

            // No more files
            if response.header.status == .statusNoMoreFiles {
                break
            }

            guard response.header.status == .statusSuccess else {
                throw SMBApiException(status: response.header.status, command: .queryDirectory)
            }

            let entries = try parseDirectoryEntries(response.data)
            results.append(contentsOf: entries)

            // If we got fewer entries than expected, we're done
            if entries.isEmpty {
                break
            }
        }

        return results
    }

    private func parseDirectoryEntries(_ data: Data) throws -> [FileDirectoryInfo] {
        var entries: [FileDirectoryInfo] = []
        var buffer = SMBBuffer(data: data)

        // Skip output buffer offset and length
        let _ = try buffer.readUInt16() // Structure size
        let outputBufferOffset = try buffer.readUInt16()
        let outputBufferLength = try buffer.readUInt32()

        guard outputBufferLength > 0 else {
            return []
        }

        // Position at output buffer
        buffer.position = Int(outputBufferOffset) - Int(SMB2PacketHeader.structureSize)

        var offset: UInt32 = 0
        repeat {
            let entryStart = buffer.position

            // Next entry offset
            let nextEntryOffset = try buffer.readUInt32()

            // File index
            let _ = try buffer.readUInt32()

            // Creation time
            let creationTime = try buffer.readUInt64()

            // Last access time
            let lastAccessTime = try buffer.readUInt64()

            // Last write time
            let lastWriteTime = try buffer.readUInt64()

            // Change time
            let changeTime = try buffer.readUInt64()

            // End of file
            let endOfFile = try buffer.readUInt64()

            // Allocation size
            let allocationSize = try buffer.readUInt64()

            // File attributes
            let attributes = FileAttributes(rawValue: try buffer.readUInt32())

            // File name length
            let fileNameLength = try buffer.readUInt32()

            // Extended attributes size
            let _ = try buffer.readUInt32()

            // Short name length
            let shortNameLength = try buffer.readByte()

            // Reserved
            let _ = try buffer.readByte()

            // Short name (24 bytes)
            let _ = try buffer.readBytes(count: 24)

            // Reserved2
            let _ = try buffer.readUInt16()

            // File ID
            let _ = try buffer.readUInt64()

            // File name
            let fileName = try buffer.readString(byteLength: Int(fileNameLength))

            let entry = FileDirectoryInfo(
                fileName: fileName,
                creationTime: creationTime,
                lastAccessTime: lastAccessTime,
                lastWriteTime: lastWriteTime,
                changeTime: changeTime,
                endOfFile: endOfFile,
                allocationSize: allocationSize,
                attributes: attributes
            )
            entries.append(entry)

            offset = nextEntryOffset
            if offset > 0 {
                buffer.position = entryStart + Int(offset)
            }
        } while offset > 0

        return entries
    }

    /// Close the directory
    public func close() async throws {
        guard let share = share, let session = share.session else {
            return
        }

        let request = SMB2CloseRequest(fileId: fileId)
        request.header.treeId = share.treeId

        let response = try await session.sendAndReceive(request)

        if response.header.status != .statusSuccess {
            logger.warning("Close returned status: \(response.header.status)")
        }
    }
}

/// Information about a file or directory
public struct FileDirectoryInfo: Sendable {
    public let fileName: String
    public let creationTime: UInt64
    public let lastAccessTime: UInt64
    public let lastWriteTime: UInt64
    public let changeTime: UInt64
    public let endOfFile: UInt64
    public let allocationSize: UInt64
    public let attributes: FileAttributes

    /// Whether this is a directory
    public var isDirectory: Bool {
        return attributes.contains(.directory)
    }

    /// File size in bytes
    public var fileSize: UInt64 {
        return endOfFile
    }

    /// Convert Windows FILETIME to Date
    public func creationDate() -> Date? {
        return windowsFileTimeToDate(creationTime)
    }

    public func lastAccessDate() -> Date? {
        return windowsFileTimeToDate(lastAccessTime)
    }

    public func lastWriteDate() -> Date? {
        return windowsFileTimeToDate(lastWriteTime)
    }

    private func windowsFileTimeToDate(_ fileTime: UInt64) -> Date? {
        guard fileTime > 0 else { return nil }
        // Windows FILETIME is 100-nanosecond intervals since January 1, 1601
        // Unix epoch is January 1, 1970
        let unixEpochDiff: UInt64 = 116444736000000000
        guard fileTime > unixEpochDiff else { return nil }
        let unixTime = Double(fileTime - unixEpochDiff) / 10_000_000.0
        return Date(timeIntervalSince1970: unixTime)
    }
}
