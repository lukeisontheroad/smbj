// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Logging

/// Represents an open file on an SMB share
public class SMBFile: @unchecked Sendable {
    private weak var share: DiskShare?
    internal let fileId: SMB2FileId
    public let path: String
    private let logger: Logger

    init(share: DiskShare, fileId: SMB2FileId, path: String) {
        self.share = share
        self.fileId = fileId
        self.path = path
        self.logger = Logger(label: "com.smbj.file")
    }

    /// Read data from the file
    public func read(offset: UInt64 = 0, length: UInt32 = 65536) async throws -> Data {
        guard let share = share, let session = share.session else {
            throw SMBError.fileError(reason: "Share not available")
        }

        let request = SMB2ReadRequest(fileId: fileId, offset: offset, length: length)
        request.header.treeId = share.treeId

        let response = try await session.sendAndReceive(request)

        guard response.header.status == .statusSuccess else {
            // End of file is okay
            if response.header.status == .statusEndOfFile {
                return Data()
            }
            throw SMBApiException(status: response.header.status, command: .read)
        }

        return try SMB2ReadResponse.read(from: response.data)
    }

    /// Read all data from the file
    public func readAll() async throws -> Data {
        var result = Data()
        var offset: UInt64 = 0
        let chunkSize: UInt32 = 65536

        while true {
            let chunk = try await read(offset: offset, length: chunkSize)
            if chunk.isEmpty {
                break
            }
            result.append(chunk)
            offset += UInt64(chunk.count)
            if chunk.count < chunkSize {
                break
            }
        }

        return result
    }

    /// Write data to the file
    public func write(_ data: Data, offset: UInt64 = 0) async throws -> UInt32 {
        guard let share = share, let session = share.session else {
            throw SMBError.fileError(reason: "Share not available")
        }

        let request = SMB2WriteRequest(fileId: fileId, offset: offset, data: data)
        request.header.treeId = share.treeId

        let response = try await session.sendAndReceive(request)

        guard response.header.status == .statusSuccess else {
            throw SMBApiException(status: response.header.status, command: .write)
        }

        return try SMB2WriteResponse.readBytesWritten(from: response.data)
    }

    /// Flush file buffers
    public func flush() async throws {
        guard let share = share, let session = share.session else {
            throw SMBError.fileError(reason: "Share not available")
        }

        let request = SMB2FlushRequest(fileId: fileId)
        request.header.treeId = share.treeId

        let response = try await session.sendAndReceive(request)

        guard response.header.status == .statusSuccess else {
            throw SMBApiException(status: response.header.status, command: .flush)
        }
    }

    /// Close the file
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
