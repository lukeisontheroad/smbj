// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Logging

/// Base class for SMB share connections
public class SMBShare: @unchecked Sendable {
    private weak var _session: SMBSession?
    internal let treeId: UInt32
    internal let shareName: String
    internal let logger: Logger

    internal var session: SMBSession? { _session }

    internal init(session: SMBSession, treeId: UInt32, shareName: String) {
        self._session = session
        self.treeId = treeId
        self.shareName = shareName
        self.logger = Logger(label: "com.smbj.share.\(shareName)")
    }

    /// Close the share connection
    public func close() async throws {
        guard let session = session else { return }
        try await session.disconnectShare(self)
    }
}

/// Represents a disk share (file system share)
public class DiskShare: SMBShare {
    /// Open a file
    public func openFile(
        path: String,
        accessMask: AccessMask = .fileRead,
        attributes: FileAttributes = .normal,
        shareAccess: SMB2ShareAccess = .all,
        createDisposition: SMB2CreateDisposition = .open,
        createOptions: SMB2CreateOptions = [.nonDirectoryFile]
    ) async throws -> SMBFile {
        guard let session = session else {
            throw SMBError.shareError(reason: "Session not available")
        }

        let request = SMB2CreateRequest(
            path: path,
            accessMask: accessMask,
            attributes: attributes,
            shareAccess: shareAccess,
            createDisposition: createDisposition,
            createOptions: createOptions
        )
        request.header.treeId = treeId

        let response = try await session.sendAndReceive(request)

        guard response.header.status == .statusSuccess else {
            throw SMBApiException(status: response.header.status, command: .create)
        }

        let createResponse = try SMB2CreateResponse.read(from: response.data)
        return SMBFile(share: self, fileId: createResponse.fileId, path: path)
    }

    /// Open a directory
    public func openDirectory(
        path: String,
        accessMask: AccessMask = [.fileListDirectory, .fileReadAttributes],
        shareAccess: SMB2ShareAccess = .all
    ) async throws -> SMBDirectory {
        guard let session = session else {
            throw SMBError.shareError(reason: "Session not available")
        }

        let request = SMB2CreateRequest(
            path: path,
            accessMask: accessMask,
            attributes: .directory,
            shareAccess: shareAccess,
            createDisposition: .open,
            createOptions: [.directoryFile]
        )
        request.header.treeId = treeId

        let response = try await session.sendAndReceive(request)

        guard response.header.status == .statusSuccess else {
            throw SMBApiException(status: response.header.status, command: .create)
        }

        let createResponse = try SMB2CreateResponse.read(from: response.data)
        return SMBDirectory(share: self, fileId: createResponse.fileId, path: path)
    }

    /// List files in a directory
    public func list(_ path: String, pattern: String = "*") async throws -> [FileDirectoryInfo] {
        let directory = try await openDirectory(path: path)
        defer { Task { try? await directory.close() } }

        return try await directory.list(pattern: pattern)
    }

    /// Check if a file or directory exists
    public func exists(_ path: String) async throws -> Bool {
        do {
            let file = try await openFile(
                path: path,
                accessMask: .fileReadAttributes,
                createDisposition: .open
            )
            try await file.close()
            return true
        } catch let error as SMBApiException {
            if error.isNotFound {
                return false
            }
            throw error
        }
    }

    /// Create a directory
    public func mkdir(_ path: String) async throws {
        guard let session = session else {
            throw SMBError.shareError(reason: "Session not available")
        }

        let request = SMB2CreateRequest(
            path: path,
            accessMask: [.fileListDirectory, .fileAddFile, .fileAddSubdirectory],
            attributes: .directory,
            shareAccess: .all,
            createDisposition: .create,
            createOptions: [.directoryFile]
        )
        request.header.treeId = treeId

        let response = try await session.sendAndReceive(request)

        guard response.header.status == .statusSuccess else {
            throw SMBApiException(status: response.header.status, command: .create)
        }

        // Close the directory handle
        let createResponse = try SMB2CreateResponse.read(from: response.data)
        let closeRequest = SMB2CloseRequest(fileId: createResponse.fileId)
        closeRequest.header.treeId = treeId
        _ = try await session.sendAndReceive(closeRequest)
    }

    /// Remove a file
    public func rm(_ path: String) async throws {
        let file = try await openFile(
            path: path,
            accessMask: .delete,
            createDisposition: .open,
            createOptions: [.nonDirectoryFile, .deleteOnClose]
        )
        try await file.close()
    }

    /// Remove a directory
    public func rmdir(_ path: String) async throws {
        guard let session = session else {
            throw SMBError.shareError(reason: "Session not available")
        }

        let request = SMB2CreateRequest(
            path: path,
            accessMask: .delete,
            attributes: .directory,
            shareAccess: .all,
            createDisposition: .open,
            createOptions: [.directoryFile, .deleteOnClose]
        )
        request.header.treeId = treeId

        let response = try await session.sendAndReceive(request)

        guard response.header.status == .statusSuccess else {
            throw SMBApiException(status: response.header.status, command: .create)
        }

        // Close to delete
        let createResponse = try SMB2CreateResponse.read(from: response.data)
        let closeRequest = SMB2CloseRequest(fileId: createResponse.fileId)
        closeRequest.header.treeId = treeId
        _ = try await session.sendAndReceive(closeRequest)
    }
}
