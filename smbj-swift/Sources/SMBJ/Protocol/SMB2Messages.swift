// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - Create Request/Response

/// SMB2 Create Request
public class SMB2CreateRequest: SMB2Request {
    public var path: String
    public var accessMask: AccessMask
    public var attributes: FileAttributes
    public var shareAccess: SMB2ShareAccess
    public var createDisposition: SMB2CreateDisposition
    public var createOptions: SMB2CreateOptions

    public init(
        path: String,
        accessMask: AccessMask = .fileRead,
        attributes: FileAttributes = .normal,
        shareAccess: SMB2ShareAccess = .all,
        createDisposition: SMB2CreateDisposition = .open,
        createOptions: SMB2CreateOptions = [.nonDirectoryFile]
    ) {
        self.path = path
        self.accessMask = accessMask
        self.attributes = attributes
        self.shareAccess = shareAccess
        self.createDisposition = createDisposition
        self.createOptions = createOptions
        super.init(command: .create)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        let pathData = path.data(using: .utf16LittleEndian) ?? Data()

        // Structure size (57)
        buffer.appendUInt16(57)

        // Security flags
        buffer.append(0)

        // Requested oplock level
        buffer.append(0) // No oplock

        // Impersonation level
        buffer.appendUInt32(0x02) // Impersonation

        // Smb create flags
        buffer.appendUInt64(0)

        // Reserved
        buffer.appendUInt64(0)

        // Desired access
        buffer.appendUInt32(accessMask.rawValue)

        // File attributes
        buffer.appendUInt32(attributes.rawValue)

        // Share access
        buffer.appendUInt32(shareAccess.rawValue)

        // Create disposition
        buffer.appendUInt32(createDisposition.rawValue)

        // Create options
        buffer.appendUInt32(createOptions.rawValue)

        // Name offset
        let nameOffset = UInt16(SMB2PacketHeader.structureSize + 56)
        buffer.appendUInt16(nameOffset)

        // Name length
        buffer.appendUInt16(UInt16(pathData.count))

        // Create contexts offset
        buffer.appendUInt32(0)

        // Create contexts length
        buffer.appendUInt32(0)

        // Path
        buffer.append(pathData)
    }
}

/// SMB2 Create Response
public struct SMB2CreateResponse {
    public var fileId: SMB2FileId
    public var creationTime: UInt64
    public var lastAccessTime: UInt64
    public var lastWriteTime: UInt64
    public var changeTime: UInt64
    public var allocationSize: UInt64
    public var endOfFile: UInt64
    public var attributes: FileAttributes

    public static func read(from data: Data) throws -> SMB2CreateResponse {
        var buffer = SMBBuffer(data: data)

        // Structure size
        let _ = try buffer.readUInt16()

        // Oplock level
        let _ = try buffer.readByte()

        // Flags
        let _ = try buffer.readByte()

        // Create action
        let _ = try buffer.readUInt32()

        // Creation time
        let creationTime = try buffer.readUInt64()

        // Last access time
        let lastAccessTime = try buffer.readUInt64()

        // Last write time
        let lastWriteTime = try buffer.readUInt64()

        // Change time
        let changeTime = try buffer.readUInt64()

        // Allocation size
        let allocationSize = try buffer.readUInt64()

        // End of file
        let endOfFile = try buffer.readUInt64()

        // File attributes
        let attributes = FileAttributes(rawValue: try buffer.readUInt32())

        // Reserved2
        let _ = try buffer.readUInt32()

        // File ID
        let fileId = try SMB2FileId.read(from: &buffer)

        return SMB2CreateResponse(
            fileId: fileId,
            creationTime: creationTime,
            lastAccessTime: lastAccessTime,
            lastWriteTime: lastWriteTime,
            changeTime: changeTime,
            allocationSize: allocationSize,
            endOfFile: endOfFile,
            attributes: attributes
        )
    }
}

// MARK: - Close Request

/// SMB2 Close Request
public class SMB2CloseRequest: SMB2Request {
    public var fileId: SMB2FileId

    public init(fileId: SMB2FileId) {
        self.fileId = fileId
        super.init(command: .close)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        // Structure size (24)
        buffer.appendUInt16(24)

        // Flags
        buffer.appendUInt16(0)

        // Reserved
        buffer.appendUInt32(0)

        // File ID
        fileId.write(to: &buffer)
    }
}

// MARK: - Read Request/Response

/// SMB2 Read Request
public class SMB2ReadRequest: SMB2Request {
    public var fileId: SMB2FileId
    public var offset: UInt64
    public var length: UInt32

    public init(fileId: SMB2FileId, offset: UInt64, length: UInt32) {
        self.fileId = fileId
        self.offset = offset
        self.length = length
        super.init(command: .read)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        // Structure size (49)
        buffer.appendUInt16(49)

        // Padding
        buffer.append(0)

        // Flags
        buffer.append(0)

        // Length
        buffer.appendUInt32(length)

        // Offset
        buffer.appendUInt64(offset)

        // File ID
        fileId.write(to: &buffer)

        // Minimum count
        buffer.appendUInt32(0)

        // Channel
        buffer.appendUInt32(0)

        // Remaining bytes
        buffer.appendUInt32(0)

        // Read channel info offset
        buffer.appendUInt16(0)

        // Read channel info length
        buffer.appendUInt16(0)

        // Padding byte
        buffer.append(0)
    }
}

/// SMB2 Read Response
public struct SMB2ReadResponse {
    public static func read(from data: Data) throws -> Data {
        var buffer = SMBBuffer(data: data)

        // Structure size
        let _ = try buffer.readUInt16()

        // Data offset
        let dataOffset = try buffer.readByte()

        // Reserved
        let _ = try buffer.readByte()

        // Data length
        let dataLength = try buffer.readUInt32()

        // Data remaining
        let _ = try buffer.readUInt32()

        // Reserved2
        let _ = try buffer.readUInt32()

        // Position at data
        buffer.position = Int(dataOffset) - Int(SMB2PacketHeader.structureSize)

        return try buffer.readBytes(count: Int(dataLength))
    }
}

// MARK: - Write Request/Response

/// SMB2 Write Request
public class SMB2WriteRequest: SMB2Request {
    public var fileId: SMB2FileId
    public var offset: UInt64
    public var data: Data

    public init(fileId: SMB2FileId, offset: UInt64, data: Data) {
        self.fileId = fileId
        self.offset = offset
        self.data = data
        super.init(command: .write)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        // Structure size (49)
        buffer.appendUInt16(49)

        // Data offset
        let dataOffset = UInt16(SMB2PacketHeader.structureSize + 48)
        buffer.appendUInt16(dataOffset)

        // Length
        buffer.appendUInt32(UInt32(data.count))

        // Offset
        buffer.appendUInt64(offset)

        // File ID
        fileId.write(to: &buffer)

        // Channel
        buffer.appendUInt32(0)

        // Remaining bytes
        buffer.appendUInt32(0)

        // Write channel info offset
        buffer.appendUInt16(0)

        // Write channel info length
        buffer.appendUInt16(0)

        // Flags
        buffer.appendUInt32(0)

        // Data
        buffer.append(data)
    }
}

/// SMB2 Write Response
public struct SMB2WriteResponse {
    public static func readBytesWritten(from data: Data) throws -> UInt32 {
        var buffer = SMBBuffer(data: data)

        // Structure size
        let _ = try buffer.readUInt16()

        // Reserved
        let _ = try buffer.readUInt16()

        // Count (bytes written)
        return try buffer.readUInt32()
    }
}

// MARK: - Flush Request

/// SMB2 Flush Request
public class SMB2FlushRequest: SMB2Request {
    public var fileId: SMB2FileId

    public init(fileId: SMB2FileId) {
        self.fileId = fileId
        super.init(command: .flush)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        // Structure size (24)
        buffer.appendUInt16(24)

        // Reserved1
        buffer.appendUInt16(0)

        // Reserved2
        buffer.appendUInt32(0)

        // File ID
        fileId.write(to: &buffer)
    }
}

// MARK: - Query Directory Request

/// Query directory flags
public struct QueryDirectoryFlags: OptionSet, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let restart = QueryDirectoryFlags(rawValue: 0x01)
    public static let returnSingleEntry = QueryDirectoryFlags(rawValue: 0x02)
    public static let indexSpecified = QueryDirectoryFlags(rawValue: 0x04)
    public static let reopen = QueryDirectoryFlags(rawValue: 0x10)
}

/// SMB2 Query Directory Request
public class SMB2QueryDirectoryRequest: SMB2Request {
    public var fileId: SMB2FileId
    public var pattern: String
    public var flags: QueryDirectoryFlags

    public init(fileId: SMB2FileId, pattern: String = "*", flags: QueryDirectoryFlags = []) {
        self.fileId = fileId
        self.pattern = pattern
        self.flags = flags
        super.init(command: .queryDirectory)
    }

    public override func write(to buffer: inout SMBBuffer) {
        super.write(to: &buffer)

        let patternData = pattern.data(using: .utf16LittleEndian) ?? Data()

        // Structure size (33)
        buffer.appendUInt16(33)

        // File information class (FileIdBothDirectoryInformation = 0x25)
        buffer.append(0x25)

        // Flags
        buffer.append(flags.rawValue)

        // File index
        buffer.appendUInt32(0)

        // File ID
        fileId.write(to: &buffer)

        // File name offset
        let fileNameOffset = UInt16(SMB2PacketHeader.structureSize + 32)
        buffer.appendUInt16(fileNameOffset)

        // File name length
        buffer.appendUInt16(UInt16(patternData.count))

        // Output buffer length
        buffer.appendUInt32(65536)

        // Pattern
        buffer.append(patternData)
    }
}
