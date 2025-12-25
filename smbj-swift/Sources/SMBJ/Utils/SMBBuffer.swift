// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Buffer for reading and writing SMB protocol data with little-endian byte order
public struct SMBBuffer {
    private var data: Data
    private var readPosition: Int = 0

    /// Create an empty buffer
    public init() {
        self.data = Data()
    }

    /// Create a buffer with initial capacity
    public init(capacity: Int) {
        self.data = Data()
        self.data.reserveCapacity(capacity)
    }

    /// Create a buffer wrapping existing data
    public init(data: Data) {
        self.data = data
    }

    /// The underlying data
    public var bytes: Data {
        return data
    }

    /// Number of bytes in the buffer
    public var count: Int {
        return data.count
    }

    /// Number of bytes remaining to read
    public var remaining: Int {
        return data.count - readPosition
    }

    /// Current read position
    public var position: Int {
        get { return readPosition }
        set { readPosition = max(0, min(newValue, data.count)) }
    }

    // MARK: - Writing

    /// Append raw bytes
    public mutating func append(_ bytes: Data) {
        data.append(bytes)
    }

    /// Append a single byte
    public mutating func append(_ byte: UInt8) {
        data.append(byte)
    }

    /// Append UInt16 in little-endian order
    public mutating func appendUInt16(_ value: UInt16) {
        var le = value.littleEndian
        data.append(Data(bytes: &le, count: 2))
    }

    /// Append UInt32 in little-endian order
    public mutating func appendUInt32(_ value: UInt32) {
        var le = value.littleEndian
        data.append(Data(bytes: &le, count: 4))
    }

    /// Append UInt64 in little-endian order
    public mutating func appendUInt64(_ value: UInt64) {
        var le = value.littleEndian
        data.append(Data(bytes: &le, count: 8))
    }

    /// Append padding bytes
    public mutating func appendPadding(_ count: Int) {
        data.append(Data(repeating: 0, count: count))
    }

    /// Append a null-terminated UTF-16LE string
    public mutating func appendString(_ string: String) {
        let utf16Data = string.data(using: .utf16LittleEndian) ?? Data()
        data.append(utf16Data)
        appendUInt16(0) // Null terminator
    }

    /// Append a UTF-16LE string without null terminator
    public mutating func appendStringNoNull(_ string: String) {
        let utf16Data = string.data(using: .utf16LittleEndian) ?? Data()
        data.append(utf16Data)
    }

    // MARK: - Reading

    /// Read a single byte
    public mutating func readByte() throws -> UInt8 {
        guard readPosition < data.count else {
            throw SMBBufferError.bufferUnderflow
        }
        let byte = data[data.startIndex + readPosition]
        readPosition += 1
        return byte
    }

    /// Read specified number of bytes
    public mutating func readBytes(count: Int) throws -> Data {
        guard readPosition + count <= data.count else {
            throw SMBBufferError.bufferUnderflow
        }
        let start = data.startIndex + readPosition
        let bytes = data[start..<(start + count)]
        readPosition += count
        return Data(bytes)
    }

    /// Read UInt16 in little-endian order
    public mutating func readUInt16() throws -> UInt16 {
        let bytes = try readBytes(count: 2)
        return bytes.withUnsafeBytes { $0.load(as: UInt16.self).littleEndian }
    }

    /// Read UInt32 in little-endian order
    public mutating func readUInt32() throws -> UInt32 {
        let bytes = try readBytes(count: 4)
        return bytes.withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
    }

    /// Read UInt64 in little-endian order
    public mutating func readUInt64() throws -> UInt64 {
        let bytes = try readBytes(count: 8)
        return bytes.withUnsafeBytes { $0.load(as: UInt64.self).littleEndian }
    }

    /// Skip specified number of bytes
    public mutating func skip(_ count: Int) throws {
        guard readPosition + count <= data.count else {
            throw SMBBufferError.bufferUnderflow
        }
        readPosition += count
    }

    /// Read a null-terminated UTF-16LE string
    public mutating func readString(byteLength: Int) throws -> String {
        let bytes = try readBytes(count: byteLength)
        // Remove null terminators
        var trimmedBytes = bytes
        while trimmedBytes.count >= 2 {
            let lastTwo = trimmedBytes.suffix(2)
            if lastTwo.allSatisfy({ $0 == 0 }) {
                trimmedBytes = trimmedBytes.dropLast(2)
            } else {
                break
            }
        }
        return String(data: trimmedBytes, encoding: .utf16LittleEndian) ?? ""
    }

    /// Peek at bytes without advancing position
    public func peek(count: Int) throws -> Data {
        guard readPosition + count <= data.count else {
            throw SMBBufferError.bufferUnderflow
        }
        let start = data.startIndex + readPosition
        return Data(data[start..<(start + count)])
    }

    /// Read remaining bytes
    public mutating func readRemaining() -> Data {
        let start = data.startIndex + readPosition
        let remaining = Data(data[start...])
        readPosition = data.count
        return remaining
    }

    /// Reset read position to beginning
    public mutating func rewind() {
        readPosition = 0
    }

    /// Write at specific offset
    public mutating func write(at offset: Int, value: UInt16) {
        guard offset + 2 <= data.count else { return }
        var le = value.littleEndian
        withUnsafeBytes(of: &le) { bytes in
            for (i, byte) in bytes.enumerated() {
                data[data.startIndex + offset + i] = byte
            }
        }
    }

    /// Write at specific offset
    public mutating func write(at offset: Int, value: UInt32) {
        guard offset + 4 <= data.count else { return }
        var le = value.littleEndian
        withUnsafeBytes(of: &le) { bytes in
            for (i, byte) in bytes.enumerated() {
                data[data.startIndex + offset + i] = byte
            }
        }
    }
}

/// Errors that can occur during buffer operations
public enum SMBBufferError: Error, LocalizedError {
    case bufferUnderflow
    case invalidData

    public var errorDescription: String? {
        switch self {
        case .bufferUnderflow:
            return "Buffer underflow: attempted to read beyond buffer bounds"
        case .invalidData:
            return "Invalid data in buffer"
        }
    }
}
