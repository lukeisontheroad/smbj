// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Errors that can occur during SMB operations
public enum SMBError: Error, LocalizedError {
    /// Server returned an error status
    case serverError(status: NtStatus, message: String?)

    /// Connection failed
    case connectionFailed(reason: String)

    /// Authentication failed
    case authenticationFailed(reason: String)

    /// Transport error
    case transportError(underlying: Error?)

    /// Invalid response from server
    case invalidResponse(reason: String)

    /// Share access error
    case shareError(reason: String)

    /// File operation error
    case fileError(reason: String)

    /// Timeout occurred
    case timeout

    /// Protocol error
    case protocolError(reason: String)

    /// Operation not supported
    case notSupported(feature: String)

    /// Buffer error
    case bufferError(underlying: SMBBufferError)

    public var errorDescription: String? {
        switch self {
        case .serverError(let status, let message):
            if let message = message {
                return "Server error: \(status) - \(message)"
            }
            return "Server error: \(status)"

        case .connectionFailed(let reason):
            return "Connection failed: \(reason)"

        case .authenticationFailed(let reason):
            return "Authentication failed: \(reason)"

        case .transportError(let underlying):
            if let underlying = underlying {
                return "Transport error: \(underlying.localizedDescription)"
            }
            return "Transport error"

        case .invalidResponse(let reason):
            return "Invalid response: \(reason)"

        case .shareError(let reason):
            return "Share error: \(reason)"

        case .fileError(let reason):
            return "File error: \(reason)"

        case .timeout:
            return "Operation timed out"

        case .protocolError(let reason):
            return "Protocol error: \(reason)"

        case .notSupported(let feature):
            return "Not supported: \(feature)"

        case .bufferError(let underlying):
            return "Buffer error: \(underlying.localizedDescription)"
        }
    }
}

/// Exception wrapper for API errors with status code
public struct SMBApiException: Error, LocalizedError {
    public let status: NtStatus
    public let statusCode: UInt32
    public let command: SMB2MessageCommandCode?
    public let message: String?

    public init(status: NtStatus, command: SMB2MessageCommandCode? = nil, message: String? = nil) {
        self.status = status
        self.statusCode = status.rawValue
        self.command = command
        self.message = message
    }

    public init(statusCode: UInt32, command: SMB2MessageCommandCode? = nil, message: String? = nil) {
        self.status = NtStatus(rawValue: statusCode)
        self.statusCode = statusCode
        self.command = command
        self.message = message
    }

    public var errorDescription: String? {
        var desc = "SMB API Error: \(status)"
        if let command = command {
            desc += " (command: \(command))"
        }
        if let message = message {
            desc += " - \(message)"
        }
        return desc
    }

    public var isAccessDenied: Bool {
        return status == .statusAccessDenied
    }

    public var isNotFound: Bool {
        return status == .statusObjectNameNotFound || status == .statusObjectPathNotFound || status == .statusNotFound
    }

    public var isSharingViolation: Bool {
        return status == .statusSharingViolation
    }
}
