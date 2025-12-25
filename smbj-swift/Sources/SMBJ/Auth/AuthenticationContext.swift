// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Authentication credentials for SMB connections
public struct AuthenticationContext: Sendable {
    /// The username for authentication
    public let username: String

    /// The password for authentication (stored securely)
    private let password: [Character]

    /// The domain for authentication
    public let domain: String?

    /// Create an authentication context with credentials
    /// - Parameters:
    ///   - username: The username
    ///   - password: The password as a character array (will be copied)
    ///   - domain: The domain (optional)
    public init(username: String, password: [Character], domain: String? = nil) {
        self.username = username
        self.password = Array(password)
        self.domain = domain
    }

    /// Create an authentication context from a string password
    /// - Parameters:
    ///   - username: The username
    ///   - password: The password as a string
    ///   - domain: The domain (optional)
    public init(username: String, password: String, domain: String? = nil) {
        self.init(username: username, password: Array(password), domain: domain)
    }

    /// Create an anonymous authentication context
    public static func anonymous() -> AuthenticationContext {
        return AuthenticationContext(username: "", password: [], domain: nil)
    }

    /// Create a guest authentication context
    public static func guest() -> AuthenticationContext {
        return AuthenticationContext(username: "Guest", password: [], domain: nil)
    }

    /// Get the password as a character array
    public func getPassword() -> [Character] {
        return Array(password)
    }

    /// Get the password as a string
    public func getPasswordString() -> String {
        return String(password)
    }

    /// Get the password as UTF-16LE data (for NTLM)
    public func getPasswordData() -> Data {
        let passwordString = String(password)
        return passwordString.data(using: .utf16LittleEndian) ?? Data()
    }

    /// Check if this is an anonymous login
    public var isAnonymous: Bool {
        return username.isEmpty && password.isEmpty
    }

    /// Check if this is a guest login
    public var isGuest: Bool {
        return username == "Guest" && password.isEmpty
    }
}

extension AuthenticationContext: CustomStringConvertible {
    public var description: String {
        if let domain = domain {
            return "AuthenticationContext[\(username)@\(domain)]"
        }
        return "AuthenticationContext[\(username)]"
    }
}

extension AuthenticationContext: CustomDebugStringConvertible {
    public var debugDescription: String {
        return description
    }
}
