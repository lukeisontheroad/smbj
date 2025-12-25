// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Crypto

/// NTLM Authentication implementation
public struct NTLMAuthenticator: Sendable {
    private let context: AuthenticationContext

    public init(context: AuthenticationContext) {
        self.context = context
    }

    // MARK: - NTLM Message Types

    /// NTLM Negotiate Flags
    public struct NTLMFlags: OptionSet, Sendable {
        public let rawValue: UInt32

        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        public static let negotiateUnicode = NTLMFlags(rawValue: 0x00000001)
        public static let negotiateOEM = NTLMFlags(rawValue: 0x00000002)
        public static let requestTarget = NTLMFlags(rawValue: 0x00000004)
        public static let negotiateSign = NTLMFlags(rawValue: 0x00000010)
        public static let negotiateSeal = NTLMFlags(rawValue: 0x00000020)
        public static let negotiateDatagram = NTLMFlags(rawValue: 0x00000040)
        public static let negotiateLMKey = NTLMFlags(rawValue: 0x00000080)
        public static let negotiateNTLM = NTLMFlags(rawValue: 0x00000200)
        public static let negotiateAnonymous = NTLMFlags(rawValue: 0x00000800)
        public static let negotiateDomainSupplied = NTLMFlags(rawValue: 0x00001000)
        public static let negotiateWorkstationSupplied = NTLMFlags(rawValue: 0x00002000)
        public static let negotiateAlwaysSign = NTLMFlags(rawValue: 0x00008000)
        public static let negotiateTargetTypeShare = NTLMFlags(rawValue: 0x00040000)
        public static let negotiateExtendedSecurity = NTLMFlags(rawValue: 0x00080000)
        public static let negotiateIdentify = NTLMFlags(rawValue: 0x00100000)
        public static let requestNonNTSessionKey = NTLMFlags(rawValue: 0x00400000)
        public static let negotiateTargetInfo = NTLMFlags(rawValue: 0x00800000)
        public static let negotiateVersion = NTLMFlags(rawValue: 0x02000000)
        public static let negotiate128 = NTLMFlags(rawValue: 0x20000000)
        public static let negotiateKeyExchange = NTLMFlags(rawValue: 0x40000000)
        public static let negotiate56 = NTLMFlags(rawValue: 0x80000000)

        /// Default flags for NTLM authentication
        public static let defaultFlags: NTLMFlags = [
            .negotiateUnicode,
            .requestTarget,
            .negotiateSign,
            .negotiateSeal,
            .negotiateNTLM,
            .negotiateAlwaysSign,
            .negotiateExtendedSecurity,
            .negotiateTargetInfo,
            .negotiateVersion,
            .negotiate128,
            .negotiateKeyExchange,
            .negotiate56
        ]
    }

    /// Create NTLM Type 1 (Negotiate) message
    public func createNegotiateMessage() -> Data {
        var buffer = SMBBuffer()

        // Signature "NTLMSSP\0"
        buffer.append(Data([0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00]))

        // Message type (1 = Negotiate)
        buffer.appendUInt32(1)

        // Negotiate flags
        buffer.appendUInt32(NTLMFlags.defaultFlags.rawValue)

        // Domain name fields (len, max len, offset)
        buffer.appendUInt16(0)
        buffer.appendUInt16(0)
        buffer.appendUInt32(0)

        // Workstation name fields (len, max len, offset)
        buffer.appendUInt16(0)
        buffer.appendUInt16(0)
        buffer.appendUInt32(0)

        // Version (optional but recommended)
        // Major version (Windows 10 = 10)
        buffer.append(10)
        // Minor version
        buffer.append(0)
        // Build number
        buffer.appendUInt16(19041)
        // Reserved
        buffer.append(Data(repeating: 0, count: 3))
        // NTLM revision
        buffer.append(15)

        return buffer.bytes
    }

    /// Parse NTLM Type 2 (Challenge) message
    public func parseChallengeMessage(_ data: Data) throws -> NTLMChallenge {
        var buffer = SMBBuffer(data: data)

        // Verify signature
        let signature = try buffer.readBytes(count: 8)
        guard Array(signature) == [0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00] else {
            throw SMBError.authenticationFailed(reason: "Invalid NTLM signature")
        }

        // Message type
        let messageType = try buffer.readUInt32()
        guard messageType == 2 else {
            throw SMBError.authenticationFailed(reason: "Expected NTLM Type 2 message")
        }

        // Target name fields
        let targetNameLen = try buffer.readUInt16()
        let _ = try buffer.readUInt16() // max len
        let targetNameOffset = try buffer.readUInt32()

        // Negotiate flags
        let flags = NTLMFlags(rawValue: try buffer.readUInt32())

        // Server challenge (8 bytes)
        let serverChallenge = try buffer.readBytes(count: 8)

        // Reserved (8 bytes)
        try buffer.skip(8)

        // Target info fields
        let targetInfoLen = try buffer.readUInt16()
        let _ = try buffer.readUInt16() // max len
        let targetInfoOffset = try buffer.readUInt32()

        // Read target name
        var targetName = ""
        if targetNameLen > 0 && targetNameOffset > 0 {
            buffer.position = Int(targetNameOffset)
            targetName = try buffer.readString(byteLength: Int(targetNameLen))
        }

        // Read target info
        var targetInfo = Data()
        if targetInfoLen > 0 && targetInfoOffset > 0 {
            buffer.position = Int(targetInfoOffset)
            targetInfo = try buffer.readBytes(count: Int(targetInfoLen))
        }

        return NTLMChallenge(
            serverChallenge: serverChallenge,
            targetName: targetName,
            targetInfo: targetInfo,
            flags: flags
        )
    }

    /// Create NTLM Type 3 (Authenticate) message
    public func createAuthenticateMessage(challenge: NTLMChallenge) throws -> Data {
        let username = context.username
        let password = context.getPasswordString()
        let domain = context.domain ?? ""

        // Generate client challenge (8 random bytes)
        var clientChallenge = Data(count: 8)
        _ = clientChallenge.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 8, $0.baseAddress!) }

        // Compute NT hash
        let ntHash = computeNTHash(password: password)

        // Compute NTLMv2 response
        let (ntlmResponse, sessionKey) = try computeNTLMv2Response(
            ntHash: ntHash,
            username: username,
            domain: domain,
            serverChallenge: challenge.serverChallenge,
            clientChallenge: clientChallenge,
            targetInfo: challenge.targetInfo
        )

        // Build the message
        var buffer = SMBBuffer()

        let domainData = domain.data(using: .utf16LittleEndian) ?? Data()
        let usernameData = username.data(using: .utf16LittleEndian) ?? Data()
        let workstationData = Data() // Empty workstation

        // Calculate offsets (header is 88 bytes with version)
        let headerSize: UInt32 = 88
        let domainOffset = headerSize
        let usernameOffset = domainOffset + UInt32(domainData.count)
        let workstationOffset = usernameOffset + UInt32(usernameData.count)
        let ntResponseOffset = workstationOffset + UInt32(workstationData.count)

        // Signature "NTLMSSP\0"
        buffer.append(Data([0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00]))

        // Message type (3 = Authenticate)
        buffer.appendUInt32(3)

        // LM response fields (empty for NTLMv2)
        buffer.appendUInt16(0) // len
        buffer.appendUInt16(0) // max len
        buffer.appendUInt32(0) // offset

        // NT response fields
        buffer.appendUInt16(UInt16(ntlmResponse.count))
        buffer.appendUInt16(UInt16(ntlmResponse.count))
        buffer.appendUInt32(ntResponseOffset)

        // Domain fields
        buffer.appendUInt16(UInt16(domainData.count))
        buffer.appendUInt16(UInt16(domainData.count))
        buffer.appendUInt32(domainOffset)

        // Username fields
        buffer.appendUInt16(UInt16(usernameData.count))
        buffer.appendUInt16(UInt16(usernameData.count))
        buffer.appendUInt32(usernameOffset)

        // Workstation fields
        buffer.appendUInt16(UInt16(workstationData.count))
        buffer.appendUInt16(UInt16(workstationData.count))
        buffer.appendUInt32(workstationOffset)

        // Encrypted random session key fields (empty, we use session key from NT response)
        buffer.appendUInt16(0)
        buffer.appendUInt16(0)
        buffer.appendUInt32(0)

        // Negotiate flags
        buffer.appendUInt32(challenge.flags.rawValue)

        // Version
        buffer.append(10) // Major
        buffer.append(0)  // Minor
        buffer.appendUInt16(19041) // Build
        buffer.append(Data(repeating: 0, count: 3)) // Reserved
        buffer.append(15) // NTLM revision

        // MIC (16 bytes, zeros for now)
        buffer.append(Data(repeating: 0, count: 16))

        // Payload
        buffer.append(domainData)
        buffer.append(usernameData)
        buffer.append(workstationData)
        buffer.append(ntlmResponse)

        return buffer.bytes
    }

    // MARK: - Cryptographic Functions

    /// Compute NT hash from password
    private func computeNTHash(password: String) -> Data {
        let passwordData = password.data(using: .utf16LittleEndian) ?? Data()
        let hash = Insecure.MD4.hash(data: passwordData)
        return Data(hash)
    }

    /// Compute NTLMv2 response
    private func computeNTLMv2Response(
        ntHash: Data,
        username: String,
        domain: String,
        serverChallenge: Data,
        clientChallenge: Data,
        targetInfo: Data
    ) throws -> (response: Data, sessionKey: Data) {
        // NTLMv2 hash = HMAC-MD5(NT hash, UPPERCASE(username) + domain)
        let identity = (username.uppercased() + domain).data(using: .utf16LittleEndian) ?? Data()
        let ntlmv2Hash = hmacMD5(key: ntHash, data: identity)

        // Create blob
        var blob = SMBBuffer()
        blob.append(0x01) // Blob signature
        blob.append(0x01)
        blob.appendUInt16(0) // Reserved
        blob.appendUInt32(0) // Reserved
        blob.appendUInt64(UInt64(Date().timeIntervalSince1970 * 10_000_000 + 116444736000000000)) // Timestamp
        blob.append(clientChallenge)
        blob.appendUInt32(0) // Reserved
        blob.append(targetInfo)
        blob.appendUInt32(0) // Reserved

        // NTProofStr = HMAC-MD5(NTLMv2 hash, server challenge + blob)
        var dataToSign = Data()
        dataToSign.append(serverChallenge)
        dataToSign.append(blob.bytes)
        let ntProofStr = hmacMD5(key: ntlmv2Hash, data: dataToSign)

        // Response = NTProofStr + blob
        var response = Data()
        response.append(ntProofStr)
        response.append(blob.bytes)

        // Session key = HMAC-MD5(NTLMv2 hash, NTProofStr)
        let sessionKey = hmacMD5(key: ntlmv2Hash, data: ntProofStr)

        return (response, sessionKey)
    }

    /// HMAC-MD5
    private func hmacMD5(key: Data, data: Data) -> Data {
        let hmac = HMAC<Insecure.MD5>.authenticationCode(for: data, using: SymmetricKey(data: key))
        return Data(hmac)
    }
}

/// NTLM Challenge (Type 2 message data)
public struct NTLMChallenge: Sendable {
    public let serverChallenge: Data
    public let targetName: String
    public let targetInfo: Data
    public let flags: NTLMAuthenticator.NTLMFlags
}
