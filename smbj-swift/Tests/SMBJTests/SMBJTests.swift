// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import SMBJ

final class SMBJTests: XCTestCase {

    // MARK: - NtStatus Tests

    func testNtStatusSuccess() {
        XCTAssertEqual(NtStatus.statusSuccess.rawValue, 0x00000000)
        XCTAssertTrue(NtStatus.statusSuccess.isSuccess)
        XCTAssertFalse(NtStatus.statusSuccess.isError)
    }

    func testNtStatusError() {
        XCTAssertTrue(NtStatus.statusAccessDenied.isError)
        XCTAssertFalse(NtStatus.statusAccessDenied.isSuccess)
    }

    func testNtStatusFromRawValue() {
        let status = NtStatus(rawValue: 0xC0000022)
        XCTAssertEqual(status, .statusAccessDenied)
    }

    // MARK: - SMB2Dialect Tests

    func testSMB2DialectComparison() {
        XCTAssertTrue(SMB2Dialect.smb_3_1_1 > SMB2Dialect.smb_2_0_2)
        XCTAssertTrue(SMB2Dialect.smb_3_0.isSmb3x)
        XCTAssertFalse(SMB2Dialect.smb_2_1.isSmb3x)
    }

    func testSupportsSmb3x() {
        let dialects: Set<SMB2Dialect> = [.smb_2_1, .smb_3_0]
        XCTAssertTrue(SMB2Dialect.supportsSmb3x(dialects))

        let noSmb3: Set<SMB2Dialect> = [.smb_2_0_2, .smb_2_1]
        XCTAssertFalse(SMB2Dialect.supportsSmb3x(noSmb3))
    }

    // MARK: - FileAttributes Tests

    func testFileAttributesOptionSet() {
        let attrs: FileAttributes = [.readOnly, .hidden]
        XCTAssertTrue(attrs.contains(.readOnly))
        XCTAssertTrue(attrs.contains(.hidden))
        XCTAssertFalse(attrs.contains(.directory))
    }

    func testFileAttributesRawValue() {
        XCTAssertEqual(FileAttributes.directory.rawValue, 0x00000010)
        XCTAssertEqual(FileAttributes.normal.rawValue, 0x00000080)
    }

    // MARK: - AccessMask Tests

    func testAccessMaskOptionSet() {
        let access: AccessMask = [.fileReadData, .fileWriteData]
        XCTAssertTrue(access.contains(.fileReadData))
        XCTAssertTrue(access.contains(.fileWriteData))
        XCTAssertFalse(access.contains(.delete))
    }

    // MARK: - SMBBuffer Tests

    func testBufferWriteRead() throws {
        var buffer = SMBBuffer()
        buffer.appendUInt16(0x1234)
        buffer.appendUInt32(0xDEADBEEF)
        buffer.appendUInt64(0x123456789ABCDEF0)

        XCTAssertEqual(try buffer.readUInt16(), 0x1234)
        XCTAssertEqual(try buffer.readUInt32(), 0xDEADBEEF)
        XCTAssertEqual(try buffer.readUInt64(), 0x123456789ABCDEF0)
    }

    func testBufferString() throws {
        var buffer = SMBBuffer()
        buffer.appendStringNoNull("Test")

        let readString = try buffer.readString(byteLength: 8) // UTF-16LE = 2 bytes per char
        XCTAssertEqual(readString, "Test")
    }

    func testBufferUnderflow() {
        var buffer = SMBBuffer()
        buffer.append(0x00)

        XCTAssertThrowsError(try buffer.readUInt32()) { error in
            XCTAssertTrue(error is SMBBufferError)
        }
    }

    // MARK: - AuthenticationContext Tests

    func testAuthenticationContextAnonymous() {
        let context = AuthenticationContext.anonymous()
        XCTAssertTrue(context.isAnonymous)
        XCTAssertFalse(context.isGuest)
        XCTAssertEqual(context.username, "")
    }

    func testAuthenticationContextGuest() {
        let context = AuthenticationContext.guest()
        XCTAssertTrue(context.isGuest)
        XCTAssertFalse(context.isAnonymous)
        XCTAssertEqual(context.username, "Guest")
    }

    func testAuthenticationContextCredentials() {
        let context = AuthenticationContext(username: "user", password: "pass", domain: "DOMAIN")
        XCTAssertEqual(context.username, "user")
        XCTAssertEqual(context.domain, "DOMAIN")
        XCTAssertEqual(context.getPasswordString(), "pass")
    }

    // MARK: - SMBConfig Tests

    func testDefaultConfig() {
        let config = SMBConfig.default()
        XCTAssertTrue(config.dialects.contains(.smb_3_1_1))
        XCTAssertTrue(config.signingEnabled)
        XCTAssertFalse(config.signingRequired)
    }

    func testConfigBuilder() throws {
        let config = try SMBConfigBuilder()
            .dialects(.smb_3_0, .smb_3_1_1)
            .signingRequired(true)
            .encryptData(true)
            .build()

        XCTAssertEqual(config.dialects.count, 2)
        XCTAssertTrue(config.signingRequired)
        XCTAssertTrue(config.encryptData)
    }

    func testConfigValidation() {
        let builder = SMBConfigBuilder()
            .dialects(.smb_2_0_2)
            .encryptData(true)

        // Encryption requires SMB 3.x
        XCTAssertThrowsError(try builder.build())
    }

    // MARK: - SMB2PacketHeader Tests

    func testPacketHeaderWriteRead() throws {
        var header = SMB2PacketHeader()
        header.command = .create
        header.messageId = 12345
        header.sessionId = 67890
        header.treeId = 100

        var buffer = SMBBuffer()
        header.write(to: &buffer)

        var readBuffer = SMBBuffer(data: buffer.bytes)
        let readHeader = try SMB2PacketHeader.read(from: &readBuffer)

        XCTAssertEqual(readHeader.command, .create)
        XCTAssertEqual(readHeader.messageId, 12345)
        XCTAssertEqual(readHeader.sessionId, 67890)
        XCTAssertEqual(readHeader.treeId, 100)
    }

    // MARK: - SMB2FileId Tests

    func testFileIdSentinel() {
        let sentinel = SMB2FileId.sentinel
        XCTAssertEqual(sentinel.persistentHandle.count, 8)
        XCTAssertEqual(sentinel.volatileHandle.count, 8)
        XCTAssertTrue(sentinel.persistentHandle.allSatisfy { $0 == 0xFF })
    }

    func testFileIdWriteRead() throws {
        let fileId = SMB2FileId(
            persistentHandle: Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            volatileHandle: Data([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18])
        )

        var buffer = SMBBuffer()
        fileId.write(to: &buffer)

        var readBuffer = SMBBuffer(data: buffer.bytes)
        let readFileId = try SMB2FileId.read(from: &readBuffer)

        XCTAssertEqual(fileId.persistentHandle, readFileId.persistentHandle)
        XCTAssertEqual(fileId.volatileHandle, readFileId.volatileHandle)
    }

    // MARK: - SMBClient Tests

    func testClientCreation() {
        let client = SMBClient()
        XCTAssertNotNil(client.config)
        XCTAssertTrue(client.config.dialects.contains(.smb_3_1_1))
    }

    func testClientWithCustomConfig() throws {
        let config = try SMBConfigBuilder()
            .dialects(.smb_3_0)
            .timeout(30)
            .build()

        let client = SMBClient(config: config)
        XCTAssertEqual(client.config.timeout, 30)
    }
}
