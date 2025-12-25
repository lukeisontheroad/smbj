// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// [MS-ERREF].pdf 2.3.1 NTSTATUS values
/// Subset of the possible values which are useful for SMB2 communication
public enum NtStatus: UInt32, Sendable, CaseIterable {
    case statusSuccess = 0x00000000
    case statusUnsuccessful = 0x00000001
    case statusTimeout = 0x00000102
    case statusPending = 0x00000103
    case statusNotifyCleanup = 0x0000010B
    case statusNotifyEnumDir = 0x0000010C
    case statusBufferOverflow = 0x80000005
    case statusNoMoreFiles = 0x80000006
    case statusStoppedOnSymlink = 0x8000002D
    case statusNotImplemented = 0xC0000002
    case statusInvalidInfoClass = 0xC0000003
    case statusInfoLengthMismatch = 0xC0000004
    case statusNoSuchFile = 0xC000000F
    case statusInvalidParameter = 0xC000000D
    case statusEndOfFile = 0xC0000011
    case statusMoreProcessingRequired = 0xC0000016
    case statusAccessDenied = 0xC0000022
    case statusBufferTooSmall = 0xC0000023
    case statusObjectNameInvalid = 0xC0000033
    case statusObjectNameNotFound = 0xC0000034
    case statusObjectNameCollision = 0xC0000035
    case statusObjectPathNotFound = 0xC000003A
    case statusSharingViolation = 0xC0000043
    case statusFileLockConflict = 0xC0000054
    case statusLockNotGranted = 0xC0000055
    case statusDeletePending = 0xC0000056
    case statusPrivilegeNotHeld = 0xC0000061
    case statusLogonFailure = 0xC000006D
    case statusPasswordExpired = 0xC0000071
    case statusAccountDisabled = 0xC0000072
    case statusRangeNotLocked = 0xC000007E
    case statusDiskFull = 0xC000007F
    case statusInsufficientResources = 0xC000009A
    case statusPipeNotAvailable = 0xC00000AC
    case statusInvalidPipeState = 0xC00000AD
    case statusPipeBusy = 0xC00000AE
    case statusIoTimeout = 0xC00000B5
    case statusFileIsADirectory = 0xC00000BA
    case statusNotSupported = 0xC00000BB
    case statusBadNetworkPath = 0xC00000BE
    case statusNetworkNameDeleted = 0xC00000C9
    case statusBadNetworkName = 0xC00000CC
    case statusRequestNotAccepted = 0xC00000D0
    case statusNetWriteFault = 0xC00000D2
    case statusNotSameDevice = 0xC00000D4
    case statusFileRenamed = 0xC00000D5
    case statusOplockNotGranted = 0xC00000E2
    case statusInternalError = 0xC00000E5
    case statusUnexpectedIoError = 0xC00000E9
    case statusDirectoryNotEmpty = 0xC0000101
    case statusNotADirectory = 0xC0000103
    case statusNameTooLong = 0xC0000106
    case statusFilesOpen = 0xC0000107
    case statusConnectionInUse = 0xC0000108
    case statusTooManyOpenedFiles = 0xC000011F
    case statusCancelled = 0xC0000120
    case statusCannotDelete = 0xC0000121
    case statusFileDeleted = 0xC0000123
    case statusFileClosed = 0xC0000128
    case statusOpenFailed = 0xC0000136
    case statusLogonTypeNotGranted = 0xC000015B
    case statusTooManySids = 0xC000017E
    case statusUserSessionDeleted = 0xC0000203
    case statusInsuffServerResources = 0xC0000205
    case statusConnectionDisconnected = 0xC000020C
    case statusConnectionReset = 0xC000020D
    case statusNotFound = 0xC0000225
    case statusRetry = 0xC000022D
    case statusPathNotCovered = 0xC0000257
    case statusDfsUnavailable = 0xC000026D
    case statusVolumeDismounted = 0xC000026E
    case statusIoReparseTagNotHandled = 0xC0000279
    case statusFileEncrypted = 0xC0000293
    case statusNetworkSessionExpired = 0xC000035C
    case statusOther = 0xFFFFFFFF

    public init(rawValue: UInt32) {
        self = NtStatus.allCases.first { $0.rawValue == rawValue } ?? .statusOther
    }

    /// Check whether the 'Sev' bits are set to 0x0 (success)
    public var isSuccess: Bool {
        return Self.isSuccess(statusCode: rawValue)
    }

    /// Check whether the 'Sev' bits are set to 0x0 (success)
    public static func isSuccess(statusCode: UInt32) -> Bool {
        return (statusCode >> 30) == 0
    }

    /// Check whether the 'Sev' bits are set to 0x01 (informational)
    public var isInformational: Bool {
        return (rawValue >> 30) == 0x01
    }

    /// Check whether the 'Sev' bits are set to 0x02 (warning)
    public var isWarning: Bool {
        return (rawValue >> 30) == 0x02
    }

    /// Check whether the 'Sev' bits are set to 0x03 (error)
    public var isError: Bool {
        return Self.isError(statusCode: rawValue)
    }

    /// Check whether the 'Sev' bits are set to 0x03 (error)
    public static func isError(statusCode: UInt32) -> Bool {
        return (statusCode >> 30) == 0x03
    }
}

extension NtStatus: CustomStringConvertible {
    public var description: String {
        return "NtStatus.\(self)(0x\(String(rawValue, radix: 16, uppercase: true)))"
    }
}
