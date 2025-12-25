// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// [MS-SMB2].pdf 2.2.1.1 / 2.2.1.2 Message Command Code(s)
public enum SMB2MessageCommandCode: UInt16, Sendable, CaseIterable {
    case negotiate = 0x00
    case sessionSetup = 0x01
    case logoff = 0x02
    case treeConnect = 0x03
    case treeDisconnect = 0x04
    case create = 0x05
    case close = 0x06
    case flush = 0x07
    case read = 0x08
    case write = 0x09
    case lock = 0x0A
    case ioctl = 0x0B
    case cancel = 0x0C
    case echo = 0x0D
    case queryDirectory = 0x0E
    case changeNotify = 0x0F
    case queryInfo = 0x10
    case setInfo = 0x11
    case oplockBreak = 0x12
}

extension SMB2MessageCommandCode: CustomStringConvertible {
    public var description: String {
        switch self {
        case .negotiate: return "SMB2_NEGOTIATE"
        case .sessionSetup: return "SMB2_SESSION_SETUP"
        case .logoff: return "SMB2_LOGOFF"
        case .treeConnect: return "SMB2_TREE_CONNECT"
        case .treeDisconnect: return "SMB2_TREE_DISCONNECT"
        case .create: return "SMB2_CREATE"
        case .close: return "SMB2_CLOSE"
        case .flush: return "SMB2_FLUSH"
        case .read: return "SMB2_READ"
        case .write: return "SMB2_WRITE"
        case .lock: return "SMB2_LOCK"
        case .ioctl: return "SMB2_IOCTL"
        case .cancel: return "SMB2_CANCEL"
        case .echo: return "SMB2_ECHO"
        case .queryDirectory: return "SMB2_QUERY_DIRECTORY"
        case .changeNotify: return "SMB2_CHANGE_NOTIFY"
        case .queryInfo: return "SMB2_QUERY_INFO"
        case .setInfo: return "SMB2_SET_INFO"
        case .oplockBreak: return "SMB2_OPLOCK_BREAK"
        }
    }
}
