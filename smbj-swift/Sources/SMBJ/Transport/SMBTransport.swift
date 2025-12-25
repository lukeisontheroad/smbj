// SMBJ - Swift SMB Client Library
// Copyright (C) 2024 - SMBJ Contributors
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Network
import Logging

/// Protocol for SMB transport implementations
public protocol SMBTransport: Sendable {
    /// Connect to the server
    func connect() async throws

    /// Disconnect from the server
    func disconnect() async

    /// Send a packet and wait for response
    func sendAndReceive(_ data: Data, messageId: UInt64) async throws -> Data

    /// Send a packet without waiting for response
    func send(_ data: Data) async throws

    /// Check if transport is connected
    var isConnected: Bool { get }
}

/// Direct TCP transport implementation using Network.framework
public actor DirectTCPTransport: SMBTransport {
    /// Default SMB port (445)
    public static let smbPort: UInt16 = 445

    /// NetBIOS TCP length header size
    private static let netbiosTcpHeaderSize = 4

    private let host: String
    private let port: UInt16
    private var connection: NWConnection?
    private var pendingResponses: [UInt64: CheckedContinuation<Data, Error>] = [:]
    private let logger: Logger
    private var connectionState: NWConnection.State = .setup
    private var receiveTask: Task<Void, Never>?

    public init(host: String, port: UInt16 = DirectTCPTransport.smbPort) {
        self.host = host
        self.port = port
        self.logger = Logger(label: "com.smbj.transport")
    }

    public var isConnected: Bool {
        return connectionState == .ready
    }

    public func connect() async throws {
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!)

        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true

        let connection = NWConnection(to: endpoint, using: parameters)
        self.connection = connection

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { [weak self] state in
                Task { @MainActor in
                    await self?.handleStateUpdate(state, continuation: continuation)
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
        }

        // Start receive loop
        receiveTask = Task { [weak self] in
            await self?.receiveLoop()
        }
    }

    private func handleStateUpdate(_ state: NWConnection.State, continuation: CheckedContinuation<Void, Error>?) {
        connectionState = state
        switch state {
        case .ready:
            logger.info("Connected to \(host):\(port)")
            continuation?.resume()
        case .failed(let error):
            logger.error("Connection failed: \(error)")
            continuation?.resume(throwing: SMBError.connectionFailed(reason: error.localizedDescription))
        case .cancelled:
            logger.info("Connection cancelled")
            continuation?.resume(throwing: SMBError.connectionFailed(reason: "Connection cancelled"))
        default:
            break
        }
    }

    public func disconnect() async {
        receiveTask?.cancel()
        receiveTask = nil
        connection?.cancel()
        connection = nil
        connectionState = .cancelled

        // Cancel all pending responses
        for (_, continuation) in pendingResponses {
            continuation.resume(throwing: SMBError.connectionFailed(reason: "Disconnected"))
        }
        pendingResponses.removeAll()
    }

    public func send(_ data: Data) async throws {
        guard let connection = connection, isConnected else {
            throw SMBError.connectionFailed(reason: "Not connected")
        }

        // Wrap with NetBIOS TCP header
        let packet = wrapWithNetBiosHeader(data)

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: packet, completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: SMBError.transportError(underlying: error))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    public func sendAndReceive(_ data: Data, messageId: UInt64) async throws -> Data {
        try await send(data)

        return try await withCheckedThrowingContinuation { continuation in
            pendingResponses[messageId] = continuation
        }
    }

    private func receiveLoop() async {
        while !Task.isCancelled {
            do {
                guard let data = try await receivePacket() else {
                    break
                }
                await processReceivedPacket(data)
            } catch {
                logger.error("Receive error: \(error)")
                break
            }
        }
    }

    private func receivePacket() async throws -> Data? {
        guard let connection = connection else { return nil }

        // Read NetBIOS header first (4 bytes)
        let headerData = try await readExact(connection: connection, length: Self.netbiosTcpHeaderSize)

        // Parse length from header (big-endian, 3 bytes after first byte)
        let length = Int(headerData[1]) << 16 | Int(headerData[2]) << 8 | Int(headerData[3])

        // Read the actual SMB packet
        let packetData = try await readExact(connection: connection, length: length)

        return packetData
    }

    private func readExact(connection: NWConnection, length: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: length, maximumLength: length) { data, _, isComplete, error in
                if let error = error {
                    continuation.resume(throwing: SMBError.transportError(underlying: error))
                } else if let data = data {
                    continuation.resume(returning: data)
                } else if isComplete {
                    continuation.resume(throwing: SMBError.connectionFailed(reason: "Connection closed"))
                } else {
                    continuation.resume(throwing: SMBError.transportError(underlying: nil))
                }
            }
        }
    }

    private func processReceivedPacket(_ data: Data) async {
        // Parse header to get message ID
        var buffer = SMBBuffer(data: data)

        do {
            let header = try SMB2PacketHeader.read(from: &buffer)
            let messageId = header.messageId

            if let continuation = pendingResponses.removeValue(forKey: messageId) {
                continuation.resume(returning: data)
            } else {
                logger.warning("Received response for unknown message ID: \(messageId)")
            }
        } catch {
            logger.error("Failed to parse response header: \(error)")
        }
    }

    /// Wrap SMB packet with NetBIOS TCP transport header
    private func wrapWithNetBiosHeader(_ data: Data) -> Data {
        var packet = Data(capacity: Self.netbiosTcpHeaderSize + data.count)

        // NetBIOS Session Message type (0x00)
        packet.append(0x00)

        // Length (3 bytes, big-endian)
        let length = data.count
        packet.append(UInt8((length >> 16) & 0xFF))
        packet.append(UInt8((length >> 8) & 0xFF))
        packet.append(UInt8(length & 0xFF))

        // SMB packet
        packet.append(data)

        return packet
    }
}
