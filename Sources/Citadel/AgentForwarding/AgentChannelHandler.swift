//===----------------------------------------------------------------------===//
//
// This source file is part of the Citadel open source project
//
// Copyright (c) 2025 Citadel contributors
// Licensed under Apache License v2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOSSH
import Logging

/// A channel handler that processes SSH agent protocol messages.
///
/// This handler is added to agent channels (auth-agent@openssh.com) and
/// handles the SSH agent protocol, delegating actual operations to an
/// `SSHAgentDelegate`.
public final class AgentChannelHandler: ChannelDuplexHandler {
    public typealias InboundIn = SSHChannelData
    public typealias InboundOut = Never
    public typealias OutboundIn = SSHChannelData
    public typealias OutboundOut = SSHChannelData

    private let delegate: SSHAgentDelegate
    private var buffer: ByteBuffer
    private let logger: Logger

    // Event-loop confined; see `enqueue`.
    private var pendingRequests = CircularBuffer<SSHAgentMessage>()
    private var isHandlingRequest = false
    private var currentRequest: Task<Void, Never>?
    /// Set on close: queued requests are dropped so no further signing or prompts happen.
    private var isClosed = false
    /// Bounds requests queued behind a slow one (a sign awaiting approval).
    static let maxPendingRequests = 32

    /// Creates a new agent channel handler.
    ///
    /// - Parameters:
    ///   - delegate: The delegate to handle agent operations.
    ///   - allocator: The byte buffer allocator to use.
    public init(delegate: SSHAgentDelegate, allocator: ByteBufferAllocator = ByteBufferAllocator()) {
        self.delegate = delegate
        self.buffer = allocator.buffer(capacity: 4096)
        self.logger = Logger(label: "nl.orlandos.citadel.agent")
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = self.unwrapInboundIn(data)

        // Only handle channel data (not extended data)
        guard channelData.type == .channel else {
            return
        }

        // Extract buffer from IOData
        guard case .byteBuffer(var incoming) = channelData.data else {
            return
        }

        // Accumulate data in buffer
        buffer.writeBuffer(&incoming)

        // Process complete messages
        processMessages(context: context)
    }

    public func channelInactive(context: ChannelHandlerContext) {
        logger.debug("Agent channel closed")
        stopHandlingRequests()
        context.fireChannelInactive()
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        stopHandlingRequests()
    }

    private func stopHandlingRequests() {
        isClosed = true
        pendingRequests.removeAll()
        currentRequest?.cancel()
        currentRequest = nil
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Agent channel error: \(error)")
        context.close(promise: nil)
    }

    // MARK: - Private

    /// Matches OpenSSH's AGENT_MAX_LEN, so a peer's length field can't make us buffer up to 4 GiB.
    static let maxMessageLength: UInt32 = 256 * 1024

    private func processMessages(context: ChannelHandlerContext) {
        while true {
            if let length = buffer.getInteger(at: buffer.readerIndex, as: UInt32.self),
               length > Self.maxMessageLength {
                logger.error("Agent message length \(length) exceeds limit, closing channel")
                buffer.clear()
                context.close(promise: nil)
                return
            }
            guard let message = tryReadMessage() else { break }
            enqueue(message, context: context)
        }
        buffer.discardReadBytes()
    }

    private func tryReadMessage() -> SSHAgentMessage? {
        // Need at least 4 bytes for length
        guard buffer.readableBytes >= 4 else {
            return nil
        }

        // Peek at length without consuming
        let readerIndex = buffer.readerIndex
        guard let length = buffer.getInteger(at: readerIndex, as: UInt32.self) else {
            return nil
        }

        // Check if we have the full message
        let totalLength = 4 + Int(length)
        guard buffer.readableBytes >= totalLength else {
            return nil
        }

        // Consume length
        buffer.moveReaderIndex(forwardBy: 4)

        // Read and parse message
        guard var messageBuffer = buffer.readSlice(length: Int(length)) else {
            return nil
        }

        do {
            return try SSHAgentMessageParser.parse(&messageBuffer)
        } catch {
            logger.error("Failed to parse agent message: \(error)")
            return .failure
        }
    }

    /// Queues a request; replies go out strictly in order, one request at a time, since the
    /// agent protocol has no request ids.
    private func enqueue(_ message: SSHAgentMessage, context: ChannelHandlerContext) {
        guard !isClosed else { return }
        guard pendingRequests.count < Self.maxPendingRequests else {
            logger.error("Too many queued agent requests, closing channel")
            context.close(promise: nil)
            return
        }
        pendingRequests.append(message)
        startNextRequestIfIdle(context: context)
    }

    private func startNextRequestIfIdle(context: ChannelHandlerContext) {
        guard !isClosed, !isHandlingRequest, let message = pendingRequests.popFirst() else {
            return
        }
        isHandlingRequest = true
        let eventLoop = context.eventLoop
        currentRequest = Task {
            let response = await self.response(to: message)
            eventLoop.execute {
                guard !self.isClosed else { return }
                let data = SSHChannelData(type: .channel, data: .byteBuffer(response))
                context.writeAndFlush(self.wrapOutboundOut(data), promise: nil)
                self.isHandlingRequest = false
                self.currentRequest = nil
                self.startNextRequestIfIdle(context: context)
            }
        }
    }

    private func response(to message: SSHAgentMessage) async -> ByteBuffer {
        switch message {
        case .requestIdentities:
            do {
                let identities = try await delegate.listIdentities()
                return SSHAgentMessageSerializer.serialize(.identitiesAnswer(identities))
            } catch {
                logger.error("Failed to list identities: \(error)")
                return SSHAgentMessageSerializer.serialize(.failure)
            }

        case .signRequest(let request):
            do {
                if let signature = try await delegate.sign(
                    publicKeyBlob: request.publicKeyBlob,
                    data: request.data,
                    flags: request.flags
                ) {
                    return SSHAgentMessageSerializer.serialize(.signResponse(signature))
                }
                // Signing denied
                return SSHAgentMessageSerializer.serialize(.failure)
            } catch {
                logger.error("Failed to sign: \(error)")
                return SSHAgentMessageSerializer.serialize(.failure)
            }

        case .extensionRequest(let request):
            // No extensions are supported.
            logger.debug("Received agent extension request: \(request.extensionName)")
            return SSHAgentMessageSerializer.serialize(.extensionFailure)

        case .failure, .success, .identitiesAnswer, .signResponse, .extensionFailure, .unknown:
            // Add/remove/lock, malformed and unknown requests: OpenSSH's agent answers
            // SSH_AGENT_FAILURE, and a client waiting on a reply must not hang.
            logger.debug("Refusing unsupported agent request: \(message)")
            return SSHAgentMessageSerializer.serialize(.failure)
        }
    }
}
