//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Dispatch
import Foundation
import NIOCore
import NIOFoundationCompat
import NIOPosix
import NIOSSH

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Bionic)
import Bionic
#endif

enum SSHServerError: Error {
    case invalidCommand
    case invalidDataType
    case invalidChannelType
    case alreadyListening
    case notListening
}

final class ExecHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = SSHChannelData
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData
    
    let delegate: ExecDelegate?
    
    init(delegate: ExecDelegate?, username: String?) {
        self.delegate = delegate
        self.username = username
    }
    
    var context: ExecCommandContext?
    var pipeChannel: Channel?
    var environment: [String: String] = [:]
    private var acceptedEnvironmentRequests = 0
    private var environmentSetup: Task<Void, Never>?
    /// Env requests queued in `environmentSetup`; a peer outrunning a slow setter is cut off.
    private var pendingEnvironmentRequests = 0
    static let maxPendingEnvironmentRequests = 32
    // Event-loop confined, like `context`: `exec` publishes its command context here.
    private var isClosed = false
    let username: String?

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        // A command published after this point is terminated by `exec` itself.
        isClosed = true
        let commandContext = self.context
        self.context = nil
        self.pipeChannel = nil
        Task {
            try await commandContext?.terminate()
        }
        context.fireChannelInactive()
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as SSHChannelRequestEvent.ExecRequest:
            if let delegate = delegate {
                self.exec(event, delegate: delegate, channel: context.channel)
            } else if event.wantReply {
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    context.channel.close(promise: nil)
                }
            }
        case let event as SSHChannelRequestEvent.EnvironmentRequest:
            // OpenSSH sshd's limits (d3bdf031d): at most 128 variables, names 2 KiB, values 16 KiB.
            let accepted = self.delegate != nil
                && self.acceptedEnvironmentRequests < 128
                && event.name.utf8.count <= 2048
                && event.value.utf8.count <= 16384
            let setter = accepted ? self.delegate : nil
            // A refusal nobody waits on needs no work at all.
            guard setter != nil || event.wantReply else { break }
            guard self.pendingEnvironmentRequests < Self.maxPendingEnvironmentRequests else {
                context.close(promise: nil)
                break
            }
            if setter != nil {
                self.acceptedEnvironmentRequests += 1
            }
            self.pendingEnvironmentRequests += 1
            // Every env request, refused ones included, replies through this chain: channel replies
            // carry no request id, so they must leave in arrival order. `exec` waits for the chain.
            let previous = self.environmentSetup
            let eventLoop = context.eventLoop
            let channel = context.channel
            self.environmentSetup = Task {
                await previous?.value
                var succeeded = false
                if let setter {
                    do {
                        try await setter.setEnvironmentValue(event.value, forKey: event.name)
                        succeeded = true
                    } catch {}
                }
                let replySucceeded = succeeded
                eventLoop.execute {
                    self.pendingEnvironmentRequests -= 1
                    guard event.wantReply, !self.isClosed else { return }
                    let reply: Any = replySucceeded ? ChannelSuccessEvent() : ChannelFailureEvent()
                    channel.triggerUserOutboundEvent(reply, promise: nil)
                }
            }
        case ChannelEvent.inputClosed:
            let commandContext = self.context
            Task {
                try await commandContext?.inputClosed()
            }
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        context.write(data, promise: promise)
    }
    
    private func exec(_ event: SSHChannelRequestEvent.ExecRequest, delegate: ExecDelegate, channel: Channel) {
        let successPromise = channel.eventLoop.makePromise(of: Int.self)
        let handler = ExecOutputHandler(username: username) { code in
            successPromise.succeed(code)
        } onFailure: { _ in
            if event.wantReply {
                channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    channel.close(promise: nil)
                }
            } else {
                channel.close(promise: nil)
            }
        }
        
        let (ours, theirs) = GlueHandler.matchedPair()
        
        // Ok, great, we've sorted stdout and stdin. For stderr we need a different strategy: we just park a thread for this.
        let stderrHandle = handler.stderrPipe.fileHandleForReading
        stderrHandle.readabilityHandler = { stderrHandle in
            do {
                guard let data = try stderrHandle.readToEnd() else {
                    stderrHandle.readabilityHandler = nil
                    return
                }
                var buffer = channel.allocator.buffer(capacity: data.count)
                buffer.writeContiguousBytes(data)
                channel.write(SSHChannelData(type: .stdErr, data: .byteBuffer(buffer)), promise: nil)
            } catch {
                channel.close(promise: nil)
            }
        }
        
        channel.pipeline.addHandler(ours).flatMap {
            NIOPipeBootstrap(group: channel.eventLoop)
                .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
                .channelInitializer { pipeChannel in
                    pipeChannel.pipeline.addHandlers(SSHInboundChannelDataWrapper(), theirs)
                }.withPipes(
                    inputDescriptor: dup(handler.stdoutPipe.fileHandleForReading.fileDescriptor),
                    outputDescriptor: dup(handler.stdinPipe.fileHandleForWriting.fileDescriptor)
                )
        }.flatMap { pipeChannel -> EventLoopFuture<Channel> in
            self.pipeChannel = pipeChannel
            let environmentSetup = self.environmentSetup
            let eventLoop = channel.eventLoop
            let start = channel.eventLoop.makePromise(of: Void.self)
            start.completeWithTask {
                await environmentSetup?.value
                // The channel may have closed while env setters ran: start nothing that can't be torn down.
                // Wherever no command will report an exit code, fail `successPromise` so it can't leak.
                guard try await eventLoop.submit({ !self.isClosed }).get() else {
                    try? await pipeChannel.close(mode: .all)
                    successPromise.fail(ChannelError.ioOnClosedChannel)
                    throw ChannelError.ioOnClosedChannel
                }
                let commandContext: ExecCommandContext
                do {
                    commandContext = try await delegate.start(
                        command: event.command,
                        outputHandler: handler
                    )
                } catch {
                    try? await pipeChannel.close(mode: .all)
                    successPromise.fail(error)
                    throw error
                }
                // Publish on the loop, where channelInactive runs, so exactly one side terminates it.
                let closedDuringStart = try await eventLoop.submit { () -> Bool in
                    guard !self.isClosed else { return true }
                    self.context = commandContext
                    return false
                }.get()
                if closedDuringStart {
                    try? await commandContext.terminate()
                    try? await pipeChannel.close(mode: .all)
                    successPromise.fail(ChannelError.ioOnClosedChannel)
                }
            }
            
            return start.futureResult.flatMap {
                if event.wantReply {
                    return channel.triggerUserOutboundEvent(ChannelSuccessEvent()).map {
                        pipeChannel
                    }
                } else {
                    return channel.eventLoop.makeSucceededFuture(pipeChannel)
                }
            }
        }.flatMap { pipeChannel in
            successPromise.futureResult.flatMap { code in
                pipeChannel.close(mode: .all).map { code }
            }
        }.flatMap { code in
            channel.triggerUserOutboundEvent(SSHChannelRequestEvent.ExitStatus(exitStatus: code))
        }.whenComplete { result in
            switch result {
            case .success:
                channel.close(promise: nil)
            case .failure:
                if event.wantReply {
                    channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                        channel.close(promise: nil)
                    }
                } else {
                    channel.close(promise: nil)
                }
            }
        }
    }
}
