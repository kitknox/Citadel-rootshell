import Foundation
import Logging
import NIOCore
@preconcurrency import NIOSSH
import NIOConcurrencyHelpers
#if canImport(NIOTransportServices)
import NIOTransportServices
#endif

/// Represents an error that occurred while processing TTY standard error output
public struct TTYSTDError: Error {
    /// The error message as a raw byte buffer
    public let message: ByteBuffer
}

/// A pair of streams representing the stdout and stderr output of an executed command
public struct ExecCommandStream {
    /// An async stream of bytes representing the standard output
    public let stdout: AsyncThrowingStream<ByteBuffer, Error>
    /// An async stream of bytes representing the standard error
    public let stderr: AsyncThrowingStream<ByteBuffer, Error>
    
    struct Continuation {
        let stdout: AsyncThrowingStream<ByteBuffer, Error>.Continuation
        let stderr: AsyncThrowingStream<ByteBuffer, Error>.Continuation
        
        func onOutput(_ output: ExecCommandHandler.Output) {
            switch output {
            case .stdout(let buffer):
                stdout.yield(buffer)
            case .stderr(let buffer):
                stderr.yield(buffer)
            case .eof(let error):
                stdout.finish(throwing: error)
                stderr.finish(throwing: error)
            case .channelSuccess:
                ()
            case .exit(0):
                stdout.finish()
                stderr.finish()
            case .exit(let status):
                stdout.finish(throwing: SSHClient.CommandFailed(exitCode: status))
                stderr.finish(throwing: SSHClient.CommandFailed(exitCode: status))
            }
        }
    }
}

/// Represents the output from an executed command, either stdout or stderr data
public enum ExecCommandOutput: Sendable {
    /// Standard output data as a byte buffer
    case stdout(ByteBuffer)
    /// Standard error data as a byte buffer
    case stderr(ByteBuffer)
    /// Shell exit status code (sent when shell exits normally)
    case exitStatus(Int)
}

/// An async sequence that provides TTY output data
@available(macOS 15.0, *)
public struct TTYOutput: AsyncSequence {
    internal let sequence: AsyncThrowingStream<ExecCommandOutput, Error>
    public typealias Element = ExecCommandOutput

    public struct AsyncIterator: AsyncIteratorProtocol {
        public typealias Element = ExecCommandOutput
        var iterator: AsyncThrowingStream<ExecCommandOutput, Error>.AsyncIterator

        public mutating func next() async throws -> ExecCommandOutput? {
            try await iterator.next()
        }
    }

    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(iterator: sequence.makeAsyncIterator())
    }
}

/// Allows writing data to a TTY's standard input and controlling terminal properties
public struct TTYStdinWriter: Sendable {
    internal let channel: Channel

    /// The serial NIO `EventLoop` that owns the underlying SSH child channel.
    /// Callers can dispatch onto this loop to serialize state transitions with
    /// `withPTYDirect` / `withPTYExecDirect` `onOutput` deliveries.
    public var eventLoop: EventLoop {
        channel.eventLoop
    }

    /// Write raw bytes to the TTY's standard input
    /// - Parameter buffer: The bytes to write
    public func write(_ buffer: ByteBuffer) async throws {
        try await channel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(buffer)))
    }

    /// Write raw bytes directly to the TTY's standard input without allocating an
    /// `EventLoopPromise` or waiting for network-stack send completion.
    ///
    /// Sequential calls from the same thread or actor preserve strict FIFO order on
    /// the channel's serial event loop while eliminating Swift Concurrency hops and
    /// head-of-line promise blocking between consecutive keystrokes.
    public func writeImmediate(_ buffer: ByteBuffer) {
        let data = SSHChannelData(type: .channel, data: .byteBuffer(buffer))
        if channel.eventLoop.inEventLoop {
            channel.writeAndFlush(data, promise: nil)
        } else {
            #if canImport(NIOTransportServices)
            if let qosLoop = channel.eventLoop as? QoSEventLoop {
                qosLoop.execute(qos: .userInteractive) { [channel] in
                    channel.writeAndFlush(data, promise: nil)
                }
                return
            }
            #endif
            channel.writeAndFlush(data, promise: nil)
        }
    }

    public func changeSize(cols: Int, rows: Int, pixelWidth:Int, pixelHeight:Int) async throws {
        try await channel.triggerUserOutboundEvent(
            SSHChannelRequestEvent.WindowChangeRequest(
                terminalCharacterWidth: cols,
                terminalRowHeight: rows,
                terminalPixelWidth: pixelWidth,
                terminalPixelHeight: pixelHeight
            )
        )
    }

    /// Close the underlying SSH child channel without waiting for remote close acknowledgement.
    public func close() {
        channel.close(promise: nil)
    }
}

final class ExecCommandHandler: ChannelDuplexHandler, @unchecked Sendable {
    enum Output {
        case channelSuccess
        case stdout(ByteBuffer)
        case stderr(ByteBuffer)
        case eof(Error?)
        case exit(Int)
    }
    
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    let logger: Logger
    let onOutput: @Sendable (Channel, Output) -> Void

    // Confined to the channel's single NIO EventLoop thread.
    // Coalesces multiple SSH_MSG_CHANNEL_DATA packets arriving in a single TCP read
    // cycle into one downstream delivery, while single-packet echoes pass through
    // with zero extra copy on the synchronous channelReadComplete call.
    private var pendingStdout: ByteBuffer?
    private var pendingStderr: ByteBuffer?

    init(
        logger: Logger,
        onOutput: @escaping @Sendable (Channel, Output) -> Void
    ) {
        self.logger = logger
        self.onOutput = onOutput
    }

    private func flushPending(on channel: Channel) {
        if let stdout = pendingStdout {
            pendingStdout = nil
            onOutput(channel, .stdout(stdout))
        }
        if let stderr = pendingStderr {
            pendingStderr = nil
            onOutput(channel, .stderr(stderr))
        }
    }
    
    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            self.logger.debug("Failed to set allowRemoteHalfClosure: \(error)")
            context.fireErrorCaught(error)
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is NIOSSH.ChannelSuccessEvent:
            flushPending(on: context.channel)
            onOutput(context.channel, .channelSuccess)
        case is NIOSSH.ChannelFailureEvent:
            flushPending(on: context.channel)
            onOutput(context.channel, .eof(CitadelError.channelFailure))
        case let status as SSHChannelRequestEvent.ExitStatus:
            flushPending(on: context.channel)
            onOutput(context.channel, .exit(status.exitStatus))
        default:
            self.logger.debug("Received unknown channel event in command handler: \(event)")
            context.fireUserInboundEventTriggered(event)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        flushPending(on: context.channel)
        onOutput(context.channel, .eof(nil))
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .byteBuffer(let buffer) = data.data else {
            flushPending(on: context.channel)
            logger.error("Unable to process channelData for executed command. Data was not a ByteBuffer")
            return onOutput(context.channel, .eof(SSHExecError.invalidData))
        }
        
        switch data.type {
        case .channel:
            if let stderr = pendingStderr {
                pendingStderr = nil
                onOutput(context.channel, .stderr(stderr))
            }
            if pendingStdout != nil {
                pendingStdout!.writeImmutableBuffer(buffer)
            } else {
                pendingStdout = buffer
            }
        case .stdErr:
            if let stdout = pendingStdout {
                pendingStdout = nil
                onOutput(context.channel, .stdout(stdout))
            }
            if pendingStderr != nil {
                pendingStderr!.writeImmutableBuffer(buffer)
            } else {
                pendingStderr = buffer
            }
        default:
            self.logger.debug("Received channel data not known by Citadel")
            // We don't know this std channel
            ()
        }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        flushPending(on: context.channel)
        context.fireChannelReadComplete()
    }
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        flushPending(on: context.channel)
        onOutput(context.channel, .eof(error))
    }
}

extension SSHClient {
    /// Error thrown when a command exits with a non-zero status code
    public struct CommandFailed: Error {
        /// The exit code returned by the command
        public let exitCode: Int
    }

    /// Executes a command on the remote server and returns its output as a single buffer
    /// - Parameters:
    ///   - command: The command to execute on the remote server
    ///   - maxResponseSize: Maximum allowed size of the combined output in bytes. Defaults to Int.max
    ///   - mergeStreams: Whether to include stderr output in the result. Defaults to false
    ///   - inShell: Whether to execute the command within a shell context. Defaults to false
    /// - Returns: A ByteBuffer containing the command's output
    /// - Throws: CitadelError.commandOutputTooLarge if output exceeds maxResponseSize
    ///          CommandFailed if the command exits with non-zero status
    /// 
    /// ## Example
    /// ```swift
    /// // Simple command execution
    /// let output = try await client.executeCommand("ls -la")
    /// print(String(buffer: output))
    /// 
    /// // Execute with merged stderr and limited output size
    /// let result = try await client.executeCommand(
    ///     "find /",
    ///     maxResponseSize: 1024 * 1024, // 1MB max
    ///     mergeStreams: true
    /// )
    /// ```
    public func executeCommand(
        _ command: String,
        maxResponseSize: Int = .max,
        mergeStreams: Bool = false,
        inShell: Bool = false
    ) async throws -> ByteBuffer {
        var result = ByteBuffer()
        let stream = try await executeCommandStream(command, inShell: inShell)

        for try await chunk in stream {
            switch chunk {
            case .stderr(let chunk):
                guard mergeStreams else {
                    logger.debug("Error data received, but ignored because `mergeStreams` is disabled")
                    continue
                }

                fallthrough
            case .stdout(let chunk):
                let newResponseSize = chunk.readableBytes + result.readableBytes

                if newResponseSize > maxResponseSize {
                    throw CitadelError.commandOutputTooLarge
                }

                result.writeImmutableBuffer(chunk)
            case .exitStatus:
                // Exit status is informational for executeCommand - just continue
                break
            }
        }

        return result
    }

    /// Executes a command on the remote server and returns a stream of its output
    /// - Parameters:
    ///   - command: The command to execute on the remote server
    ///   - environment: Array of environment variables to set for the command. This requires `PermitUserEnvironment` to be enabled in your OpenSSH server's configuration.
    ///   - inShell: Whether to execute the command within a shell context. Defaults to false
    /// - Returns: An async stream that yields command output as it becomes available
    /// - Throws: CommandFailed if the command exits with non-zero status
    /// 
    /// ## Example
    /// ```swift
    /// // Stream command output as it arrives
    /// let stream = try await client.executeCommandStream("tail -f /var/log/system.log")
    /// for try await output in stream {
    ///     switch output {
    ///     case .stdout(let buffer):
    ///         print("stdout:", String(buffer: buffer))
    ///     case .stderr(let buffer):
    ///         print("stderr:", String(buffer: buffer))
    ///     }
    /// }
    /// ```
    public func executeCommandStream(
        _ command: String,
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        inShell: Bool = false
    ) async throws -> AsyncThrowingStream<ExecCommandOutput, Error> {
        try await _executeCommandStream(
            environment: environment,
            mode: inShell ? .tty(command: command) : .command(command)
        ).output
    }

    /// Execute a command with bidirectional I/O access.
    /// Returns the NIO channel (for writing to stdin) and a stream for reading stdout/stderr.
    public func executeCommandBidirectional(
        _ command: String,
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = []
    ) async throws -> (channel: Channel, output: AsyncThrowingStream<ExecCommandOutput, Error>) {
        try await _executeCommandStream(environment: environment, mode: .command(command))
    }

    enum CommandMode {
        case pty(SSHChannelRequestEvent.PseudoTerminalRequest)
        case ptyExec(SSHChannelRequestEvent.PseudoTerminalRequest, command: String)
        case tty(command: String?)
        case command(String)
    }

    /// Queues all initial channel setup requests (env, pty-req, auth-agent-req, shell/exec)
    /// directly onto the child channel while it is initializing. `SSHChildChannel` buffers
    /// them and flushes the entire batch in one TCP segment the instant
    /// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` arrives on the event loop, avoiding 6-7
    /// sequential event-loop hops and separate TCP packets.
    internal func openCommandChannel(
        environment: [SSHChannelRequestEvent.EnvironmentRequest],
        mode: CommandMode,
        agentDelegate: SSHAgentDelegate?,
        handler: ExecCommandHandler,
        timeout: TimeAmount = .seconds(15)
    ) async throws -> Channel {
        try Task.checkCancellation()

        // Capture the session's inbound handler and event loop up front so an
        // automatic reconnect replacing `self.session` mid-open cannot cause
        // rollback or close cleanup to remove a token from the new session.
        let currentSession = session
        let inboundHandler = currentSession.inboundChannelHandler
        let sessionEventLoop = currentSession.channel.eventLoop

        let agentToken: UInt64?
        if let agentDelegate {
            agentToken = inboundHandler.registerAgentHandler { [allocator = currentSession.channel.allocator] agentChannel in
                let agentHandler = AgentChannelHandler(delegate: agentDelegate, allocator: allocator)
                return agentChannel.pipeline.addHandler(agentHandler)
            }
        } else {
            agentToken = nil
        }

        final class ChannelOpenState: @unchecked Sendable {
            // Event-loop confined on `sessionEventLoop`.
            var child: Channel?
            var createPromise: EventLoopPromise<Channel>?
            var readyPromise: EventLoopPromise<Channel>?
            var setupFutures: [EventLoopFuture<Void>] = []
            var aborted = false
            var abortError: Error?

            func abort(error: Error) {
                guard !aborted else { return }
                aborted = true
                abortError = error
                // Fail the caller's promises FIRST so the caller receives the
                // intended error (channelCreationFailed or CancellationError)
                // rather than ChannelError.eof from the synchronous pre-activation close.
                readyPromise?.fail(error)
                createPromise?.fail(error)
                child?.close(mode: .all, promise: nil)
            }
        }

        let openState = ChannelOpenState()

        do {
            let channel = try await withTaskCancellationHandler {
                try await sessionEventLoop.flatSubmit { [sessionEventLoop, sshHandler = currentSession.sshHandler] in
                    let createChannel = sessionEventLoop.makePromise(of: Channel.self)
                    let readyPromise = sessionEventLoop.makePromise(of: Channel.self)
                    openState.createPromise = createChannel
                    openState.readyPromise = readyPromise

                    if openState.aborted {
                        let error = openState.abortError ?? CancellationError()
                        readyPromise.fail(error)
                        createChannel.fail(error)
                        return readyPromise.futureResult
                    }

                    sshHandler.value.createChannel(createChannel) { channel, _ in
                        openState.child = channel
                        if openState.aborted {
                            channel.close(mode: .all, promise: nil)
                            return channel.eventLoop.makeFailedFuture(openState.abortError ?? CancellationError())
                        }
                        return channel.pipeline.addHandlers(handler).map {
                            guard !openState.aborted else {
                                channel.close(mode: .all, promise: nil)
                                return
                            }

                            func queueRequest(_ event: Any) {
                                let reqPromise = channel.eventLoop.makePromise(of: Void.self)
                                openState.setupFutures.append(reqPromise.futureResult)
                                channel.triggerUserOutboundEvent(event, promise: reqPromise)
                            }

                            for env in environment {
                                queueRequest(env)
                            }

                            switch mode {
                            case .pty(let request):
                                queueRequest(request)
                                if agentDelegate != nil {
                                    queueRequest(SSHChannelRequestEvent.AuthAgentRequest(wantReply: false))
                                }
                                queueRequest(SSHChannelRequestEvent.ShellRequest(wantReply: true))
                            case .tty:
                                queueRequest(SSHChannelRequestEvent.ShellRequest(wantReply: true))
                            case .ptyExec(let request, let command):
                                queueRequest(request)
                                if agentDelegate != nil {
                                    queueRequest(SSHChannelRequestEvent.AuthAgentRequest(wantReply: false))
                                }
                                queueRequest(SSHChannelRequestEvent.ExecRequest(command: command, wantReply: true))
                            case .command(let command):
                                queueRequest(SSHChannelRequestEvent.ExecRequest(command: command, wantReply: true))
                            }
                        }
                    }

                    // Requests remain batched in a single flush on CHANNEL_OPEN_CONFIRMATION,
                    // while collecting their write promises so any local write failure fails
                    // channel setup instead of returning a channel whose command never sent.
                    createChannel.futureResult.whenComplete { result in
                        switch result {
                        case .success(let channel):
                            let setupFutures = openState.setupFutures
                            EventLoopFuture.andAllSucceed(setupFutures, on: sessionEventLoop).whenComplete { writeResult in
                                switch writeResult {
                                case .success:
                                    readyPromise.succeed(channel)
                                case .failure(let error):
                                    readyPromise.fail(error)
                                    channel.close(mode: .all, promise: nil)
                                }
                            }
                        case .failure(let error):
                            readyPromise.fail(error)
                        }
                    }

                    let timeoutTask = sessionEventLoop.scheduleTask(in: timeout) {
                        openState.abort(error: CitadelError.channelCreationFailed)
                    }

                    // Cancel the channel-open timer as soon as channel confirmation
                    // completes so a confirmed channel whose exec/shell has already
                    // been submitted can never time out as channelCreationFailed.
                    createChannel.futureResult.whenComplete { _ in
                        timeoutTask.cancel()
                    }

                    return readyPromise.futureResult
                }.get()
            } onCancel: {
                sessionEventLoop.execute {
                    openState.abort(error: CancellationError())
                }
            }

            if let agentToken {
                channel.closeFuture.whenComplete { _ in
                    inboundHandler.rollbackAgentHandler(token: agentToken)
                }
            }

            return channel
        } catch {
            if let agentToken {
                inboundHandler.rollbackAgentHandler(token: agentToken)
            }
            throw error
        }
    }

    internal func _executeCommandStream(
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        mode: CommandMode,
        agentDelegate: SSHAgentDelegate? = nil
    ) async throws -> (channel: Channel, output: AsyncThrowingStream<ExecCommandOutput, Error>) {
        let (stream, streamContinuation) = AsyncThrowingStream<ExecCommandOutput, Error>.makeStream()

        let hasReceivedChannelSuccess = NIOLockedValueBox<Bool>(false)
        let exitCode = NIOLockedValueBox<Int?>(nil)

        let handler = ExecCommandHandler(logger: logger) { channel, output in
            switch output {
            case .stdout(let stdout):
                streamContinuation.yield(.stdout(stdout))
            case .stderr(let stderr):
                streamContinuation.yield(.stderr(stderr))
            case .eof(let error):
                self.logger.debug("EOF triggered, ending the command stream.")
                if let error {
                    streamContinuation.finish(throwing: error)
                } else if let exitCode = exitCode.withLockedValue({ $0 }), exitCode != 0 {
                    streamContinuation.finish(throwing: CommandFailed(exitCode: exitCode))
                } else {
                    streamContinuation.finish()
                }
            case .channelSuccess:
                if case .tty(.some(let command)) = mode, !hasReceivedChannelSuccess.withLockedValue({ $0 }) {
                    let commandData = SSHChannelData(
                        type: .channel,
                        data: .byteBuffer(ByteBuffer(string: command + ";exit\n"))
                    )
                    channel.writeAndFlush(commandData, promise: nil)
                    hasReceivedChannelSuccess.withLockedValue({ $0 = true })
                }
            case .exit(let status):
                self.logger.debug("Process exited with status code \(status). Will await on EOF for correct exit")
                exitCode.withLockedValue({ $0 = status })
                streamContinuation.yield(.exitStatus(status))
            }
        }

        let channel = try await openCommandChannel(
            environment: environment,
            mode: mode,
            agentDelegate: agentDelegate,
            handler: handler
        )

        return (channel, stream)
    }

    /// Runs a PTY session delivering stdout/stderr/exitStatus synchronously on the
    /// channel's NIO event loop without an `AsyncThrowingStream` or Swift Concurrency
    /// thread hop per packet.
    private func _runPTYDirect(
        environment: [SSHChannelRequestEvent.EnvironmentRequest],
        mode: CommandMode,
        agentDelegate: SSHAgentDelegate?,
        onReady: @escaping @Sendable (TTYStdinWriter) -> Void,
        onOutput: @escaping @Sendable (ExecCommandOutput) -> Void
    ) async throws {
        struct CompletionState {
            var exitCode: Int?
            var result: Result<Void, Error>?
            var continuation: CheckedContinuation<Void, Error>?
        }
        let completionState = NIOLockedValueBox(CompletionState())

        let finish: @Sendable (Result<Void, Error>) -> Void = { result in
            let continuation: CheckedContinuation<Void, Error>? = completionState.withLockedValue { state in
                guard state.result == nil else { return nil }
                state.result = result
                let cont = state.continuation
                state.continuation = nil
                return cont
            }
            continuation?.resume(with: result)
        }

        let handler = ExecCommandHandler(logger: logger) { _, output in
            switch output {
            case .stdout(let stdout):
                onOutput(.stdout(stdout))
            case .stderr(let stderr):
                onOutput(.stderr(stderr))
            case .exit(let status):
                self.logger.debug("Process exited with status code \(status). Will await on EOF for correct exit")
                completionState.withLockedValue { $0.exitCode = status }
                onOutput(.exitStatus(status))
            case .channelSuccess:
                break
            case .eof(let error):
                self.logger.debug("EOF triggered, ending the direct PTY session.")
                let result: Result<Void, Error>
                if let error {
                    result = .failure(error)
                } else if let code = completionState.withLockedValue({ $0.exitCode }), code != 0 {
                    result = .failure(CommandFailed(exitCode: code))
                } else {
                    result = .success(())
                }
                finish(result)
            }
        }

        let channel = try await openCommandChannel(
            environment: environment,
            mode: mode,
            agentDelegate: agentDelegate,
            handler: handler
        )

        if Task.isCancelled {
            channel.close(promise: nil)
            throw CancellationError()
        }

        onReady(TTYStdinWriter(channel: channel))

        do {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    let immediateResult: Result<Void, Error>? = completionState.withLockedValue { state in
                        if let existing = state.result {
                            return existing
                        }
                        state.continuation = continuation
                        return nil
                    }
                    if let immediateResult {
                        continuation.resume(with: immediateResult)
                    }
                }
            } onCancel: {
                channel.close(promise: nil)
                finish(.success(()))
            }
            try? await channel.close()
        } catch {
            try? await channel.close()
            throw error
        }
    }

    /// Low-latency PTY session that delivers inbound output synchronously on the NIO event loop
    /// via `onOutput` instead of hopping through `AsyncThrowingStream` on every packet.
    public func withPTYDirect(
        _ request: SSHChannelRequestEvent.PseudoTerminalRequest,
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        agentDelegate: SSHAgentDelegate? = nil,
        onReady: @escaping @Sendable (TTYStdinWriter) -> Void,
        onOutput: @escaping @Sendable (ExecCommandOutput) -> Void
    ) async throws {
        try await _runPTYDirect(
            environment: environment,
            mode: .pty(request),
            agentDelegate: agentDelegate,
            onReady: onReady,
            onOutput: onOutput
        )
    }

    /// Low-latency PTY+exec session that delivers inbound output synchronously on the NIO event loop
    /// via `onOutput` instead of hopping through `AsyncThrowingStream` on every packet.
    public func withPTYExecDirect(
        _ request: SSHChannelRequestEvent.PseudoTerminalRequest,
        command: String,
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        agentDelegate: SSHAgentDelegate? = nil,
        onReady: @escaping @Sendable (TTYStdinWriter) -> Void,
        onOutput: @escaping @Sendable (ExecCommandOutput) -> Void
    ) async throws {
        try await _runPTYDirect(
            environment: environment,
            mode: .ptyExec(request, command: command),
            agentDelegate: agentDelegate,
            onReady: onReady,
            onOutput: onOutput
        )
    }

    /// Creates a pseudo-terminal (PTY) session and executes the provided closure with input/output streams
    /// - Parameters:
    ///   - request: PTY configuration parameters
    ///   - environment: Array of environment variables to set for the PTY session. This requires `PermitUserEnvironment` to be enabled in your OpenSSH server's configuration.
    ///   - perform: Closure that receives TTY input/output streams and performs terminal operations
    /// - Throws: Any errors that occur during PTY setup or operation
    @available(macOS 15.0, *)
    public func withPTY(
        _ request: SSHChannelRequestEvent.PseudoTerminalRequest,
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        perform: (_ inbound: TTYOutput, _ outbound: TTYStdinWriter) async throws -> Void
    ) async throws {
        let (channel, output) = try await _executeCommandStream(
            environment: environment,
            mode: .pty(request)
        )

        func close() async throws {
            try await channel.close()
        }

        do {
            let inbound = TTYOutput(sequence: output)
            try await perform(inbound, TTYStdinWriter(channel: channel))
            try await close()
        } catch {
            try await close()
            throw error
        }
    }

    /// Creates a TTY session and executes the provided closure with input/output streams
    /// 
    /// - Parameters:
    ///   - environment: Array of environment variables to set for the TTY session
    ///   - perform: Closure that receives TTY input/output streams and performs terminal operations
    /// - Throws: Any errors that occur during TTY setup or operation
    /// 
    /// ## Example
    /// ```swift
    /// // Create an interactive shell session
    /// try await client.withTTY { inbound, outbound in
    ///     // Send commands
    ///     try await outbound.write(ByteBuffer(string: "echo $PATH\n"))
    ///     
    ///     // Process output
    ///     for try await output in inbound {
    ///         switch output {
    ///         case .stdout(let buffer):
    ///             print(String(buffer: buffer))
    ///         case .stderr(let buffer):
    ///             print("Error:", String(buffer: buffer))
    ///         }
    ///     }
    /// }
    /// ```
    /// Creates a pseudo-terminal (PTY) session with optional agent forwarding
    /// - Parameters:
    ///   - request: PTY configuration parameters
    ///   - environment: Array of environment variables to set for the PTY session
    ///   - agentDelegate: Optional agent delegate for SSH agent forwarding
    ///   - perform: Closure that receives TTY input/output streams and performs terminal operations
    /// - Throws: Any errors that occur during PTY setup or operation
    @available(macOS 15.0, *)
    public func withPTY(
        _ request: SSHChannelRequestEvent.PseudoTerminalRequest,
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        agentDelegate: SSHAgentDelegate?,
        perform: (_ inbound: TTYOutput, _ outbound: TTYStdinWriter) async throws -> Void
    ) async throws {
        // Pass agent delegate to _executeCommandStream so it's enabled
        // in the correct order (after PTY request, before shell request)
        let (channel, output) = try await _executeCommandStream(
            environment: environment,
            mode: .pty(request),
            agentDelegate: agentDelegate
        )

        func close() async throws {
            try await channel.close()
        }

        do {
            let inbound = TTYOutput(sequence: output)
            try await perform(inbound, TTYStdinWriter(channel: channel))
            try await close()
        } catch {
            try await close()
            throw error
        }
    }

    @available(macOS 15.0, *)
    public func withTTY(
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        perform: (_ inbound: TTYOutput, _ outbound: TTYStdinWriter) async throws -> Void
    ) async throws {
        let (channel, output) = try await _executeCommandStream(
            environment: environment,
            mode: .tty(command: nil)
        )

        func close() async throws {
            try await channel.close()
        }

        do {
            let inbound = TTYOutput(sequence: output)
            try await perform(inbound, TTYStdinWriter(channel: channel))
            try await close()
        } catch {
            try await close()
            throw error
        }
    }

    /// Creates a pseudo-terminal (PTY) session and executes a specific command
    ///
    /// Unlike `withPTY` which starts an interactive shell, this method sends an exec request
    /// with the specified command. This is useful for launching interactive applications like
    /// tmux directly via SSH protocol rather than typing them into a shell.
    ///
    /// - Parameters:
    ///   - request: PTY configuration parameters
    ///   - command: The command to execute (e.g., "tmux new-session -A -s main")
    ///   - environment: Array of environment variables to set for the session
    ///   - agentDelegate: Optional agent delegate for SSH agent forwarding
    ///   - perform: Closure that receives TTY input/output streams and performs terminal operations
    /// - Throws: Any errors that occur during PTY setup or command execution
    @available(macOS 15.0, *)
    public func withPTYExec(
        _ request: SSHChannelRequestEvent.PseudoTerminalRequest,
        command: String,
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        agentDelegate: SSHAgentDelegate?,
        perform: (_ inbound: TTYOutput, _ outbound: TTYStdinWriter) async throws -> Void
    ) async throws {
        let (channel, output) = try await _executeCommandStream(
            environment: environment,
            mode: .ptyExec(request, command: command),
            agentDelegate: agentDelegate
        )

        func close() async throws {
            try await channel.close()
        }

        do {
            let inbound = TTYOutput(sequence: output)
            try await perform(inbound, TTYStdinWriter(channel: channel))
            try await close()
        } catch {
            try await close()
            throw error
        }
    }

    /// Executes a command and returns separate stdout and stderr streams
    /// 
    /// Example:
    /// ```swift
    /// let client = try await SSHClient(/* ... */)
    /// 
    /// // Execute a command with separate stdout/stderr handling
    /// let streams = try await client.executeCommandPair("make")
    /// 
    /// // Handle stdout
    /// Task {
    ///     for try await output in streams.stdout {
    ///         print("stdout:", String(buffer: output))
    ///     }
    /// }
    /// 
    /// // Handle stderr
    /// Task {
    ///     for try await error in streams.stderr {
    ///         print("stderr:", String(buffer: error))
    ///     }
    /// }
    /// ```
    /// - Parameters:
    ///   - command: The command to execute on the remote server
    ///   - inShell: Whether to execute the command within a shell context. Defaults to false
    /// - Returns: An ExecCommandStream containing separate stdout and stderr streams
    /// - Throws: CommandFailed if the command exits with non-zero status
    public func executeCommandPair(_ command: String, inShell: Bool = false) async throws -> ExecCommandStream {
        var stdoutContinuation: AsyncThrowingStream<ByteBuffer, Error>.Continuation!
        var stderrContinuation: AsyncThrowingStream<ByteBuffer, Error>.Continuation!
        let stdout = AsyncThrowingStream<ByteBuffer, Error>(bufferingPolicy: .unbounded) { continuation in
            stdoutContinuation = continuation
        }
        
        let stderr = AsyncThrowingStream<ByteBuffer, Error>(bufferingPolicy: .unbounded) { continuation in
            stderrContinuation = continuation
        }
        
        let handler = ExecCommandStream.Continuation(
            stdout: stdoutContinuation,
            stderr: stderrContinuation
        )
        
        Task {
            do {
                let stream = try await executeCommandStream(command, inShell: inShell)
                for try await chunk in stream {
                    switch chunk {
                    case .stdout(let buffer):
                        handler.stdout.yield(buffer)
                    case .stderr(let buffer):
                        handler.stderr.yield(buffer)
                    case .exitStatus:
                        // Exit status is informational - just continue
                        break
                    }
                }
                
                handler.stdout.finish()
                handler.stderr.finish()
            } catch {
                handler.stdout.finish(throwing: error)
                handler.stderr.finish(throwing: error)
            }
        }
        
        return ExecCommandStream(stdout: stdout, stderr: stderr)
    }
}
