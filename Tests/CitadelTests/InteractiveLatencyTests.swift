@testable import Citadel
import Logging
import Network
import NIOCore
import NIOEmbedded
import NIOConcurrencyHelpers
import NIOPosix
@preconcurrency import NIOSSH
import NIOTransportServices
import XCTest

final class InteractiveLatencyTests: XCTestCase {
    private enum WaiterError: Error {
        case prematureEOF
        case timedOut
    }

    private func withDeadline<T: Sendable>(
        seconds: Double = 10.0,
        onTimeout: @escaping @Sendable () -> Void = {},
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask {
                try await operation()
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                onTimeout()
                throw WaiterError.timedOut
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    private final class BoundedWaiter: @unchecked Sendable {
        private let lock = NIOLock()
        private var continuation: CheckedContinuation<ByteBuffer, Error>?
        private var pending: [ByteBuffer] = []
        private var terminalError: Error?

        func deliver(_ buf: ByteBuffer) {
            let cont: CheckedContinuation<ByteBuffer, Error>? = lock.withLock {
                guard terminalError == nil else { return nil }
                if let c = continuation {
                    continuation = nil
                    return c
                }
                pending.append(buf)
                return nil
            }
            cont?.resume(returning: buf)
        }

        func fail(_ error: Error) {
            let cont: CheckedContinuation<ByteBuffer, Error>? = lock.withLock {
                guard terminalError == nil else { return nil }
                terminalError = error
                let c = continuation
                continuation = nil
                return c
            }
            cont?.resume(throwing: error)
        }

        func finish() {
            fail(WaiterError.prematureEOF)
        }

        func next(timeoutSeconds: Double = 5.0) async throws -> ByteBuffer {
            try await withThrowingTaskGroup(of: ByteBuffer.self) { group in
                group.addTask {
                    try await withCheckedThrowingContinuation { cont in
                        let action: Result<ByteBuffer, Error>? = self.lock.withLock {
                            if !self.pending.isEmpty {
                                return .success(self.pending.removeFirst())
                            }
                            if let err = self.terminalError {
                                return .failure(err)
                            }
                            self.continuation = cont
                            return nil
                        }
                        if let action {
                            cont.resume(with: action)
                        }
                    }
                }
                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                    self.fail(WaiterError.timedOut)
                    throw WaiterError.timedOut
                }
                let result = try await group.next()!
                group.cancelAll()
                return result
            }
        }
    }

    func testExecCommandHandlerCoalescesSameReadCycleAndPreservesOrder() throws {
        let loop = EmbeddedEventLoop()
        let channel = EmbeddedChannel(loop: loop)
        let delivered = NIOLockedValueBox<[String]>([])

        let handler = ExecCommandHandler(logger: Logger(label: "test.exec.coalesce")) { _, output in
            let entry: String
            switch output {
            case .stdout(let buf):
                entry = "out:\(String(buffer: buf))"
            case .stderr(let buf):
                entry = "err:\(String(buffer: buf))"
            case .exit(let code):
                entry = "exit:\(code)"
            case .channelSuccess:
                entry = "success"
            case .eof:
                entry = "eof"
            }
            delivered.withLockedValue { $0.append(entry) }
        }

        try channel.pipeline.syncOperations.addHandler(handler)

        // Two stdout packets in one read cycle coalesce into one delivery on channelReadComplete.
        channel.pipeline.syncOperations.fireChannelRead(NIOAny(SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(string: "hel")))))
        channel.pipeline.syncOperations.fireChannelRead(NIOAny(SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(string: "lo")))))
        channel.pipeline.syncOperations.fireChannelReadComplete()
        XCTAssertEqual(delivered.withLockedValue { $0 }, ["out:hello"])

        // Switching from stdout to stderr flushes stdout first, preserving stream ordering.
        channel.pipeline.syncOperations.fireChannelRead(NIOAny(SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(string: "A")))))
        channel.pipeline.syncOperations.fireChannelRead(NIOAny(SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(string: "B")))))
        channel.pipeline.syncOperations.fireChannelRead(NIOAny(SSHChannelData(type: .stdErr, data: .byteBuffer(ByteBuffer(string: "E1")))))
        channel.pipeline.syncOperations.fireChannelRead(NIOAny(SSHChannelData(type: .stdErr, data: .byteBuffer(ByteBuffer(string: "E2")))))
        channel.pipeline.syncOperations.fireUserInboundEventTriggered(SSHChannelRequestEvent.ExitStatus(exitStatus: 0))
        channel.pipeline.syncOperations.fireChannelReadComplete()

        XCTAssertEqual(delivered.withLockedValue { $0 }, [
            "out:hello",
            "out:AB",
            "err:E1E2",
            "exit:0",
        ])

        _ = try channel.finish()
    }

    func testTTYStdinWriterWriteImmediateDeliversFIFO() throws {
        let loop = EmbeddedEventLoop()
        let channel = EmbeddedChannel(loop: loop)
        let writer = TTYStdinWriter(channel: channel)

        for byte in ["a", "b", "c", "d"] {
            writer.writeImmediate(ByteBuffer(string: byte))
        }
        loop.run()

        var received = ""
        while let data = try channel.readOutbound(as: SSHChannelData.self) {
            if case .byteBuffer(let buf) = data.data {
                received += String(buffer: buf)
            }
        }
        XCTAssertEqual(received, "abcd")
        _ = try channel.finish()
    }

    func testAgentHandlerOverlappingRollbacksPreserveSurvivingShell() throws {
        let inbound = SSHClientInboundChannelHandler()
        let invoked = NIOLockedValueBox<[String]>([])
        let loop = EmbeddedEventLoop()
        let channel = EmbeddedChannel(loop: loop)

        // Live shell S registers first.
        _ = inbound.registerAgentHandler { ch in
            invoked.withLockedValue { $0.append("shell") }
            return ch.eventLoop.makeSucceededVoidFuture()
        }

        // Overlapping pending opens A then B.
        let tokenA = inbound.registerAgentHandler { ch in
            invoked.withLockedValue { $0.append("A") }
            return ch.eventLoop.makeSucceededVoidFuture()
        }
        let tokenB = inbound.registerAgentHandler { ch in
            invoked.withLockedValue { $0.append("B") }
            return ch.eventLoop.makeSucceededVoidFuture()
        }

        // A fails first: B stays active.
        inbound.rollbackAgentHandler(token: tokenA)
        try inbound.handleChannel(channel: channel, channelType: .authAgent).wait()
        XCTAssertEqual(invoked.withLockedValue { $0 }, ["B"])

        // B then fails: must restore live shell S (NOT failed A).
        inbound.rollbackAgentHandler(token: tokenB)
        try inbound.handleChannel(channel: channel, channelType: .authAgent).wait()
        XCTAssertEqual(invoked.withLockedValue { $0 }, ["B", "shell"])

        // Concurrent registrations on the same channel owner: A succeeding before B
        // must NOT prune newer B; B succeeding then prunes older A, leaving B active.
        let owner = ObjectIdentifier(channel)
        let first = inbound.registerAgentHandler(ownerID: owner) { ch in
            invoked.withLockedValue { $0.append("owner-1") }
            return ch.eventLoop.makeSucceededVoidFuture()
        }
        let second = inbound.registerAgentHandler(ownerID: owner) { ch in
            invoked.withLockedValue { $0.append("owner-2") }
            return ch.eventLoop.makeSucceededVoidFuture()
        }
        inbound.pruneAgentHandlers(forOwner: owner, keeping: first)
        inbound.pruneAgentHandlers(forOwner: owner, keeping: second)
        try inbound.handleChannel(channel: channel, channelType: .authAgent).wait()
        XCTAssertEqual(invoked.withLockedValue { $0 }, ["B", "shell", "owner-2"])

        // Rolling back owner-2 now falls all the way back to "shell" because owner-1 was pruned.
        inbound.rollbackAgentHandler(token: second)
        try inbound.handleChannel(channel: channel, channelType: .authAgent).wait()
        XCTAssertEqual(invoked.withLockedValue { $0 }, ["B", "shell", "owner-2", "shell"])

        _ = try channel.finish()
    }

    /// Verifies that both a channel-open timeout and task cancellation during
    /// `openCommandChannel` close the unconfirmed child channel (discarding its
    /// queued exec request so a late confirmation never executes the command)
    /// and surface the intended error (`CitadelError.channelCreationFailed` /
    /// `CancellationError`) rather than `ChannelError.eof`.
    func testOpenCommandChannelTimeoutAndCancellationDiscardQueuedCommand() async throws {
        final class RecordingExecDelegate: ExecDelegate, @unchecked Sendable {
            final class Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            let executedCommands = NIOLockedValueBox<[String]>([])
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                executedCommands.withLockedValue { $0.append(command) }
                outputHandler.succeed(exitCode: 0)
                return Ctx()
            }
        }

        // Pausable TCP proxy: once paused, buffers server->client bytes (e.g.
        // CHANNEL_OPEN_CONFIRMATION) until resumed, letting us reliably trigger
        // timeout or cancellation mid-open and then deliver the late confirmation.
        final class PausableForwarder: ChannelInboundHandler, @unchecked Sendable {
            typealias InboundIn = ByteBuffer
            private let peer: Channel
            private let gate: NIOLockedValueBox<(paused: Bool, held: [ByteBuffer])>
            init(peer: Channel, gate: NIOLockedValueBox<(paused: Bool, held: [ByteBuffer])>) {
                self.peer = peer
                self.gate = gate
            }
            func channelRead(context: ChannelHandlerContext, data: NIOAny) {
                let buf = unwrapInboundIn(data)
                let shouldForward = gate.withLockedValue { state -> Bool in
                    if state.paused {
                        state.held.append(buf)
                        return false
                    }
                    return true
                }
                if shouldForward {
                    peer.writeAndFlush(buf, promise: nil)
                }
            }
            func channelInactive(context: ChannelHandlerContext) {
                peer.close(promise: nil)
            }
        }

        let authDelegate = AuthDelegate(supportedAuthenticationMethods: .password) { request, promise in
            promise.succeed(request.username == "citadel" ? .success : .failure)
        }
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let server = try await SSHServer.host(
            host: "127.0.0.1",
            port: 0,
            hostKeys: [hostKey],
            authenticationDelegate: authDelegate
        )
        defer { Task { try? await server.close() } }
        let execDelegate = RecordingExecDelegate()
        server.enableExec(withDelegate: execDelegate)
        let serverPort = try XCTUnwrap(server.channel.localAddress?.port)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }

        let serverToClientGate = NIOLockedValueBox<(paused: Bool, held: [ByteBuffer])>((false, []))
        let clientSideChannel = NIOLockedValueBox<Channel?>(nil)
        let proxyServer = try await ServerBootstrap(group: group)
            .childChannelInitializer { clientCh in
                clientSideChannel.withLockedValue { $0 = clientCh }
                return ClientBootstrap(group: clientCh.eventLoop)
                    .connect(host: "127.0.0.1", port: serverPort)
                    .flatMap { backendCh in
                        let passThrough = NIOLockedValueBox<(paused: Bool, held: [ByteBuffer])>((false, []))
                        return clientCh.pipeline.addHandler(PausableForwarder(peer: backendCh, gate: passThrough)).flatMap {
                            backendCh.pipeline.addHandler(PausableForwarder(peer: clientCh, gate: serverToClientGate))
                        }
                    }
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        defer { try? proxyServer.close().wait() }
        let proxyPort = try XCTUnwrap(proxyServer.localAddress?.port)

        let client = try await SSHClient.connect(
            host: "127.0.0.1",
            port: proxyPort,
            authenticationMethod: .passwordBased(username: "citadel", password: "test"),
            hostKeyValidator: .trustedKeys([hostKey.publicKey]),
            reconnect: .never
        )
        defer { Task { try? await client.close() } }

        func flushHeldServerPackets() {
            let held = serverToClientGate.withLockedValue { state -> [ByteBuffer] in
                state.paused = false
                let chunks = state.held
                state.held.removeAll()
                return chunks
            }
            if let ch = clientSideChannel.withLockedValue({ $0 }) {
                ch.eventLoop.execute {
                    for buf in held {
                        ch.write(buf, promise: nil)
                    }
                    ch.flush()
                }
            }
        }

        // 1. Timeout during openCommandChannel must surface CitadelError.channelCreationFailed
        //    (not ChannelError.eof) and discard the queued exec request even when confirmation arrives late.
        serverToClientGate.withLockedValue { $0.paused = true }
        let timeoutHandler = ExecCommandHandler(logger: Logger(label: "test.timeout")) { _, _ in }
        do {
            _ = try await client.openCommandChannel(
                environment: [],
                mode: .command("must-not-run-timeout"),
                agentDelegate: nil,
                handler: timeoutHandler,
                timeout: .milliseconds(100)
            )
            XCTFail("Expected channelCreationFailed timeout")
        } catch let err as CitadelError {
            XCTAssertEqual(err, .channelCreationFailed)
        } catch {
            XCTFail("Expected CitadelError.channelCreationFailed, got \(error)")
        }
        flushHeldServerPackets()
        try await Task.sleep(nanoseconds: 150_000_000)
        XCTAssertEqual(execDelegate.executedCommands.withLockedValue { $0 }, [])

        // 2. Task cancellation during openCommandChannel must surface CancellationError
        //    and close the pending child so late confirmation never runs the queued exec request.
        //    Deterministically wait until the proxy actually buffers server->client bytes
        //    (CHANNEL_OPEN_CONFIRMATION) before cancelling, proving a pending child exists.
        serverToClientGate.withLockedValue { $0.paused = true }
        let cancelHandler = ExecCommandHandler(logger: Logger(label: "test.cancel")) { _, _ in }
        let openTask = Task {
            try await client.openCommandChannel(
                environment: [],
                mode: .command("must-not-run-cancel"),
                agentDelegate: nil,
                handler: cancelHandler,
                timeout: .seconds(15)
            )
        }
        let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
        while serverToClientGate.withLockedValue({ $0.held.isEmpty }) {
            if DispatchTime.now().uptimeNanoseconds >= deadline {
                openTask.cancel()
                XCTFail("Timed out waiting for proxy to buffer CHANNEL_OPEN_CONFIRMATION")
                return
            }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        openTask.cancel()
        do {
            _ = try await openTask.value
            XCTFail("Expected CancellationError")
        } catch is CancellationError {
            // expected
        } catch {
            XCTFail("Expected CancellationError, got \(error)")
        }
        flushHeldServerPackets()
        try await Task.sleep(nanoseconds: 150_000_000)
        XCTAssertEqual(execDelegate.executedCommands.withLockedValue { $0 }, [])

        // 3. Verify the same SSH connection remains healthy and runs subsequent commands normally.
        _ = try await withDeadline(seconds: 5.0) {
            try await client.executeCommand("after-abort-ok")
        }
        XCTAssertEqual(execDelegate.executedCommands.withLockedValue { $0 }, ["after-abort-ok"])
    }

    @available(macOS 15.0, *)
    func testWithPTYDirectEchoRoundTripAndCachedAlgorithms() async throws {
        struct EchoShellDelegate: ShellDelegate {
            func startShell(
                inbound: AsyncStream<ShellClientEvent>,
                outbound: ShellOutboundWriter,
                context: SSHShellContext
            ) async throws {
                for await event in inbound {
                    switch event {
                    case .stdin(let buf):
                        if String(buffer: buf) == "\u{04}" {
                            return
                        }
                        outbound.write(buf)
                    }
                }
            }
        }

        let authDelegate = AuthDelegate(supportedAuthenticationMethods: .password) { request, promise in
            promise.succeed(request.username == "citadel" ? .success : .failure)
        }

        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let server = try await SSHServer.host(
            host: "127.0.0.1",
            port: 0,
            hostKeys: [hostKey],
            authenticationDelegate: authDelegate
        )
        defer { Task { try? await server.close() } }
        server.enableShell(withDelegate: EchoShellDelegate())

        let port = try XCTUnwrap(server.channel.localAddress?.port)
        let client = try await SSHClient.connect(
            host: "127.0.0.1",
            port: port,
            authenticationMethod: .passwordBased(username: "citadel", password: "test"),
            hostKeyValidator: .trustedKeys([hostKey.publicKey]),
            reconnect: .never
        )
        defer { Task { try? await client.close() } }

        // Synchronous negotiatedAlgorithms snapshot and live async query should both succeed and match.
        let cachedAlgos = try XCTUnwrap(client.negotiatedAlgorithms)
        let liveResult = try await client.getNegotiatedAlgorithms()
        let liveAlgos = try XCTUnwrap(liveResult)
        XCTAssertEqual(cachedAlgos.keyExchange, liveAlgos.keyExchange)
        XCTAssertEqual(cachedAlgos.hostKey, liveAlgos.hostKey)
        XCTAssertEqual(cachedAlgos.cipher, liveAlgos.cipher)
        XCTAssertEqual(cachedAlgos.mac, liveAlgos.mac)

        let ptyReq = SSHChannelRequestEvent.PseudoTerminalRequest(
            wantReply: true,
            term: "xterm-256color",
            terminalCharacterWidth: 80,
            terminalRowHeight: 24,
            terminalPixelWidth: 0,
            terminalPixelHeight: 0,
            terminalModes: .init([:])
        )

        let iterations = 200
        let burstCount = 50
        let closeClientOnTimeout: @Sendable () -> Void = {
            Task { try? await client.close() }
        }

        // 1. Measure legacy path under an overall deadline covering every iterator.next().
        let (legacyRttsUs, legacyBurstMs): ([Double], Double) = try await withDeadline(
            seconds: 10.0,
            onTimeout: closeClientOnTimeout
        ) {
            var rtts: [Double] = []
            rtts.reserveCapacity(iterations)
            var burstMs: Double = 0
            try await client.withPTY(ptyReq) { inbound, outbound in
                let (stdinStream, stdinCont) = AsyncStream.makeStream(of: ByteBuffer.self)
                let writerTask = Task.detached(priority: .userInitiated) {
                    for await buf in stdinStream {
                        try? await outbound.write(buf)
                    }
                }
                var iterator = inbound.makeAsyncIterator()

                for _ in 0..<10 {
                    stdinCont.yield(ByteBuffer(string: "w"))
                    guard try await iterator.next() != nil else { throw WaiterError.prematureEOF }
                }

                for i in 0..<iterations {
                    let ch = String(UnicodeScalar(97 + (i % 26))!)
                    let start = DispatchTime.now().uptimeNanoseconds
                    stdinCont.yield(ByteBuffer(string: ch))
                    guard let next = try await iterator.next() else { throw WaiterError.prematureEOF }
                    let elapsedUs = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000.0
                    if case .stdout(let buf) = next {
                        XCTAssertEqual(String(buffer: buf), ch)
                    } else {
                        XCTFail("Expected stdout, got \(next)")
                    }
                    rtts.append(elapsedUs)
                }

                let burstStart = DispatchTime.now().uptimeNanoseconds
                for i in 0..<burstCount {
                    stdinCont.yield(ByteBuffer(string: String(UnicodeScalar(97 + (i % 26))!)))
                }
                var burstReceived = 0
                while burstReceived < burstCount {
                    guard let next = try await iterator.next() else {
                        throw WaiterError.prematureEOF
                    }
                    if case .stdout(let buf) = next {
                        burstReceived += buf.readableBytes
                    }
                }
                burstMs = Double(DispatchTime.now().uptimeNanoseconds - burstStart) / 1_000_000.0

                stdinCont.yield(ByteBuffer(string: "\u{04}"))
                stdinCont.finish()
                _ = await writerTask.value
            }
            return (rtts, burstMs)
        }

        // 2. Measure new direct path under an overall deadline covering echoes and ptyTask completion.
        let (directRttsUs, directBurstMs): ([Double], Double) = try await withDeadline(
            seconds: 10.0,
            onTimeout: closeClientOnTimeout
        ) {
            let waiter = BoundedWaiter()
            let readySignal = BoundedWaiter()
            let writerBox = NIOLockedValueBox<TTYStdinWriter?>(nil)

            let ptyTask = Task {
                do {
                    try await client.withPTYDirect(
                        ptyReq,
                        onReady: { writer in
                            writerBox.withLockedValue { $0 = writer }
                            readySignal.deliver(ByteBuffer())
                        },
                        onOutput: { output in
                            if case .stdout(let buf) = output {
                                waiter.deliver(buf)
                            }
                        }
                    )
                    readySignal.finish()
                    waiter.finish()
                } catch {
                    readySignal.fail(error)
                    waiter.fail(error)
                    throw error
                }
            }

            _ = try await readySignal.next()
            let writer = try XCTUnwrap(writerBox.withLockedValue { $0 })

            for _ in 0..<10 {
                writer.writeImmediate(ByteBuffer(string: "w"))
                _ = try await waiter.next()
            }

            var rtts: [Double] = []
            rtts.reserveCapacity(iterations)
            for i in 0..<iterations {
                let ch = String(UnicodeScalar(97 + (i % 26))!)
                let start = DispatchTime.now().uptimeNanoseconds
                writer.writeImmediate(ByteBuffer(string: ch))
                let echoed = try await waiter.next()
                let elapsedUs = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000.0
                XCTAssertEqual(String(buffer: echoed), ch)
                rtts.append(elapsedUs)
            }

            let directBurstStart = DispatchTime.now().uptimeNanoseconds
            for i in 0..<burstCount {
                writer.writeImmediate(ByteBuffer(string: String(UnicodeScalar(97 + (i % 26))!)))
            }
            var directBurstReceived = 0
            while directBurstReceived < burstCount {
                directBurstReceived += (try await waiter.next()).readableBytes
            }
            let burstMs = Double(DispatchTime.now().uptimeNanoseconds - directBurstStart) / 1_000_000.0

            writer.writeImmediate(ByteBuffer(string: "\u{04}"))
            try await ptyTask.value
            return (rtts, burstMs)
        }

        let sortedLegacy = legacyRttsUs.sorted()
        let sortedDirect = directRttsUs.sorted()
        let legacyP50 = sortedLegacy[sortedLegacy.count / 2]
        let legacyP95 = sortedLegacy[Int(Double(sortedLegacy.count - 1) * 0.95)]
        let directP50 = sortedDirect[sortedDirect.count / 2]
        let directP95 = sortedDirect[Int(Double(sortedDirect.count - 1) * 0.95)]
        print(String(format: "BENCH legacy  1-byte echo RTT (n=%d): p50=%.1f us, p95=%.1f us, 50-key burst=%.2f ms", iterations, legacyP50, legacyP95, legacyBurstMs))
        print(String(format: "BENCH direct  1-byte echo RTT (n=%d): p50=%.1f us, p95=%.1f us, 50-key burst=%.2f ms", iterations, directP50, directP95, directBurstMs))
    }

    @available(macOS 15.0, *)
    func testNIOTSInteractiveLatencyComparison() async throws {
        struct EchoShellDelegate: ShellDelegate {
            func startShell(
                inbound: AsyncStream<ShellClientEvent>,
                outbound: ShellOutboundWriter,
                context: SSHShellContext
            ) async throws {
                for await event in inbound {
                    switch event {
                    case .stdin(let buf):
                        let str = String(buffer: buf)
                        if str == "\u{04}" { return }
                        if str == "R" {
                            // Simulate a 32 KiB full-screen TUI redraw
                            outbound.write(ByteBuffer(repeating: 0x41, count: 32 * 1024))
                        } else {
                            outbound.write(buf)
                        }
                    }
                }
            }
        }

        let authDelegate = AuthDelegate(supportedAuthenticationMethods: .password) { request, promise in
            promise.succeed(request.username == "citadel" ? .success : .failure)
        }
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let server = try await SSHServer.host(
            host: "127.0.0.1",
            port: 0,
            hostKeys: [hostKey],
            authenticationDelegate: authDelegate
        )
        defer { Task { try? await server.close() } }
        server.enableShell(withDelegate: EchoShellDelegate())
        let port = try XCTUnwrap(server.channel.localAddress?.port)

        let ptyReq = SSHChannelRequestEvent.PseudoTerminalRequest(
            wantReply: true,
            term: "xterm-256color",
            terminalCharacterWidth: 80,
            terminalRowHeight: 24,
            terminalPixelWidth: 0,
            terminalPixelHeight: 0,
            terminalModes: .init([:])
        )

        // Legacy NIOTS client (.default QoS, default 8 KiB maxReceive, withPTY + AsyncStream + await write)
        let legacyGroup = NIOTSEventLoopGroup(loopCount: 2)
        defer { try? legacyGroup.syncShutdownGracefully() }
        let legacyChannel = try await NIOTSConnectionBootstrap(group: legacyGroup)
            .channelOption(ChannelOptions.autoRead, value: false)
            .connect(host: "127.0.0.1", port: port)
            .get()
        let legacySettings = SSHClientSettings(
            host: "127.0.0.1",
            port: port,
            authenticationMethod: { .passwordBased(username: "citadel", password: "test") },
            hostKeyValidator: .trustedKeys([hostKey.publicKey])
        )
        let legacyClient = try await SSHClient.connect(on: legacyChannel, settings: legacySettings)
        defer { Task { try? await legacyClient.close() } }

        let iterations = 150
        let burstCount = 50

        let (legacyRtts, legacyBurstMs, legacyRedrawUs): ([Double], Double, [Double]) = try await withDeadline(
            seconds: 10.0,
            onTimeout: { Task { try? await legacyClient.close() } }
        ) {
            var rtts: [Double] = []
            var burstMs = 0.0
            var redraws: [Double] = []
            try await legacyClient.withPTY(ptyReq) { inbound, outbound in
                let (stdinStream, stdinCont) = AsyncStream.makeStream(of: ByteBuffer.self)
                let writerTask = Task.detached(priority: .userInitiated) {
                    for await buf in stdinStream { try? await outbound.write(buf) }
                }
                var it = inbound.makeAsyncIterator()
                for _ in 0..<10 {
                    stdinCont.yield(ByteBuffer(string: "w"))
                    guard try await it.next() != nil else { throw WaiterError.prematureEOF }
                }
                for i in 0..<iterations {
                    let ch = String(UnicodeScalar(97 + (i % 26))!)
                    let t0 = DispatchTime.now().uptimeNanoseconds
                    stdinCont.yield(ByteBuffer(string: ch))
                    guard try await it.next() != nil else { throw WaiterError.prematureEOF }
                    rtts.append(Double(DispatchTime.now().uptimeNanoseconds - t0) / 1_000.0)
                }
                let b0 = DispatchTime.now().uptimeNanoseconds
                for i in 0..<burstCount {
                    stdinCont.yield(ByteBuffer(string: String(UnicodeScalar(97 + (i % 26))!)))
                }
                var got = 0
                while got < burstCount {
                    guard let next = try await it.next() else { throw WaiterError.prematureEOF }
                    if case .stdout(let b) = next { got += b.readableBytes }
                }
                burstMs = Double(DispatchTime.now().uptimeNanoseconds - b0) / 1_000_000.0

                for _ in 0..<30 {
                    let t0 = DispatchTime.now().uptimeNanoseconds
                    stdinCont.yield(ByteBuffer(string: "R"))
                    var n = 0
                    while n < 32 * 1024 {
                        guard let next = try await it.next() else { throw WaiterError.prematureEOF }
                        if case .stdout(let b) = next { n += b.readableBytes }
                    }
                    redraws.append(Double(DispatchTime.now().uptimeNanoseconds - t0) / 1_000.0)
                }
                stdinCont.yield(ByteBuffer(string: "\u{04}"))
                stdinCont.finish()
                _ = await writerTask.value
            }
            return (rtts, burstMs, redraws)
        }

        // Optimized NIOTS client (.userInteractive QoS, disableAckStretching, interactiveVideo, 64 KiB maxReceive, withPTYDirect + writeImmediate)
        let fastGroup = NIOTSEventLoopGroup(loopCount: 2, defaultQoS: .userInteractive)
        defer { try? fastGroup.syncShutdownGracefully() }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.disableAckStretching = true
        let fastChannel = try await NIOTSConnectionBootstrap(group: fastGroup)
            .tcpOptions(tcp)
            .withQoS(.userInteractive)
            .configureNWParameters { $0.serviceClass = .interactiveVideo }
            .channelOption(ChannelOptions.autoRead, value: false)
            .channelOption(NIOTSChannelOptions.minimumIncompleteReceiveLength, value: 1)
            .channelOption(NIOTSChannelOptions.maximumReceiveLength, value: 65536)
            .connect(host: "127.0.0.1", port: port)
            .get()
        let fastClient = try await SSHClient.connect(on: fastChannel, settings: legacySettings)
        defer { Task { try? await fastClient.close() } }

        let (fastRtts, fastBurstMs, fastRedrawUs): ([Double], Double, [Double]) = try await withDeadline(
            seconds: 10.0,
            onTimeout: { Task { try? await fastClient.close() } }
        ) {
            let waiter = BoundedWaiter()
            let ready = BoundedWaiter()
            let writerBox = NIOLockedValueBox<TTYStdinWriter?>(nil)
            let ptyTask = Task {
                do {
                    try await fastClient.withPTYDirect(
                        ptyReq,
                        onReady: { w in writerBox.withLockedValue { $0 = w }; ready.deliver(ByteBuffer()) },
                        onOutput: { if case .stdout(let b) = $0 { waiter.deliver(b) } }
                    )
                    ready.finish()
                    waiter.finish()
                } catch {
                    ready.fail(error)
                    waiter.fail(error)
                    throw error
                }
            }
            _ = try await ready.next()
            let writer = try XCTUnwrap(writerBox.withLockedValue { $0 })

            for _ in 0..<10 { writer.writeImmediate(ByteBuffer(string: "w")); _ = try await waiter.next() }
            var rtts: [Double] = []
            for i in 0..<iterations {
                let ch = String(UnicodeScalar(97 + (i % 26))!)
                let t0 = DispatchTime.now().uptimeNanoseconds
                writer.writeImmediate(ByteBuffer(string: ch))
                _ = try await waiter.next()
                rtts.append(Double(DispatchTime.now().uptimeNanoseconds - t0) / 1_000.0)
            }
            let b0 = DispatchTime.now().uptimeNanoseconds
            for i in 0..<burstCount {
                writer.writeImmediate(ByteBuffer(string: String(UnicodeScalar(97 + (i % 26))!)))
            }
            var got = 0
            while got < burstCount { got += (try await waiter.next()).readableBytes }
            let burstMs = Double(DispatchTime.now().uptimeNanoseconds - b0) / 1_000_000.0

            var redraws: [Double] = []
            for _ in 0..<30 {
                let t0 = DispatchTime.now().uptimeNanoseconds
                writer.writeImmediate(ByteBuffer(string: "R"))
                var n = 0
                while n < 32 * 1024 { n += (try await waiter.next()).readableBytes }
                redraws.append(Double(DispatchTime.now().uptimeNanoseconds - t0) / 1_000.0)
            }
            writer.writeImmediate(ByteBuffer(string: "\u{04}"))
            try await ptyTask.value
            return (rtts, burstMs, redraws)
        }

        let sLegacyRtts = legacyRtts.sorted()
        let sFastRtts = fastRtts.sorted()
        let sLegacyRedraw = legacyRedrawUs.sorted()
        let sFastRedraw = fastRedrawUs.sorted()
        print(String(format: "NIOTS legacy: 1B p50=%.1f us p95=%.1f us | 50-key burst=%.2f ms | 32KB redraw p50=%.1f us",
                     sLegacyRtts[sLegacyRtts.count/2], sLegacyRtts[Int(Double(sLegacyRtts.count-1)*0.95)], legacyBurstMs, sLegacyRedraw[sLegacyRedraw.count/2]))
        print(String(format: "NIOTS fast  : 1B p50=%.1f us p95=%.1f us | 50-key burst=%.2f ms | 32KB redraw p50=%.1f us",
                     sFastRtts[sFastRtts.count/2], sFastRtts[Int(Double(sFastRtts.count-1)*0.95)], fastBurstMs, sFastRedraw[sFastRedraw.count/2]))
    }
}
