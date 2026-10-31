@testable import Citadel
import NIO
import NIOEmbedded
import NIOSSH
import NIOConcurrencyHelpers
import XCTest

/// Env request replies carry no request id, so they must leave in arrival order, refusals included.
final class ExecHandlerEnvironmentTests: XCTestCase {
    func testRefusalWaitsForSuspendedSetter() async throws {
        let recorder = OutboundEventRecorder()
        let delegate = SlowEnvironmentDelegate()
        let channel = NIOAsyncTestingChannel()
        try await channel.pipeline.addHandlers([recorder, ExecHandler(delegate: delegate, username: nil)])

        // Valid (setter suspends), then oversized (refused): replies must be success, failure.
        channel.pipeline.fireUserInboundEventTriggered(
            SSHChannelRequestEvent.EnvironmentRequest(wantReply: true, name: "LANG", value: "C")
        )
        channel.pipeline.fireUserInboundEventTriggered(
            SSHChannelRequestEvent.EnvironmentRequest(wantReply: true, name: String(repeating: "N", count: 3000), value: "x")
        )

        for _ in 0..<100 where recorder.replies.withLockedValue({ $0.count }) < 2 {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(recorder.replies.withLockedValue { $0 }, ["success", "failure"])
        XCTAssertEqual(delegate.keys.withLockedValue { $0 }, ["LANG"])
        _ = try? await channel.finish(acceptAlreadyClosed: true)
    }

    func testOverflowingQueueClosesChannelAndSilentRefusalsAreDropped() async throws {
        let delegate = SlowEnvironmentDelegate(setterDelay: 1_000_000_000)
        let channel = NIOAsyncTestingChannel()
        try await channel.pipeline.addHandler(ExecHandler(delegate: delegate, username: nil))
        try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0))
        let oversized = String(repeating: "N", count: 3000)

        channel.pipeline.fireUserInboundEventTriggered(
            SSHChannelRequestEvent.EnvironmentRequest(wantReply: false, name: "LANG", value: "C")
        )
        // Refusals nobody waits on queue nothing, however many arrive.
        for _ in 0..<500 {
            channel.pipeline.fireUserInboundEventTriggered(
                SSHChannelRequestEvent.EnvironmentRequest(wantReply: false, name: oversized, value: "x")
            )
        }
        try await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertTrue(channel.isActive)

        // Refusals that owe a reply queue behind the slow setter, up to the cap.
        for _ in 0..<ExecHandler.maxPendingEnvironmentRequests {
            channel.pipeline.fireUserInboundEventTriggered(
                SSHChannelRequestEvent.EnvironmentRequest(wantReply: true, name: oversized, value: "x")
            )
        }
        for _ in 0..<100 where channel.isActive {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertFalse(channel.isActive)
        _ = try? await channel.finish(acceptAlreadyClosed: true)
    }

    /// `exec` bootstraps a real pipe, so these run on a real event loop.
    private func makePipeChannel(group: EventLoopGroup) async throws -> (Channel, [Pipe]) {
        let input = Pipe()
        let output = Pipe()
        let channel = try await NIOPipeBootstrap(group: group)
            .takingOwnershipOfDescriptors(
                input: dup(input.fileHandleForReading.fileDescriptor),
                output: dup(output.fileHandleForWriting.fileDescriptor)
            ).get()
        return (channel, [input, output])
    }

    func testExecDoesNotStartAfterCloseDuringEnvironmentSetup() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let delegate = SlowEnvironmentDelegate(setterDelay: 300_000_000)
        let (channel, pipes) = try await makePipeChannel(group: group)
        try await channel.pipeline.addHandler(ExecHandler(delegate: delegate, username: nil))

        channel.pipeline.fireUserInboundEventTriggered(
            SSHChannelRequestEvent.EnvironmentRequest(wantReply: false, name: "LANG", value: "C")
        )
        channel.pipeline.fireUserInboundEventTriggered(SSHChannelRequestEvent.ExecRequest(command: "true", wantReply: false))
        try await Task.sleep(nanoseconds: 50_000_000)
        try await channel.close()
        try await Task.sleep(nanoseconds: 600_000_000)

        XCTAssertEqual(delegate.starts.withLockedValue { $0 }, 0)
        withExtendedLifetime(pipes) {}
        try await group.shutdownGracefully()
    }

    func testCommandStartedAfterCloseIsTerminated() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let delegate = SlowEnvironmentDelegate(setterDelay: 0, startDelay: 300_000_000)
        let (channel, pipes) = try await makePipeChannel(group: group)
        try await channel.pipeline.addHandler(ExecHandler(delegate: delegate, username: nil))

        channel.pipeline.fireUserInboundEventTriggered(SSHChannelRequestEvent.ExecRequest(command: "true", wantReply: false))
        try await Task.sleep(nanoseconds: 100_000_000)
        try await channel.close()
        try await Task.sleep(nanoseconds: 600_000_000)

        XCTAssertEqual(delegate.starts.withLockedValue { $0 }, 1)
        XCTAssertEqual(delegate.terminations.withLockedValue { $0 }, 1)
        withExtendedLifetime(pipes) {}
        try await group.shutdownGracefully()
    }
}

private final class OutboundEventRecorder: ChannelOutboundHandler, @unchecked Sendable {
    typealias OutboundIn = Any

    let replies = NIOLockedValueBox<[String]>([])

    func triggerUserOutboundEvent(context: ChannelHandlerContext, event: Any, promise: EventLoopPromise<Void>?) {
        switch event {
        case is ChannelSuccessEvent: replies.withLockedValue { $0.append("success") }
        case is ChannelFailureEvent: replies.withLockedValue { $0.append("failure") }
        default: break
        }
        promise?.succeed(())
    }
}

private final class SlowEnvironmentDelegate: ExecDelegate {
    let keys = NIOLockedValueBox<[String]>([])
    let starts = NIOLockedValueBox(0)
    let terminations = NIOLockedValueBox(0)
    private let setterDelay: UInt64
    private let startDelay: UInt64

    init(setterDelay: UInt64 = 100_000_000, startDelay: UInt64 = 0) {
        self.setterDelay = setterDelay
        self.startDelay = startDelay
    }

    func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
        starts.withLockedValue { $0 += 1 }
        try await Task.sleep(nanoseconds: startDelay)
        return CountingCommandContext(terminations: terminations)
    }

    func setEnvironmentValue(_ value: String, forKey key: String) async throws {
        try await Task.sleep(nanoseconds: setterDelay)
        keys.withLockedValue { $0.append(key) }
    }
}

private struct CountingCommandContext: ExecCommandContext {
    let terminations: NIOLockedValueBox<Int>

    func terminate() async throws {
        terminations.withLockedValue { $0 += 1 }
    }
}
