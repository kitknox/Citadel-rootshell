@testable import Citadel
import NIO
import NIOEmbedded
import NIOSSH
import NIOConcurrencyHelpers
import XCTest

/// Forwarded-agent requests must each get a reply, in order: OpenSSH's agent answers anything it
/// doesn't support with SSH_AGENT_FAILURE, and a client waiting on silence hangs.
final class AgentChannelHandlerTests: XCTestCase {
    private func request(_ type: UInt8, payload: [UInt8] = []) -> SSHChannelData {
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt32(1 + payload.count))
        buffer.writeInteger(type)
        buffer.writeBytes(payload)
        return SSHChannelData(type: .channel, data: .byteBuffer(buffer))
    }

    private func replyType(_ data: SSHChannelData) -> UInt8? {
        guard case .byteBuffer(let buffer) = data.data else { return nil }
        return buffer.getInteger(at: buffer.readerIndex + 4, as: UInt8.self)
    }

    func testUnsupportedRequestsGetFailureInOrder() async throws {
        let channel = NIOAsyncTestingChannel()
        try await channel.pipeline.addHandler(AgentChannelHandler(delegate: SlowNoKeysAgent()))

        // SSH_AGENTC_REQUEST_IDENTITIES (slow), ADD_IDENTITY (17), REMOVE_ALL (19), unknown (250).
        try await channel.writeInbound(request(11))
        try await channel.writeInbound(request(17, payload: [0, 0, 0, 0]))
        try await channel.writeInbound(request(19))
        try await channel.writeInbound(request(250))

        var replies: [UInt8?] = []
        for _ in 0..<4 {
            replies.append(replyType(try await channel.waitForOutboundWrite(as: SSHChannelData.self)))
        }
        // IDENTITIES_ANSWER (12) first despite being slowest, then three SSH_AGENT_FAILURE (5).
        XCTAssertEqual(replies, [12, 5, 5, 5])
        _ = try await channel.finish(acceptAlreadyClosed: true)
    }

    // Disconnecting while a request awaits approval must not run the ones queued behind it.
    func testQueuedRequestsAreDroppedOnClose() async throws {
        let agent = CountingSlowAgent()
        let channel = NIOAsyncTestingChannel()
        try await channel.pipeline.addHandler(AgentChannelHandler(delegate: agent))
        try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0))

        for _ in 0..<3 {
            try await channel.writeInbound(request(11))
        }
        try await channel.close()
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(agent.calls.withLockedValue { $0 }, 1)
    }
}

private final class CountingSlowAgent: SSHAgentDelegate {
    let calls = NIOLockedValueBox(0)

    func listIdentities() async throws -> [SSHAgentIdentity] {
        calls.withLockedValue { $0 += 1 }
        try? await Task.sleep(nanoseconds: 50_000_000)
        return []
    }

    func sign(publicKeyBlob: ByteBuffer, data: ByteBuffer, flags: UInt32) async throws -> ByteBuffer? {
        nil
    }
}

private struct SlowNoKeysAgent: SSHAgentDelegate {
    func listIdentities() async throws -> [SSHAgentIdentity] {
        try await Task.sleep(nanoseconds: 50_000_000)
        return []
    }

    func sign(publicKeyBlob: ByteBuffer, data: ByteBuffer, flags: UInt32) async throws -> ByteBuffer? {
        nil
    }
}
