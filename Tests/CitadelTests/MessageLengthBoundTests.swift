@testable import Citadel
import NIO
import NIOSSH
import XCTest

/// Peer-supplied length fields must be bounded before the decoders buffer on them.
final class MessageLengthBoundTests: XCTestCase {
    func testSFTPZeroLengthIsRejected() throws {
        let channel = EmbeddedChannel(handler: ByteToMessageHandler(SFTPMessageParser()))
        defer { XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true)) }
        var buffer = channel.allocator.buffer(capacity: 8)
        buffer.writeInteger(UInt32(0))
        buffer.writeInteger(UInt8(SFTPMessageType.version.rawValue))
        buffer.writeInteger(UInt32(3))

        XCTAssertThrowsError(try channel.writeInbound(buffer)) { error in
            guard case SFTPError.invalidMessageLength(0) = error else {
                return XCTFail("Unexpected error \(error)")
            }
        }
    }

    func testSFTPOversizedLengthIsRejected() throws {
        let channel = EmbeddedChannel(handler: ByteToMessageHandler(SFTPMessageParser()))
        defer { XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true)) }
        var buffer = channel.allocator.buffer(capacity: 8)
        buffer.writeInteger(UInt32.max)
        buffer.writeInteger(UInt8(SFTPMessageType.data.rawValue))

        XCTAssertThrowsError(try channel.writeInbound(buffer)) { error in
            guard case SFTPError.invalidMessageLength(.max) = error else {
                return XCTFail("Unexpected error \(error)")
            }
        }
    }

    func testSFTPMessageAtLimitStillBuffers() throws {
        let channel = EmbeddedChannel(handler: ByteToMessageHandler(SFTPMessageParser()))
        defer { XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true)) }
        var buffer = channel.allocator.buffer(capacity: 8)
        buffer.writeInteger(SFTPMessageParser.maxMessageLength)
        buffer.writeInteger(UInt8(SFTPMessageType.data.rawValue))

        XCTAssertNoThrow(try channel.writeInbound(buffer))
        XCTAssertNil(try channel.readInbound(as: SFTPMessage.self))
    }

    func testAgentOversizedLengthClosesChannel() throws {
        let channel = EmbeddedChannel(handler: AgentChannelHandler(delegate: NoKeysAgent()))
        defer { XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true)) }
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
        XCTAssertTrue(channel.isActive)

        var buffer = channel.allocator.buffer(capacity: 4)
        buffer.writeInteger(AgentChannelHandler.maxMessageLength + 1)
        try channel.writeInbound(SSHChannelData(type: .channel, data: .byteBuffer(buffer)))

        XCTAssertFalse(channel.isActive)
    }
}

private struct NoKeysAgent: SSHAgentDelegate {
    func listIdentities() async throws -> [SSHAgentIdentity] { [] }

    func sign(publicKeyBlob: ByteBuffer, data: ByteBuffer, flags: UInt32) async throws -> ByteBuffer? {
        nil
    }
}
