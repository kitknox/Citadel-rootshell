import Foundation
import NIO
import XCTest
import Citadel

/// Drives the system `sftp-server` over plain pipes to check handle- and link-level
/// attribute changes (cf. OpenSSH bc01263f1) and the single-name REALPATH reply.
final class SFTPSetAttributesTests: XCTestCase {
    private static let serverPath = "/usr/libexec/sftp-server"

    private var group: MultiThreadedEventLoopGroup!
    private var process: Process!
    private var sftp: SFTPClient!
    private var root: String!

    override func setUp() async throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: Self.serverPath))
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("citadel-attrs-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)

        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        process = Process()
        let toServer = Pipe()
        let fromServer = Pipe()
        process.executableURL = URL(fileURLWithPath: Self.serverPath)
        process.currentDirectoryURL = URL(fileURLWithPath: root)
        process.standardInput = toServer
        process.standardOutput = fromServer
        try process.run()

        let channel = try await NIOPipeBootstrap(group: group)
            .takingOwnershipOfDescriptors(
                input: dup(fromServer.fileHandleForReading.fileDescriptor),
                output: dup(toServer.fileHandleForWriting.fileDescriptor)
            ).get()
        sftp = try await SFTPClient.connect(rawChannel: channel)
    }

    override func tearDown() async throws {
        try? await sftp?.close()
        process?.terminate()
        try? await group?.shutdownGracefully()
        if let root { try? FileManager.default.removeItem(atPath: root) }
    }

    private func mode(of path: String, followingLinks: Bool = true) throws -> UInt16 {
        var info = stat()
        let result = followingLinks ? stat(path, &info) : lstat(path, &info)
        guard result == 0 else { throw POSIXError(.ENOENT) }
        return info.st_mode & 0o7777
    }

    func testFileHandleSetAttributes() async throws {
        let path = "\(root!)/file"
        let file = try await sftp.openFile(filePath: path, flags: [.write, .create, .truncate])
        try await file.write(ByteBuffer(string: "hello"))
        var attributes = SFTPFileAttributes()
        attributes.permissions = 0o640
        try await file.setAttributes(attributes)
        try await file.close()
        XCTAssertEqual(try mode(of: path), 0o640)
    }

    func testLinkSetAttributesDoesNotFollowSymlink() async throws {
        XCTAssertTrue(sftp.supportsLinkSetStat)
        let target = "\(root!)/target"
        let link = "\(root!)/link"
        FileManager.default.createFile(atPath: target, contents: nil, attributes: [.posixPermissions: 0o600])
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)

        var attributes = SFTPFileAttributes()
        attributes.permissions = 0o755
        try await sftp.setLinkAttributes(at: link, attributes: attributes)
        XCTAssertEqual(try mode(of: target), 0o600)
    }

    func testReadAllReturnsWholeFile() async throws {
        let contents = String(repeating: "abcdef", count: 50_000)
        FileManager.default.createFile(atPath: "\(root!)/big", contents: Data(contents.utf8))
        let data = try await sftp.withFile(filePath: "\(root!)/big", flags: .read) { try await $0.readAll() }
        XCTAssertEqual(String(buffer: data), contents)
    }

    func testRealPathResolvesSingleName() async throws {
        let resolved = try await sftp.getRealPath(atPath: ".")
        XCTAssertEqual(URL(fileURLWithPath: resolved).resolvingSymlinksInPath().path,
                       URL(fileURLWithPath: root).resolvingSymlinksInPath().path)
    }
}
