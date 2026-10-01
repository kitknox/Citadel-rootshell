import Foundation
import NIO
import XCTest
import Citadel

/// Drives the system `sftp-server` over plain pipes to check `listDirectory`:
/// listings spanning several READDIR replies, relative paths, missing folders,
/// and that directory handles are closed rather than left open in the server.
final class SFTPListDirectoryTests: XCTestCase {
    private static let serverPath = "/usr/libexec/sftp-server"

    private var group: MultiThreadedEventLoopGroup!
    private var process: Process!
    private var sftp: SFTPClient!
    private var root: String!

    override func setUp() async throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: Self.serverPath))
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("citadel-list-\(UUID().uuidString)").path
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

    func testListsEveryEntryAcrossReplies() async throws {
        // sftp-server returns at most 100 names per READDIR reply.
        for index in 0..<250 {
            FileManager.default.createFile(atPath: "\(root!)/file-\(index)", contents: nil)
        }
        let names = try await sftp.listDirectory(atPath: root).flatMap(\.components).map(\.filename)
        XCTAssertEqual(Set(names), Set((0..<250).map { "file-\($0)" } + [".", ".."]))
    }

    func testListsRelativePath() async throws {
        try FileManager.default.createDirectory(atPath: "\(root!)/sub", withIntermediateDirectories: false)
        FileManager.default.createFile(atPath: "\(root!)/sub/inside", contents: nil)
        let names = try await sftp.listDirectory(atPath: "sub").flatMap(\.components).map(\.filename)
        XCTAssertTrue(names.contains("inside"))
    }

    func testEmptyPathListsWorkingDirectory() async throws {
        // REALPATH treats "" as the working directory, but OPENDIR("") fails
        // with ENOENT, so the empty path has to be mapped before opening.
        FileManager.default.createFile(atPath: "\(root!)/in-cwd", contents: nil)
        let names = try await sftp.listDirectory(atPath: "").flatMap(\.components).map(\.filename)
        XCTAssertTrue(names.contains("in-cwd"))
    }

    func testMissingFolderThrowsNoSuchFile() async throws {
        do {
            _ = try await sftp.listDirectory(atPath: "\(root!)/missing")
            XCTFail("Listing a missing folder succeeded")
        } catch let status as SFTPMessage.Status {
            XCTAssertEqual(status.errorCode, .noSuchFile)
        }
    }

    func testClosesDirectoryHandles() async throws {
        let before = try openDescriptors(of: process.processIdentifier)
        for _ in 0..<50 {
            _ = try await sftp.listDirectory(atPath: root)
        }
        // `listDirectory` sends its close without waiting for it, so give the
        // closes a moment to reach the server.
        var after = Int.max
        for _ in 0..<20 where after - before >= 5 {
            try await Task.sleep(nanoseconds: 50_000_000)
            _ = try await sftp.getAttributes(at: root)
            after = try openDescriptors(of: process.processIdentifier)
        }
        XCTAssertLessThan(after - before, 5, "sftp-server kept \(after - before) directory handles open")
    }

    private func openDescriptors(of pid: Int32) throws -> Int {
        let lsof = Process()
        let output = Pipe()
        lsof.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        lsof.arguments = ["-p", String(pid)]
        lsof.standardOutput = output
        try lsof.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        lsof.waitUntilExit()
        return String(decoding: data, as: UTF8.self).split(separator: "\n").count
    }
}
