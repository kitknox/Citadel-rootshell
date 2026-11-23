import CCryptoBoringSSL
import Foundation
import Crypto
import NIOCore
import NIOSSH

// MARK: - AES128-CTR with Encrypt-Then-MAC

public final class AES128CTR_ETM: NIOSSHTransportProtection {
    private enum Mac {
        case sha256, sha512
    }

    public static let macNames = [
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com"
    ]
    public static let cipherBlockSize = 16
    public static let cipherName = "aes128-ctr"
    public var macBytes: Int {
        keySizes.macKeySize
    }

    public static func keySizes(forMac mac: String?) throws -> ExpectedKeySizes {
        let macKeySize: Int

        switch mac {
        case "hmac-sha2-256-etm@openssh.com":
            macKeySize = SHA256.byteCount
        case "hmac-sha2-512-etm@openssh.com":
            macKeySize = SHA512.byteCount
        default:
            throw CitadelError.invalidMac
        }

        return ExpectedKeySizes(
            ivSize: 16,
            encryptionKeySize: 16, // 128 bits
            macKeySize: macKeySize
        )
    }

    private var keys: NIOSSHSessionKeys
    private var decryptionContext: UnsafeMutablePointer<EVP_CIPHER_CTX>
    private var encryptionContext: UnsafeMutablePointer<EVP_CIPHER_CTX>
    private let mac: Mac
    private let keySizes: ExpectedKeySizes

    public init(initialKeys: NIOSSHSessionKeys, mac: String?) throws {
        let keySizes = try Self.keySizes(forMac: mac)

        guard
            initialKeys.outboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8,
            initialKeys.inboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8
        else {
            throw CitadelError.invalidKeySize
        }

        switch mac {
        case "hmac-sha2-256-etm@openssh.com":
            self.mac = .sha256
        case "hmac-sha2-512-etm@openssh.com":
            self.mac = .sha512
        default:
            throw CitadelError.invalidMac
        }

        self.keys = initialKeys
        self.keySizes = keySizes
        self.encryptionContext = CCryptoBoringSSL_EVP_CIPHER_CTX_new()
        self.decryptionContext = CCryptoBoringSSL_EVP_CIPHER_CTX_new()

        let outboundEncryptionKey = initialKeys.outboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            Array(buffer.bindMemory(to: UInt8.self))
        }

        let inboundEncryptionKey = initialKeys.inboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            Array(buffer.bindMemory(to: UInt8.self))
        }

        guard CCryptoBoringSSL_EVP_CipherInit(
            encryptionContext,
            CCryptoBoringSSL_EVP_aes_128_ctr(),
            outboundEncryptionKey,
            initialKeys.initialOutboundIV,
            1
        ) == 1 else {
            throw CitadelError.cryptographicError
        }

        guard CCryptoBoringSSL_EVP_CipherInit(
            decryptionContext,
            CCryptoBoringSSL_EVP_aes_128_ctr(),
            inboundEncryptionKey,
            initialKeys.initialInboundIV,
            0
        ) == 1 else {
            throw CitadelError.cryptographicError
        }
    }

    public func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        guard
            newKeys.outboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8,
            newKeys.inboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8
        else {
            throw CitadelError.invalidKeySize
        }

        self.keys = newKeys

        let outboundEncryptionKey = newKeys.outboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            Array(buffer.bindMemory(to: UInt8.self))
        }

        let inboundEncryptionKey = newKeys.inboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            Array(buffer.bindMemory(to: UInt8.self))
        }

        guard CCryptoBoringSSL_EVP_CipherInit(
            encryptionContext,
            CCryptoBoringSSL_EVP_aes_128_ctr(),
            outboundEncryptionKey,
            newKeys.initialOutboundIV,
            1
        ) == 1 else {
            throw CitadelError.cryptographicError
        }

        guard CCryptoBoringSSL_EVP_CipherInit(
            decryptionContext,
            CCryptoBoringSSL_EVP_aes_128_ctr(),
            inboundEncryptionKey,
            newKeys.initialInboundIV,
            0
        ) == 1 else {
            throw CitadelError.cryptographicError
        }
    }

    // ETM: length field is plaintext, no decryption needed.
    // Do NOT consume AES-CTR keystream here.
    public func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        guard source.readableBytes >= Self.cipherBlockSize else {
            throw CitadelError.invalidKeySize
        }
    }

    public func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        switch mac {
        case .sha256:
            return try _decryptAndVerifyRemainingPacket(&source, hash: SHA256.self, sequenceNumber: sequenceNumber)
        case .sha512:
            return try _decryptAndVerifyRemainingPacket(&source, hash: SHA512.self, sequenceNumber: sequenceNumber)
        }
    }

    internal func _decryptAndVerifyRemainingPacket<H: HashFunction>(_ source: inout ByteBuffer, hash: H.Type, sequenceNumber: UInt32) throws -> ByteBuffer {
        // ETM wire format: [4-byte plaintext length] [ciphertext] [MAC]
        // MAC covers: seq_number || length_bytes || ciphertext
        let macSize = keySizes.macKeySize
        let ciphertextLength = source.readableBytes - 4 - macSize
        guard
            ciphertextLength > 0,
            let lengthSlice = source.readSlice(length: 4),
            let ciphertextSlice = source.readSlice(length: ciphertextLength),
            let macSlice = source.readSlice(length: macSize)
        else {
            throw CitadelError.invalidEncryptedPacketLength
        }

        // Verify MAC FIRST (Encrypt-then-MAC: verify before decryption) without allocating [UInt8] copies.
        var hmac = Crypto.HMAC<H>(key: keys.inboundMACKey)
        withUnsafeBytes(of: sequenceNumber.bigEndian) { hmac.update(data: $0) }
        lengthSlice.withUnsafeReadableBytes { hmac.update(data: $0) }
        ciphertextSlice.withUnsafeReadableBytes { hmac.update(data: $0) }

        let isValid = hmac.finalize().withUnsafeBytes { expected in
            macSlice.withUnsafeReadableBytes { received -> Bool in
                guard expected.count == received.count else { return false }
                var diff: UInt8 = 0
                for i in 0..<expected.count {
                    diff |= expected[i] ^ received[i]
                }
                return diff == 0
            }
        }

        guard isValid else {
            throw CitadelError.invalidMac
        }

        // Decrypt directly into the returned ByteBuffer (single allocation, zero intermediate [UInt8] copies).
        var output = ByteBufferAllocator().buffer(capacity: ciphertextLength)
        try output.writeWithUnsafeMutableBytes(minimumWritableBytes: ciphertextLength) { outPtr in
            try ciphertextSlice.withUnsafeReadableBytes { inPtr in
                guard CCryptoBoringSSL_EVP_Cipher(
                    decryptionContext,
                    outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    inPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    ciphertextLength
                ) == 1 else {
                    throw CitadelError.cryptographicError
                }
            }
            return ciphertextLength
        }

        // Parse: padding_length(1) || payload || padding
        guard let paddingLengthByte = output.readInteger(as: UInt8.self) else {
            throw CitadelError.invalidDecryptedPlaintextLength
        }
        let paddingLength = Int(paddingLengthByte)
        guard paddingLength <= output.readableBytes else {
            throw CitadelError.invalidDecryptedPlaintextLength
        }
        output.moveWriterIndex(to: output.writerIndex - paddingLength)
        return output
    }

    public func encryptPacket(
        _ packet: NIOSSHEncryptablePayload,
        to outboundBuffer: inout ByteBuffer,
        sequenceNumber: UInt32
    ) throws {
        switch mac {
        case .sha256:
            try _encryptPacket(packet, to: &outboundBuffer, hashFunction: SHA256.self, sequenceNumber: sequenceNumber)
        case .sha512:
            try _encryptPacket(packet, to: &outboundBuffer, hashFunction: SHA512.self, sequenceNumber: sequenceNumber)
        }
    }

    internal func _encryptPacket<H: HashFunction>(
        _ packet: NIOSSHEncryptablePayload,
        to outboundBuffer: inout ByteBuffer,
        hashFunction: H.Type,
        sequenceNumber: UInt32
    ) throws {
        // ETM format: [4-byte plaintext length] [encrypted(padding_len || payload || padding)] [MAC]
        let packetLengthIndex = outboundBuffer.writerIndex
        let packetLengthLength = MemoryLayout<UInt32>.size
        let packetPaddingLength = MemoryLayout<UInt8>.size

        // Placeholders for packet_length + padding_length, overwritten below via
        // setInteger. moveWriterIndex(forwardBy:) does not grow the buffer and traps
        // at a capacity boundary, which this buffer hits as it accumulates packets.
        outboundBuffer.writeMultipleIntegers(UInt32(0), UInt8(0))

        let payloadBytes = outboundBuffer.writeEncryptablePayload(packet)

        // ETM aligns only the encrypted body. The four-byte packet length
        // stays cleartext and is excluded from the block-size calculation.
        let contentWithoutPadding = packetPaddingLength + payloadBytes
        var paddingLength = Self.cipherBlockSize - (contentWithoutPadding % Self.cipherBlockSize)
        if paddingLength < 4 {
            paddingLength += Self.cipherBlockSize
        }

        outboundBuffer.writeSSHPaddingBytes(count: paddingLength)

        // packet_length = padding_length_byte + payload + padding
        let packetLength = packetPaddingLength + payloadBytes + paddingLength
        precondition(packetLength % Self.cipherBlockSize == 0,
                     "ETM encrypted body not block-aligned; got \(packetLength)")

        outboundBuffer.setInteger(UInt32(packetLength), at: packetLengthIndex)
        outboundBuffer.setInteger(UInt8(paddingLength), at: packetLengthIndex + packetLengthLength)

        // Encrypt in-place inside outboundBuffer and compute MAC directly over its bytes
        // without allocating temporary [UInt8] copies.
        let bodyOffset = packetLengthIndex + packetLengthLength
        let relBody = bodyOffset - outboundBuffer.readerIndex
        try outboundBuffer.withUnsafeMutableReadableBytes { rawBuf in
            let base = rawBuf.baseAddress!.assumingMemoryBound(to: UInt8.self)
            let bodyPtr = base + relBody
            guard CCryptoBoringSSL_EVP_Cipher(
                encryptionContext,
                bodyPtr,
                bodyPtr,
                packetLength
            ) == 1 else {
                throw CitadelError.cryptographicError
            }
        }

        // Compute MAC over: seq_number || plaintext_length || ciphertext
        var hmac = Crypto.HMAC<H>(key: keys.outboundMACKey)
        withUnsafeBytes(of: sequenceNumber.bigEndian) { hmac.update(data: $0) }
        outboundBuffer.withUnsafeReadableBytes { rawBuf in
            let relLen = packetLengthIndex - outboundBuffer.readerIndex
            let macRegion = UnsafeRawBufferPointer(
                start: rawBuf.baseAddress!.advanced(by: relLen),
                count: packetLengthLength + packetLength
            )
            hmac.update(data: macRegion)
        }
        let macHash = hmac.finalize()

        outboundBuffer.writeContiguousBytes(macHash)
    }

    deinit {
        CCryptoBoringSSL_EVP_CIPHER_CTX_free(encryptionContext)
        CCryptoBoringSSL_EVP_CIPHER_CTX_free(decryptionContext)
    }
}

// MARK: - AES256-CTR with Encrypt-Then-MAC

public final class AES256CTR_ETM: NIOSSHTransportProtection {
    private enum Mac {
        case sha256, sha512
    }

    public static let macNames = [
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com"
    ]
    public static let cipherBlockSize = 16
    public static let cipherName = "aes256-ctr"
    public var macBytes: Int {
        keySizes.macKeySize
    }

    public static func keySizes(forMac mac: String?) throws -> ExpectedKeySizes {
        let macKeySize: Int

        switch mac {
        case "hmac-sha2-256-etm@openssh.com":
            macKeySize = SHA256.byteCount
        case "hmac-sha2-512-etm@openssh.com":
            macKeySize = SHA512.byteCount
        default:
            throw CitadelError.invalidMac
        }

        return ExpectedKeySizes(
            ivSize: 16,
            encryptionKeySize: 32, // 256 bits
            macKeySize: macKeySize
        )
    }

    private var keys: NIOSSHSessionKeys
    private var decryptionContext: UnsafeMutablePointer<EVP_CIPHER_CTX>
    private var encryptionContext: UnsafeMutablePointer<EVP_CIPHER_CTX>
    private let mac: Mac
    private let keySizes: ExpectedKeySizes

    public init(initialKeys: NIOSSHSessionKeys, mac: String?) throws {
        let keySizes = try Self.keySizes(forMac: mac)

        guard
            initialKeys.outboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8,
            initialKeys.inboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8
        else {
            throw CitadelError.invalidKeySize
        }

        switch mac {
        case "hmac-sha2-256-etm@openssh.com":
            self.mac = .sha256
        case "hmac-sha2-512-etm@openssh.com":
            self.mac = .sha512
        default:
            throw CitadelError.invalidMac
        }

        self.keys = initialKeys
        self.keySizes = keySizes
        self.encryptionContext = CCryptoBoringSSL_EVP_CIPHER_CTX_new()
        self.decryptionContext = CCryptoBoringSSL_EVP_CIPHER_CTX_new()

        let outboundEncryptionKey = initialKeys.outboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            Array(buffer.bindMemory(to: UInt8.self))
        }

        let inboundEncryptionKey = initialKeys.inboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            Array(buffer.bindMemory(to: UInt8.self))
        }

        guard CCryptoBoringSSL_EVP_CipherInit(
            encryptionContext,
            CCryptoBoringSSL_EVP_aes_256_ctr(),
            outboundEncryptionKey,
            initialKeys.initialOutboundIV,
            1
        ) == 1 else {
            throw CitadelError.cryptographicError
        }

        guard CCryptoBoringSSL_EVP_CipherInit(
            decryptionContext,
            CCryptoBoringSSL_EVP_aes_256_ctr(),
            inboundEncryptionKey,
            initialKeys.initialInboundIV,
            0
        ) == 1 else {
            throw CitadelError.cryptographicError
        }
    }

    public func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        guard
            newKeys.outboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8,
            newKeys.inboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8
        else {
            throw CitadelError.invalidKeySize
        }

        self.keys = newKeys

        let outboundEncryptionKey = newKeys.outboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            Array(buffer.bindMemory(to: UInt8.self))
        }

        let inboundEncryptionKey = newKeys.inboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            Array(buffer.bindMemory(to: UInt8.self))
        }

        guard CCryptoBoringSSL_EVP_CipherInit(
            encryptionContext,
            CCryptoBoringSSL_EVP_aes_256_ctr(),
            outboundEncryptionKey,
            newKeys.initialOutboundIV,
            1
        ) == 1 else {
            throw CitadelError.cryptographicError
        }

        guard CCryptoBoringSSL_EVP_CipherInit(
            decryptionContext,
            CCryptoBoringSSL_EVP_aes_256_ctr(),
            inboundEncryptionKey,
            newKeys.initialInboundIV,
            0
        ) == 1 else {
            throw CitadelError.cryptographicError
        }
    }

    // ETM: length field is plaintext, no decryption needed.
    // Do NOT consume AES-CTR keystream here.
    public func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        guard source.readableBytes >= Self.cipherBlockSize else {
            throw CitadelError.invalidKeySize
        }
    }

    public func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        switch mac {
        case .sha256:
            return try _decryptAndVerifyRemainingPacket(&source, hash: SHA256.self, sequenceNumber: sequenceNumber)
        case .sha512:
            return try _decryptAndVerifyRemainingPacket(&source, hash: SHA512.self, sequenceNumber: sequenceNumber)
        }
    }

    internal func _decryptAndVerifyRemainingPacket<H: HashFunction>(_ source: inout ByteBuffer, hash: H.Type, sequenceNumber: UInt32) throws -> ByteBuffer {
        // ETM wire format: [4-byte plaintext length] [ciphertext] [MAC]
        // MAC covers: seq_number || length_bytes || ciphertext
        let macSize = keySizes.macKeySize
        let ciphertextLength = source.readableBytes - 4 - macSize
        guard
            ciphertextLength > 0,
            let lengthSlice = source.readSlice(length: 4),
            let ciphertextSlice = source.readSlice(length: ciphertextLength),
            let macSlice = source.readSlice(length: macSize)
        else {
            throw CitadelError.invalidEncryptedPacketLength
        }

        // Verify MAC FIRST (Encrypt-then-MAC: verify before decryption) without allocating [UInt8] copies.
        var hmac = Crypto.HMAC<H>(key: keys.inboundMACKey)
        withUnsafeBytes(of: sequenceNumber.bigEndian) { hmac.update(data: $0) }
        lengthSlice.withUnsafeReadableBytes { hmac.update(data: $0) }
        ciphertextSlice.withUnsafeReadableBytes { hmac.update(data: $0) }

        let isValid = hmac.finalize().withUnsafeBytes { expected in
            macSlice.withUnsafeReadableBytes { received -> Bool in
                guard expected.count == received.count else { return false }
                var diff: UInt8 = 0
                for i in 0..<expected.count {
                    diff |= expected[i] ^ received[i]
                }
                return diff == 0
            }
        }

        guard isValid else {
            throw CitadelError.invalidMac
        }

        // Decrypt directly into the returned ByteBuffer (single allocation, zero intermediate [UInt8] copies).
        var output = ByteBufferAllocator().buffer(capacity: ciphertextLength)
        try output.writeWithUnsafeMutableBytes(minimumWritableBytes: ciphertextLength) { outPtr in
            try ciphertextSlice.withUnsafeReadableBytes { inPtr in
                guard CCryptoBoringSSL_EVP_Cipher(
                    decryptionContext,
                    outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    inPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    ciphertextLength
                ) == 1 else {
                    throw CitadelError.cryptographicError
                }
            }
            return ciphertextLength
        }

        // Parse: padding_length(1) || payload || padding
        guard let paddingLengthByte = output.readInteger(as: UInt8.self) else {
            throw CitadelError.invalidDecryptedPlaintextLength
        }
        let paddingLength = Int(paddingLengthByte)
        guard paddingLength <= output.readableBytes else {
            throw CitadelError.invalidDecryptedPlaintextLength
        }
        output.moveWriterIndex(to: output.writerIndex - paddingLength)
        return output
    }

    public func encryptPacket(
        _ packet: NIOSSHEncryptablePayload,
        to outboundBuffer: inout ByteBuffer,
        sequenceNumber: UInt32
    ) throws {
        switch mac {
        case .sha256:
            try _encryptPacket(packet, to: &outboundBuffer, hashFunction: SHA256.self, sequenceNumber: sequenceNumber)
        case .sha512:
            try _encryptPacket(packet, to: &outboundBuffer, hashFunction: SHA512.self, sequenceNumber: sequenceNumber)
        }
    }

    internal func _encryptPacket<H: HashFunction>(
        _ packet: NIOSSHEncryptablePayload,
        to outboundBuffer: inout ByteBuffer,
        hashFunction: H.Type,
        sequenceNumber: UInt32
    ) throws {
        // ETM format: [4-byte plaintext length] [encrypted(padding_len || payload || padding)] [MAC]
        let packetLengthIndex = outboundBuffer.writerIndex
        let packetLengthLength = MemoryLayout<UInt32>.size
        let packetPaddingLength = MemoryLayout<UInt8>.size

        // Placeholders for packet_length + padding_length, overwritten below via
        // setInteger. moveWriterIndex(forwardBy:) does not grow the buffer and traps
        // at a capacity boundary, which this buffer hits as it accumulates packets.
        outboundBuffer.writeMultipleIntegers(UInt32(0), UInt8(0))

        let payloadBytes = outboundBuffer.writeEncryptablePayload(packet)

        // ETM aligns only the encrypted body. The four-byte packet length
        // stays cleartext and is excluded from the block-size calculation.
        let contentWithoutPadding = packetPaddingLength + payloadBytes
        var paddingLength = Self.cipherBlockSize - (contentWithoutPadding % Self.cipherBlockSize)
        if paddingLength < 4 {
            paddingLength += Self.cipherBlockSize
        }

        outboundBuffer.writeSSHPaddingBytes(count: paddingLength)

        // packet_length = padding_length_byte + payload + padding
        let packetLength = packetPaddingLength + payloadBytes + paddingLength
        precondition(packetLength % Self.cipherBlockSize == 0,
                     "ETM encrypted body not block-aligned; got \(packetLength)")

        outboundBuffer.setInteger(UInt32(packetLength), at: packetLengthIndex)
        outboundBuffer.setInteger(UInt8(paddingLength), at: packetLengthIndex + packetLengthLength)

        // Encrypt in-place inside outboundBuffer and compute MAC directly over its bytes
        // without allocating temporary [UInt8] copies.
        let bodyOffset = packetLengthIndex + packetLengthLength
        let relBody = bodyOffset - outboundBuffer.readerIndex
        try outboundBuffer.withUnsafeMutableReadableBytes { rawBuf in
            let base = rawBuf.baseAddress!.assumingMemoryBound(to: UInt8.self)
            let bodyPtr = base + relBody
            guard CCryptoBoringSSL_EVP_Cipher(
                encryptionContext,
                bodyPtr,
                bodyPtr,
                packetLength
            ) == 1 else {
                throw CitadelError.cryptographicError
            }
        }

        // Compute MAC over: seq_number || plaintext_length || ciphertext
        var hmac = Crypto.HMAC<H>(key: keys.outboundMACKey)
        withUnsafeBytes(of: sequenceNumber.bigEndian) { hmac.update(data: $0) }
        outboundBuffer.withUnsafeReadableBytes { rawBuf in
            let relLen = packetLengthIndex - outboundBuffer.readerIndex
            let macRegion = UnsafeRawBufferPointer(
                start: rawBuf.baseAddress!.advanced(by: relLen),
                count: packetLengthLength + packetLength
            )
            hmac.update(data: macRegion)
        }
        let macHash = hmac.finalize()

        outboundBuffer.writeContiguousBytes(macHash)
    }

    deinit {
        CCryptoBoringSSL_EVP_CIPHER_CTX_free(encryptionContext)
        CCryptoBoringSSL_EVP_CIPHER_CTX_free(decryptionContext)
    }
}
