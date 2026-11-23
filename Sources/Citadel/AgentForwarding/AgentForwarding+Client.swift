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

extension SSHClient {
    /// Enables SSH agent forwarding for this connection.
    ///
    /// This method:
    /// 1. Registers a handler for incoming agent channels
    /// 2. Sends an `auth-agent-req@openssh.com` request to enable agent forwarding
    ///
    /// After calling this method, the server can open agent channels back to the client,
    /// which will be handled by the provided delegate.
    ///
    /// - Parameters:
    ///   - delegate: The delegate to handle agent operations (identity listing and signing).
    ///   - channel: The session channel on which to request agent forwarding.
    /// - Throws: If the agent forwarding request fails.
    public func enableAgentForwarding(
        delegate: SSHAgentDelegate,
        on channel: Channel
    ) async throws {
        // Capture the session's inbound handler up front so an automatic
        // reconnect replacing `self.session` during the await below cannot
        // cause cleanup/pruning to touch the new session's token namespace.
        let inboundHandler = session.inboundChannelHandler
        let ownerID = ObjectIdentifier(channel)
        // Register the agent channel handler with a token so failure or channel
        // close cleans up only this registration, and repeated calls on the same
        // channel prune older superseded delegates once the new request succeeds.
        let token = inboundHandler.registerAgentHandler(ownerID: ownerID) { [allocator = channel.allocator] agentChannel in
            let handler = AgentChannelHandler(delegate: delegate, allocator: allocator)
            return agentChannel.pipeline.addHandler(handler)
        }

        // Send auth-agent-req@openssh.com request on the session channel
        // Use wantReply: false because a failure response would terminate the PTY session
        // The server will simply not open agent channels if it doesn't support forwarding
        let request = SSHChannelRequestEvent.AuthAgentRequest(wantReply: false)
        do {
            try await channel.triggerUserOutboundEvent(request).get()
        } catch {
            inboundHandler.rollbackAgentHandler(token: token)
            throw error
        }

        inboundHandler.pruneAgentHandlers(forOwner: ownerID, keeping: token)
        channel.closeFuture.whenComplete { _ in
            inboundHandler.rollbackAgentHandler(token: token)
        }
    }

    /// Disables SSH agent forwarding for this connection.
    ///
    /// This unregisters the agent handler, so new agent channels will be rejected.
    /// Existing agent channels are not affected.
    public func disableAgentForwarding() {
        session.inboundChannelHandler.unregisterAgentHandler()
    }
}
