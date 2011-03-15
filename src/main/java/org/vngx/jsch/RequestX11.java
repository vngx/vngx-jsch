/*
 * Copyright (c) 2002-2010 Atsuhiko Yamanaka, JCraft,Inc.  All rights reserved.
 * Copyright (c) 2010-2011 Michael Laudati, N1 Concepts LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. The names of the authors may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
 * INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch;

/**
 * <p>Implementation of <code>Request</code> to send a X11 request.</p>
 *
 * <p>X11 forwarding may be requested for a session by sending a
 * SSH_MSG_CHANNEL_REQUEST message.  It is recommended that the
 * 'x11 authentication cookie' that is sent be a fake, random cookie, and that
 * the cookie be checked and replaced by the real cookie when a connection
 * request is received.</p>
 *
 * <p>X11 connection forwarding should stop when the session channel is closed.
 * However, already opened forwardings should not be automatically closed when
 * the session channel is closed.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4254">RFC 4254 - The Secure Shell
 * (SSH) Connection Protocol</a></p>
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
final class RequestX11 extends Request {

	/** Constant name for X11 forwarding request. */
	static final String X11_REQUEST = "x11-req";
	/** Constant name for X11 authentication protocol. */
	static final String X11_MIT_MAGIC_COOKIE = "MIT-MAGIC-COOKIE-1";

	@Override
	void request(Session session, Channel channel) throws Exception {
		super.request(session, channel);

		// byte      SSH_MSG_CHANNEL_REQUEST(98)
		// uint32    recipient channel
		// string    request type        // "x11-req"
		// boolean   want reply          // 0
		// boolean   single connection
		// string    x11 authentication protocol // "MIT-MAGIC-COOKIE-1".
		// string    x11 authentication cookie
		// uint32    x11 screen number
		Buffer buffer = new Buffer(1024);
		Packet packet = new Packet(buffer);
		packet.reset();
		buffer.putByte(SSH_MSG_CHANNEL_REQUEST);
		buffer.putInt(channel.getRecipient());
		buffer.putString(X11_REQUEST);
		buffer.putBoolean(waitForReply());
		buffer.putByte((byte) 0);	// TODO Allow value to be set (single connection)
		buffer.putString(X11_MIT_MAGIC_COOKIE);
		buffer.putString(ChannelX11.getFakedCookie(session));
		buffer.putInt(0);
		write(packet);
		session._x11Forwarding = true;	// Update session X11 forwarding is allowed
	}

}
