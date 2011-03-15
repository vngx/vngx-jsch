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

import org.vngx.jsch.constants.ConnectionProtocol;
import org.vngx.jsch.exception.JSchException;

/**
 * <p>Base implementation of a SSH request which sends a request packet over the
 * session to the specific channel and optionally waits for a response.</p>
 *
 * <p>After the key exchange, the client requests a service.  The service is
 * identified by a name.
 * <pre>
 *		byte      SSH_MSG_SERVICE_REQUEST
 *		string    service name
 * </pre></p>
 *
 * <p>If the server rejects the service request, it SHOULD send an appropriate
 * SSH_MSG_DISCONNECT message and MUST disconnect.  When the service starts, it
 * may have access to the session identifier generated during the key exchange.
 * If the server supports the service (and permits the client to use it), it
 * MUST respond with the following:
 * <pre>
 *		byte      SSH_MSG_SERVICE_ACCEPT
 *		string    service name
 * </pre></p>
 *
 * <p>Message numbers used by services should be in the area reserved for them.
 * The transport level will continue to process its own messages.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4254">RFC 4254 - The Secure Shell
 * (SSH) Connection Protocol</a></p>
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
abstract class Request implements ConnectionProtocol {

	/** True if the request waits for a reply from server. */
	private boolean _reply = false;
	/** Session to send request through. */
	private Session _session;
	/** Channel to send request for. */
	private Channel _channel;


	/**
	 * Uses the specified {@code session} and {@code channel} to make the
	 * request to server.  Implementations should override this method to
	 * implement request specific logic.
	 *
	 * @param session
	 * @param channel
	 * @throws Exception
	 */
	void request(Session session, Channel channel) throws Exception {
		_session = session;
		_channel = channel;
		// TODO Why FORCE set reply to true if channel has a timeout?!?
		if( channel._connectTimeout > 0 ) {
			setReply(true);
		}
	}

	/**
	 * Returns {@code true} if the request should wait for a reply from the
	 * server.
	 *
	 * @return true if request waits for reply from server
	 */
	final boolean waitForReply() {
		return _reply;
	}

	/**
	 * Sets if the request will wait for a reply from the server.
	 *
	 * @param reply
	 */
	final void setReply(boolean reply) {
		_reply = reply;
	}

	/**
	 * Writes the specified SSH packet to the session through the channel.
	 *
	 * If the request has been set to wait for a reply, then the calling thread
	 * will wait for a reply from the server.  The response from the server is
	 * received in the underlying session and the channel's reply value is set
	 * to 1 for a request success or 0 for a request failure.  The connection's
	 * timeout value in milliseconds is used to determine the timeout for
	 * waiting for a reply (0 or less timeout indicates no timeout).
	 *
	 * @param packet to write
	 * @throws Exception if any errors occur
	 */
	final void write(final Packet packet) throws Exception {
		if( _reply ) {				// Reset channel's reply to -1, reply will be
			_channel._reply = -1;	// set by the session when response is received
		}							// to 1 for success or 0 for failure
		_session.write(packet);
		if( _reply ) {
			long start = System.currentTimeMillis();
			long timeout = _channel._connectTimeout;
			while( _channel.isConnected() && _channel._reply == -1 ) {	// reply will be changed by session
				try {
					Thread.sleep(10);
				} catch(InterruptedException e) { /* Ignore error. */ }
				if( timeout > 0L && (System.currentTimeMillis() - start) > timeout ) {
					_channel._reply = 0;
					throw new JSchException("Channel request timed out after "+_channel._connectTimeout+"ms, "+getClass().getSimpleName());
				}
			}
			if( _channel._reply == 0 ) {	// Should this be an exception?
				throw new JSchException("Server responded with failure for channel request, "+getClass().getSimpleName());
			}
		}
	}

}
