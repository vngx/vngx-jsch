/*
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
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL N1
 * CONCEPTS LLC OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch.exception;

import org.vngx.jsch.constants.TransportLayerProtocol;

/**
 * <p>General exception class for vngx-jsch library which maintains a reason
 * code sent to the server with the SSH_MSG_DISCONNET packet specifying why the
 * client is disconnecting from the server.  The standard disconnect reason
 * codes are specified in RFC 4253.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-11.1">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: Disconnection Message</a></p>
 *
 * @author Michael Laudati
 */
public class JSchException extends Exception {

	/** 
	 * <p>Disconnect reason code sent to server for this error.</p>
	 * 
	 * @see org.vngx.jsch.constants.TransportLayerProtocol
	 */
	protected final int _disconnectReason;


	/**
	 * Creates a new instance of <code>JSchException</code>.
	 */
	public JSchException() {
		this(TransportLayerProtocol.SSH_DISCONNECT_BY_APPLICATION);
	}

	/**
	 * Creates a new instance of <code>JSchException</code> with the specified
	 * disconnect reason code.
	 *
	 * @param disconnectReason code sent to server
	 */
	public JSchException(int disconnectReason) {
		_disconnectReason = disconnectReason;
	}

	/**
	 * Creates a new instance of <code>JSchException</code> with the specified
	 * message.
	 *
	 * @param message
	 */
	public JSchException(String message) {
		this(message, TransportLayerProtocol.SSH_DISCONNECT_BY_APPLICATION);
	}

	/**
	 * Creates a new instance of <code>JSchException</code> with the specified
	 * message and disconnect reason code.
	 *
	 * @param message
	 * @param disconnectReason code sent to server
	 */
	public JSchException(String message, int disconnectReason) {
		super(message);
		_disconnectReason = disconnectReason;
	}

	/**
	 * Creates a new instance of <code>JSchException</code> with the specified
	 * message and cause.
	 *
	 * @param message
	 * @param cause
	 */
	public JSchException(String message, Throwable cause) {
		this(message, cause, TransportLayerProtocol.SSH_DISCONNECT_BY_APPLICATION);
	}

	/**
	 * Creates a new instance of <code>JSchException</code> with the specified
	 * message and cause.
	 *
	 * @param message
	 * @param cause
	 * @param disconnectReason code sent to server
	 */
	public JSchException(String message, Throwable cause, int disconnectReason) {
		super(message, cause);
		_disconnectReason = disconnectReason;
	}

	/**
	 * Returns the disconnect reason code sent to the server for this error.
	 * 
	 * @return disconnect reason code
	 */
	public int getDisconnectReason() {
		return _disconnectReason;
	}

}
