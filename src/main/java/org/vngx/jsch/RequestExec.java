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
 * <p>Implementation of <code>Request</code> for sending an exec request to
 * execute a command over a session channel.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4254">RFC 4254 - The Secure Shell
 * (SSH) Connection Protocol</a></p>
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
final class RequestExec extends Request {

	/** Constant name for exec request. */
	static final String EXEC_REQUEST = "exec";

	/** Command value to send as exec request. */
	private final byte[] _command;


	/**
	 * Creates a new instance of <code>RequestExec</code> for the specified
	 * command value.
	 *
	 * @param command to send
	 */
	RequestExec(byte[] command) {
		_command = command != null ? command : new byte[0];
	}

	/*
	 * Sends the exec command request.
	 */
	@Override
	void request(Session session, Channel channel) throws Exception {
		super.request(session, channel);

		// send
		// byte     SSH_MSG_CHANNEL_REQUEST(98)
		// uint32 recipient channel
		// string request type       // "exec"
		// boolean want reply        // 0
		// string command
		Buffer buffer = new Buffer(200 + _command.length);
		Packet packet = new Packet(buffer);
		packet.reset();
		buffer.putByte(SSH_MSG_CHANNEL_REQUEST);
		buffer.putInt(channel.getRecipient());
		buffer.putString(EXEC_REQUEST);
		buffer.putBoolean(waitForReply());
		buffer.putString(_command);
		write(packet);
	}
	
}
