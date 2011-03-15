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
 * <p>Implementation of <code>Request</code> for sending requests to set/update
 * environment variables.</p>
 *
 * <p>Environment variables may be passed to the shell/command to be started
 * later.  Uncontrolled setting of environment variables in a privileged process
 * can be a security hazard.  It is recommended that implementations either
 * maintain a list of allowable variable names or only set environment variables
 * after the server process has dropped sufficient privileges.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4254">RFC 4254 - The Secure Shell
 * (SSH) Connection Protocol</a></p>
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
final class RequestEnv extends Request {

	/** Constant name for environment variable request. */
	static final String ENV_REQUEST = "env";

	/** Environment variable name to set (byte[] instead of String to support different encodings). */
	private byte[] _name = new byte[0];
	/** Environment variable value to set (byte[] instead of String to support different encodings). */
	private byte[] _value = new byte[0];


	/**
	 * Sets the environment variable name and value to send in request.  The use
	 * of byte[] instead of String is to allow for any character encoding.
	 *
	 * @param name of environment variable
	 * @param value of environment variable
	 */
	void setEnv(byte[] name, byte[] value) {
		_name = name;
		_value = value;
	}

	/**
	 * Sends a request to update the environment variable.
	 *
	 * {@inheritDoc}
	 *
	 * @param session
	 * @param channel
	 * @throws Exception
	 */
	@Override
	void request(Session session, Channel channel) throws Exception {
		super.request(session, channel);

		// byte		SSH_MSG_CHANNEL_REQUEST(98)
		// uint32	recipient channel
		// string	request type        // "env"
		// boolean	want reply          // 0
		// string   env name			// environment variable name
		// string   env value			// environment variable value
		Buffer buffer = new Buffer(200 + _name.length + _value.length);
		Packet packet = new Packet(buffer);
		packet.reset();
		buffer.putByte(SSH_MSG_CHANNEL_REQUEST);
		buffer.putInt(channel.getRecipient());
		buffer.putString(ENV_REQUEST);
		buffer.putBoolean(waitForReply());
		buffer.putString(_name);
		buffer.putString(_value);
		write(packet);
	}

}
