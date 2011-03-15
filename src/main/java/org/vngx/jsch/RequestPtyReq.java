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
 * <p>Implementation of <code>Request</code> for sending requests to set the PTY
 * terminal type and the window size (columns, rows and pixels).</p>
 *
 * <p>Zero dimension parameters MUST be ignored.  The character/row dimensions
 * override the pixel dimensions (when nonzero).  Pixel dimensions refer to the
 * drawable area of the window. The dimension parameters are only informational.
 * </p>
 *
 * TODO Maybe all dimension values should be 0 by default in order for them to
 * be ignored by server, unless the user specifically requests to set values.
 *
 * <p><a href="http://tools.ietf.org/html/rfc4254">RFC 4254 - The Secure Shell
 * (SSH) Connection Protocol</a></p>
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
final class RequestPtyReq extends Request {

	/** Constant name for pseudo terminal request. */
	static final String PTY_REQUEST = "pty-req";

	/** Terminal type to request. TODO Extract value to constants, make configurable? */
	private String _terminalType = "vt100";
	/** Terminal column count to request. */
	private int _terminalColumns = 80;
	/** Terminal row count to request. */
	private int _terminalRows = 24;
	/** Terminal window width in pixels to request. */
	private int _terminalWidth = 640;
	/** Terminal window height in pixels to request. */
	private int _terminalHeight = 480;
	/** Terminal mode to request. */
	private byte[] _terminalMode = new byte[0];


	/**
	 * Sets the terminal type for request.
	 *
	 * @param terminalType
	 */
	void setTerminalType(String terminalType) {
		_terminalType = terminalType;
	}

	/**
	 * Sets the terminal modes to request.
	 *
	 * {@link http://www.ietf.org/rfc/rfc4254.txt}
	 *
	 * @param terminalMode
	 */
	void setTerminalMode(byte[] terminalMode) {
		_terminalMode = terminalMode;
	}

	/**
	 * Sets the terminal size to request in columns, rows and pixels.
	 *
	 * @param tcol terminal columns
	 * @param trow terminal rows
	 * @param twp terminal width in pixels
	 * @param thp terminal height in pixels
	 */
	void setTerminalSize(int tcol, int trow, int twp, int thp) {
		_terminalColumns = tcol;
		_terminalRows = trow;
		_terminalWidth = twp;
		_terminalHeight = thp;
	}

	@Override
	void request(Session session, Channel channel) throws Exception {
		super.request(session, channel);

		// byte      SSH_MSG_CHANNEL_REQUEST
		// uint32    recipient channel
		// string    "pty-req"
		// boolean   want_reply
		// string    TERM environment variable value (e.g., vt100)
		// uint32    terminal width, characters (e.g., 80)
		// uint32    terminal height, rows (e.g., 24)
		// uint32    terminal width, pixels (e.g., 640)
		// uint32    terminal height, pixels (e.g., 480)
		// string    encoded terminal modes
		Buffer buffer = new Buffer(1024);
		Packet packet = new Packet(buffer);
		packet.reset();
		buffer.putByte(SSH_MSG_CHANNEL_REQUEST);
		buffer.putInt(channel.getRecipient());
		buffer.putString(PTY_REQUEST);
		buffer.putBoolean(waitForReply());
		buffer.putString(_terminalType);
		buffer.putInt(_terminalColumns);
		buffer.putInt(_terminalRows);
		buffer.putInt(_terminalWidth);
		buffer.putInt(_terminalHeight);
		buffer.putString(_terminalMode);
		write(packet);
	}

}
