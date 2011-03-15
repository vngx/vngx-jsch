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
 * <p>Implementation of <code>Request</code> for requesting a window change.</p>
 *
 * <p>When the window (terminal) size changes on the client side, it may send a
 * message to the other side to inform it of the new dimensions.</p>
 *
 * <p>A response SHOULD NOT be sent to this message.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4254">RFC 4254 - The Secure Shell
 * (SSH) Connection Protocol</a></p>
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
final class RequestWindowChange extends Request {

	/** Constant name for window change request. */
	static final String WINDOW_CHANGE_REQUEST = "window-change";

	/** Window width in columns. */
	private int _widthColumns = 80;
	/** Window height in rows. */
	private int _heightRows = 24;
	/** Window width in pixels. */
	private int _widthPixels = 640;
	/** Window height in pixels. */
	private int _heightPixels = 480;


	/**
	 * Sets the window size to request.
	 *
	 * @param col
	 * @param row
	 * @param wp
	 * @param hp
	 */
	void setSize(int col, int row, int wp, int hp) {
		_widthColumns = col;
		_heightRows = row;
		_widthPixels = wp;
		_heightPixels = hp;
	}

	/*
	 * Sends request to set the window size.
	 */
	@Override
	void request(Session session, Channel channel) throws Exception {
		super.request(session, channel);

		//byte      SSH_MSG_CHANNEL_REQUEST
		//uint32    recipient_channel
		//string    "window-change"
		//boolean   FALSE
		//uint32    terminal width, columns
		//uint32    terminal height, rows
		//uint32    terminal width, pixels
		//uint32    terminal height, pixels
		Buffer buffer = new Buffer(200);
		Packet packet = new Packet(buffer);
		packet.reset();
		buffer.putByte(SSH_MSG_CHANNEL_REQUEST);
		buffer.putInt(channel.getRecipient());
		buffer.putString(WINDOW_CHANGE_REQUEST);
		buffer.putBoolean(false);	// Reply must always be false as per spec
		buffer.putInt(_widthColumns);
		buffer.putInt(_heightRows);
		buffer.putInt(_widthPixels);
		buffer.putInt(_heightPixels);
		write(packet);
	}

}
