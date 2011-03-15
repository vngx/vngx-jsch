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

import static org.vngx.jsch.constants.ConnectionProtocol.*;

import org.vngx.jsch.util.Logger.Level;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of <code>Channel</code> for creating a session.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
class ChannelSession extends Channel {

	/** True if pseudo-terminal should be requested. */
	boolean _pty = false;
	/** True to indicate X11 forwarding should be requested. */
	boolean _x11Forwarding = false;
	/** True to indicate agent forwarding should be requested. */
	private boolean _agentForwarding = false;
	/** Environment variables to set as requests after connecting. */
	private Map<byte[],byte[]> _env;

	/** Terminal type to request. TODO Extract value to constants, make configurable? */
	private String _terminalType = "vt100";
	/** Number of columns in terminal. */
	private int _terminalCols = 80;
	/** Number of rows in terminal. */
	private int _terminalRows = 24;
	/** Number of pixels in width of terminal. */
	private int _terminalWidth = 640;
	/** Number of pixels in height of terminal. */
	private int _terminalHeight = 480;
	/** Terminal mode. */
	private byte[] _terminalMode;


	/**
	 * Creates a new instance of <code>ChannelSession</code>.
	 *
	 * @param session
	 */
	ChannelSession(Session session) {
		this(session, ChannelType.SESSION);
	}

	/**
	 * Creates a new instance of <code>ChannelSession</code> with the specified
	 * channel type.
	 *
	 * @param session
	 * @param channelType of sub class
	 */
	ChannelSession(Session session, ChannelType channelType) {
		super(session, channelType, ChannelType.SESSION._typeName);
		_io = new IO();
	}

	/**
	 * Sets if agent forwarding should be requested after connecting.  This
	 * value must be set prior to connecting the channel to have any effect.
	 *
	 * @param agentForwarding true if agent forwarding should be requested
	 */
	public void setAgentForwarding(boolean agentForwarding) {
		_agentForwarding = agentForwarding;
	}

	/**
	 * Sets if X11 forwarding should be requested after connecting.  This value
	 * must be set prior to connecting the channel to have any effect.
	 *
	 * @see RFC4254 6.3.1. Requesting X11 Forwarding
	 *
	 * @param x11Forwarding true if X11 forwarding should be requested
	 */
	public void setX11Forwarding(boolean x11Forwarding) {
		_x11Forwarding = x11Forwarding;
	}

	/**
	 * Sets the environment variable to request after connecting.  These values
	 * must be set prior to connecting the channel to have any effect.  If
	 * <code>name</code> and <code>value</code> need to be passed to the remote
	 * in your favorite encoding, use {@link #setEnv(byte[], byte[])}.
	 *
	 * @see RFC4254 6.4 Environment Variable Passing
	 *
	 * @param name for environment variable
	 * @param value for environment variable
	 */
	public void setEnv(String name, String value) {
		setEnv(Util.str2byte(name), Util.str2byte(value));
	}

	/**
	 * Sets the environment variable to request after connecting.  These values
	 * must be set prior to connecting the channel to have any effect.
	 *
	 * @see RFC4254 6.4 Environment Variable Passing
	 *
	 * @param name of environment variable
	 * @param value of environment variable
	 */
	public void setEnv(byte[] name, byte[] value) {
		synchronized( this ) {
			if( _env == null ) {
				_env = new HashMap<byte[],byte[]>();
			}
			_env.put(name, value);
		}
	}

	/**
	 * Sets if a Pseudo-Terminal should be requested after connecting.  This
	 * value must be set prior to connecting the channel to have any effect.
	 *
	 * @see RFC4254 6.2. Requesting a Pseudo-Terminal
	 *
	 * @param pty true if pseudo terminal should be requested
	 */
	public void setPty(boolean pty) {
		_pty = pty;
	}

	/**
	 * Sets the terminal mode to request.
	 *
	 * @param terminalMode
	 */
	public void setTerminalMode(byte[] terminalMode) {
		_terminalMode = terminalMode;
	}

	/**
	 * Sets the pseudo terminal's window dimension.  If the channel is connected
	 * and a pseudo terminal has been requested, then dynamically makes a 
	 * request to update the terminal window as specified.
	 *
	 * @see RFC4254 6.7. Window Dimension Change Message
	 *
	 * @param col terminal width, columns
	 * @param row terminal height, rows
	 * @param wp terminal width, pixels
	 * @param hp terminal height, pixels
	 */
	public void setPtySize(int col, int row, int wp, int hp) {
		setPtyType(_terminalType, col, row, wp, hp);
		if( !_pty || !isConnected() ) {
			return;
		}
		try {
			RequestWindowChange request = new RequestWindowChange();
			request.setSize(col, row, wp, hp);
			request.request(_session, this);
		} catch(Exception e) {
			/* Ignore error, don't bubble exception. */
			JSch.getLogger().log(Level.WARN, "Failed to send channel window change request", e);
		}
	}

	/**
	 * Sets the terminal type to request.  This value must be set prior to
	 * connecting the channel to have any effect.
	 *
	 * @param terminalType (for example, "vt100")
	 */
	public void setPtyType(String terminalType) {
		_terminalType = terminalType;
	}

	/**
	 * Sets the terminal type and window size to request.  These values must be
	 * set prior to connecting the channel to have any effect.
	 *
	 * @param terminalType (for example, "vt100")
	 * @param col terminal width, columns
	 * @param row terminal height, rows
	 * @param wp terminal width, pixels
	 * @param hp terminal height, pixels
	 */
	public void setPtyType(String terminalType, int col, int row, int wp, int hp) {
		_terminalType = terminalType;
		_terminalCols = col;
		_terminalRows = row;
		_terminalWidth = wp;
		_terminalHeight = hp;
	}

	/**
	 * Sends any required requests for the channel.
	 *
	 * @throws Exception if any errors occur
	 */
	final void sendRequests() throws Exception {
		// Send a agent forwarding request if enabled
		if( _agentForwarding ) {
			new RequestAgentForwarding().request(_session, this);
		}
		// Send a X11 forwarding request if enabled
		if( _x11Forwarding ) {
			new RequestX11().request(_session, this);
		}
		// Send a pseudo terminal request if enabled
		if( _pty ) {
			RequestPtyReq request = new RequestPtyReq();
			request.setTerminalType(_terminalType);
			request.setTerminalSize(_terminalCols, _terminalRows, _terminalWidth, _terminalHeight);
			if( _terminalMode != null ) {
				request.setTerminalMode(_terminalMode);
			}
			request.request(_session, this);
		}
		// Send an environment request for each defined env variable
		if( _env != null ) {
			RequestEnv request = new RequestEnv();
			for( Map.Entry<byte[],byte[]> entry : _env.entrySet() ) {
				request.setEnv(entry.getKey(), entry.getValue());
				request.request(_session, this);
			}
		}
	}

	@Override
	public void run() {
		Buffer buffer = new Buffer(_remoteMaxPacketSize);
		Packet packet = new Packet(buffer);
		int i;
		try {
			while( isConnected() && _thread != null && _io != null && _io.in != null ) {
				i = _io.in.read(buffer.buffer, 14, buffer.buffer.length - 14 - (32 - 20 /** padding and mac */));
				if( i == 0 ) {
					continue;	// If no bytes read, keep looping until data is ready
				} else if( i == -1 ) {
					eof();	// If -1, stream is finished, notify session eof
					break;	// and break out of loop
				}
				if( _closed ) {
					break;	// If channel closed, break out of loop
				}
				packet.reset();
				buffer.putByte(SSH_MSG_CHANNEL_DATA);
				buffer.putInt(_recipient);
				buffer.putInt(i);
				buffer.skip(i);
				_session.write(packet, this, i);
			}
		} catch(Exception e) {
			/* Ignore error, don't bubble exception. */
			JSch.getLogger().log(Level.WARN, "Failed to run channel session", e);
		}
		final Thread thread = _thread;
		if( thread != null ) {
			synchronized( thread ) {
				thread.notifyAll();	// TODO is anything waiting on thread?
			}
		}
		_thread = null;
	}
	
}
