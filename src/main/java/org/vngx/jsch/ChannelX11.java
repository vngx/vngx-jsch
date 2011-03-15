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

import org.vngx.jsch.constants.SSHConstants;
import org.vngx.jsch.util.Logger.Level;
import org.vngx.jsch.util.SocketFactory;
import java.io.IOException;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.vngx.jsch.algorithm.AlgorithmManager;
import org.vngx.jsch.algorithm.Algorithms;
import org.vngx.jsch.algorithm.Random;

/**
 * Implementation of <code>Channel</code> for an X11 agent.
 *
 * The X Window System (commonly X or X11) is a computer software system and
 * network protocol that provides a graphical user interface (GUI) for networked
 * computers. It creates a hardware abstraction layer where software is written
 * to use a generalized set of commands, allowing for device independence and
 * reuse of programs on any computer that implements X.
 *
 * X11 forwarding may be requested for a session by sending a
 * SSH_MSG_CHANNEL_REQUEST message.
 *
 *		byte      SSH_MSG_CHANNEL_REQUEST
 *		uint32    recipient channel
 *		string    "x11-req"
 *		boolean   want reply
 *		boolean   single connection
 *		string    x11 authentication protocol
 *		string    x11 authentication cookie
 *		uint32    x11 screen number
 *
 * It is RECOMMENDED that the 'x11 authentication cookie' that is sent be a
 * fake, random cookie, and that the cookie be checked and replaced by the real
 * cookie when a connection request is received.
 *
 * X11 connection forwarding should stop when the session channel is closed.
 * However, already opened forwardings should not be automatically closed when
 * the session channel is closed.
 *
 * If 'single connection' is TRUE, only a single connection should be forwarded.
 * No more connections will be forwarded after the first, or after the session
 * channel has been closed.
 *
 * The 'x11 authentication protocol' is the name of the X11 authentication
 * method used, e.g., "MIT-MAGIC-COOKIE-1".  The 'x11 authentication cookie'
 * must be hexadecimal encoded.
 *
 * X11 channels are opened with a channel open request.  The resulting channels
 * are independent of the session, and closing the session channel does not
 * close the forwarded X11 channels.
 *
 *		byte      SSH_MSG_CHANNEL_OPEN
 *		string    "x11"
 *		uint32    sender channel
 *		uint32    initial window size
 *		uint32    maximum packet size
 *		string    originator address (e.g., "192.168.7.38")
 *		uint32    originator port
 *
 * The recipient should respond with SSH_MSG_CHANNEL_OPEN_CONFIRMATION or
 * SSH_MSG_CHANNEL_OPEN_FAILURE.  Implementations must reject any X11 channel
 * open requests if they have not requested X11 forwarding.
 *
 * TODO Why are there class variables instead of instance variables?  Can only
 * one X11 forwarding channel be opened per JVM?  If two sessions are open in
 * the same JVM, only one can use X11 forwarding?  All sorts of issus with this
 * design... damn, sometimes i hate programming... =/  Why mix static and non-
 * static shit?!
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
class ChannelX11 extends Channel {

	/** Constant for local maximum window size. */
	private static final int LOCAL_WINDOW_SIZE_MAX = 0x20000;
	/** Constant for local maximum packet size. */
	private static final int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;
	/** Constant for timeout in milliseconds. */
	private static final int TIMEOUT = 10 * 1000;
	/** Map of faked cookies stored by session instance. */
	private static final Map<Session,byte[]> FAKED_COOKIE_POOL = new HashMap<Session,byte[]>();
	/** Map of faked hexadecimal cookies stored by session instance. */
	private static final Map<Session,byte[]> FAKED_COOKIE_HEX_POOL = new HashMap<Session,byte[]>();
	/** TODO ??? */
	private static final byte[] TABLE = {
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
	};


	/** Host to display forwarded X11 session to (default localhost). */
	private static String $host = SSHConstants.LOCALHOST;
	/** PORt to display forwarded X11 session to (default 6000). */
	private static int $port = 6000;
	/** Cookie containing random data to be send with forwarded X11 packets. */
	private static byte[] $cookie = null;
	/** Hexadecimal value of cookie value as per X11 forwarding spec. */
	private static byte[] $cookieHex = null;
	/** Random instance for generating random data. */
	private static Random $random = null;


	/** Socket connection to X window session receiving forwarded remote X session. */
	private Socket _socket = null;
	/** True if the channel needs to be initialized at first write() call. */
	private boolean _init = true;
	/** TODO ??? local cache? */
	private byte[] _cache = new byte[0];


	/**
	 * Returns the index of the specified byte value in the constant table.
	 *
	 * @param foo byte to lookup index
	 * @return index of byte in table or zero if no match
	 */
	static int revtable(byte c) {
		for( int i = 0; i < TABLE.length; i++ ) {
			if( TABLE[i] == c ) {
				return i;
			}
		}
		return 0;
	}

	static void setCookie(String cookieHex) {
		$cookieHex = Util.str2byte(cookieHex);
		$cookie = new byte[16];
		for( int i = 0; i < 16; i++ ) {
			$cookie[i] = (byte) (
					((revtable($cookieHex[i * 2]) << 4) & 0xf0) |
					((revtable($cookieHex[i * 2 + 1])) & 0xf)
			);
		}
	}

	static void setHost(String host) {
		$host = host;
	}

	static void setPort(int port) {
		$port = port;
	}

	static byte[] getFakedCookie(Session session) {
		synchronized( FAKED_COOKIE_HEX_POOL ) {
			byte[] fakedCookie = FAKED_COOKIE_HEX_POOL.get(session);
			if( fakedCookie == null ) {
				fakedCookie = new byte[16];
				getRandom().fill(fakedCookie, 0, 16);
				FAKED_COOKIE_POOL.put(session, fakedCookie);
				byte[] bar = new byte[32];
				for( int i = 0; i < 16; i++ ) {
					bar[2 * i] = TABLE[(fakedCookie[i] >>> 4) & 0xf];
					bar[2 * i + 1] = TABLE[(fakedCookie[i]) & 0xf];
				}
				FAKED_COOKIE_HEX_POOL.put(session, bar);
				fakedCookie = bar;
			}
			return fakedCookie;
		}
	}


	/**
	 * Creates a new instance of <code>ChannelX11</code>.
	 *
	 * @param session
	 */
	ChannelX11(Session session) {
		super(session, ChannelType.X11);
		setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
		setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
		setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
		_connected = true;	// TODO Why set to true before actually connected?
	}

	@Override
	public void run() {
		try {
			_socket = SocketFactory.DEFAULT_SOCKET_FACTORY.createSocket($host, $port, TIMEOUT);
			_socket.setTcpNoDelay(true);
			_io = new IO();
			_io.setInputStream(_socket.getInputStream());
			_io.setOutputStream(_socket.getOutputStream());
			sendOpenConfirmation();
		} catch (Exception e) {
			// TODO Error handling? Log this somewhere to notify user
			sendOpenFailure(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
			_closed = true;
			disconnect();
			return;
		}

		_thread = Thread.currentThread();
		Buffer buffer = new Buffer(_remoteMaxPacketSize);
		Packet packet = new Packet(buffer);
		int i = 0;
		try {
			while( _thread != null && _io != null && _io.in != null ) {
				if( (i = _io.in.read(buffer.buffer, 14, buffer.buffer.length - 14 - (32 - 20 /* padding and mac */))) <= 0 ) {
					eof();
					break;
				} else if( _closed ) {
					break;
				}
				packet.reset();
				buffer.putByte(SSH_MSG_CHANNEL_DATA);
				buffer.putInt(_recipient);
				buffer.putInt(i);
				buffer.skip(i);
				_session.write(packet, this, i);
			}
		} catch (Exception e) {
			/* Ignore error, don't bubble exception. */
			JSch.getLogger().log(Level.WARN, "Failed to run channel X11", e);
		} finally {
			disconnect();	// Always disconnect at end
		}
	}
	
	private byte[] addCache(byte[] buffer, int offset, int length) {
		byte[] temp = new byte[_cache.length + length];
		System.arraycopy(buffer, offset, temp, _cache.length, length);
		if( _cache.length > 0 ) {
			System.arraycopy(_cache, 0, temp, 0, _cache.length);
		}
		_cache = temp;
		return _cache;
	}

	@Override
	void write(byte[] buffer, int offset, int length) throws IOException {
		if( _init ) {
			buffer = addCache(buffer, offset, length);
			offset = 0;
			length = buffer.length;
			if( length < 9 ) {
				return;
			}

			int plen = (buffer[offset + 6] & 0xff) * 256 + (buffer[offset + 7] & 0xff);
			int dlen = (buffer[offset + 8] & 0xff) * 256 + (buffer[offset + 9] & 0xff);

			if( (buffer[offset] & 0xff) == 0x42 ) {
				// TODO ???
			} else if( (buffer[offset] & 0xff) == 0x6c ) {
				plen = ((plen >>> 8) & 0xff) | ((plen << 8) & 0xff00);
				dlen = ((dlen >>> 8) & 0xff) | ((dlen << 8) & 0xff00);
			} else {
				// TODO ???
			}

			if( length < 12 + plen + ((-plen) & 3) + dlen ) {
				return;
			}

			byte[] temp = new byte[dlen];
			System.arraycopy(buffer, offset + 12 + plen + ((-plen) & 3), temp, 0, dlen);
			byte[] faked_cookie = null;
			synchronized( FAKED_COOKIE_POOL ) {
				faked_cookie = FAKED_COOKIE_POOL.get(_session);
			}

			if( Arrays.equals(temp, faked_cookie) ) {
				if( $cookie != null ) {
					System.arraycopy($cookie, 0, buffer, offset + 12 + plen + ((-plen) & 3), dlen);
				}
			} else {
				_thread = null;
				eof();
				_io.close();
				disconnect();
			}
			_init = false;
			_io.put(buffer, offset, length);
			_cache = null;
			return;
		}
		_io.put(buffer, offset, length);
	}

	private static Random getRandom() {
		if( $random == null ) {
			try {
				$random = AlgorithmManager.getManager().createAlgorithm(Algorithms.RANDOM);
			} catch(Exception e) {
				throw new IllegalStateException("Failed to create Random instance", e);
			}
		}
		return $random;
	}

}
