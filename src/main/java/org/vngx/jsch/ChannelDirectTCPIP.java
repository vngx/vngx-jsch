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
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.util.Logger.Level;

/**
 * Implementation of <code>Channel</code> for client-to-server forwarded
 * connections over TCP/IP.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class ChannelDirectTCPIP extends Channel {

	/** Local maximum window size. */
	private static final int LOCAL_WINDOW_SIZE_MAX = 0x20000;
	/** Local maximum packet size. */
	private static final int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

	/** Host for direct TCP/IP channel. */
	private String _host;
	/** Port for direct TCP/IP channel. */
	private int _port;
	/** Originator IP address for direct TCP/IP channel. */
	private String _originatorIPAddress = SSHConstants.LOCALHOST;
	/** Originator port for direct TCP/IP channel. */
	private int _originatorPort = 0;

	
	/**
	 * Creates a new instance of <code>ChannelDirectTCPIP</code>.
	 *
	 * @param session
	 */
	ChannelDirectTCPIP(Session session) {
		super(session, ChannelType.DIRECT_TCP_IP);
		setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
		setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
		setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
		_io = new IO();
	}

	/*
	 * Override of connected to connect as direct TCP/IP (must pass different
	 * parameters when creating channel).
	 */
	@Override
	public void connect() throws JSchException {
		try {
			if( !_session.isConnected() ) {
				throw new JSchException("Failed to open channel: session is not connected");
			}
			Buffer buffer = new Buffer(150);
			Packet packet = new Packet(buffer);
			// send
			// byte   SSH_MSG_CHANNEL_OPEN(90)
			// string channel type         //
			// uint32 sender channel       // 0
			// uint32 initial window size  // 0x100000(65536)
			// uint32 maxmum packet size   // 0x4000(16384)
			packet.reset();
			buffer.putByte(SSH_MSG_CHANNEL_OPEN);
			buffer.putString(_type);
			buffer.putInt(_id);
			buffer.putInt(_localWindowSize);
			buffer.putInt(_localMaxPacketSize);
			buffer.putString(_host);
			buffer.putInt(_port);
			buffer.putString(_originatorIPAddress);
			buffer.putInt(_originatorPort);
			_session.write(packet);

			int retry = 1000;
			while( _recipient == -1 && _session.isConnected() && retry-- > 0 && !_eofRemote ) {
				try { Thread.sleep(50); } catch(InterruptedException e) { /* Ignore error. */ }
			}
			if( !_session.isConnected() ) {
				throw new JSchException("Failed to open channel: session is not connected");
			} else if( retry == 0 || _eofRemote ) {
				throw new JSchException("Failed to open channel: no response");
			}
			_connected = true;

			if( _io.in != null ) {
				_thread = new Thread(this, "DirectTCPIP thread " + _session.getHost());
				_thread.setDaemon(_session.isDaemonThread());
				_thread.start();
			}
		} catch(JSchException e) {
			_connected = false;
			disconnect();
			throw e;
		} catch(Exception e) {
			_connected = false;
			disconnect();
			throw new JSchException("Failed to open channel "+getClass().getSimpleName()+": "+_exitstatus, e);
		}
	}

	/*
	 * Override of Channel.connect(timeout) to forward to connect() method.
	 * Without this override, if a call to connect(timeout) is made on an
	 * instance of ChannelDirectTCPIP, it will call the base Channel
	 * implementation and not work correctly as a direct TCPIP channel.
	 */
	@Override
	public void connect(int timeout) throws JSchException {
		connect();
	}

	/*
	 * Implementation of <code>Runnable</code> to run this as a thread to
	 * continue reading from the input stream and writing out to the channel.
	 */
	@Override
	public void run() {
		Buffer buffer = new Buffer(_remoteMaxPacketSize);
		Packet packet = new Packet(buffer);
		int i = 0;
		try {
			while( isConnected() && _thread != null && _io != null && _io.in != null ) {
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
		} catch(Exception e) {
			/* Ignore error, don't bubble exception. */
			JSch.getLogger().log(Level.DEBUG, "Failed to run ChannelDirectTCPIP", e);
		}
		disconnect();	// Disconnect after finished reading from stream
	}

	/**
	 * Sets the host for the direct TCP/IP channel.
	 *
	 * @param host
	 */
	public void setHost(String host) {
		_host = host;
	}

	/**
	 * Sets the port for the direct TCP/IP channel.
	 *
	 * @param port
	 */
	public void setPort(int port) {
		_port = port;
	}

	/**
	 * Sets the originator IP address for the direct TCP/IP channel.
	 *
	 * @param originatorIPAddress
	 */
	public void setOriginatorIPAddress(String originatorIPAddress) {
		_originatorIPAddress = originatorIPAddress;
	}

	/**
	 * Sets the originator port for the direct TCP/IP channel.
	 *
	 * @param originatorPort
	 */
	public void setOriginatorPort(int originatorPort) {
		_originatorPort = originatorPort;
	}
	
}
