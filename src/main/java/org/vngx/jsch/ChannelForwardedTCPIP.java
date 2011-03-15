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
import org.vngx.jsch.util.SocketFactory;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Implementation of <code>Channel</code> for server-to-client forwarded
 * connections over TCP/IP.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class ChannelForwardedTCPIP extends Channel {

	/** Constant for local maximum window size. */
	private static final int LOCAL_WINDOW_SIZE_MAX = 0x20000;
	/** Constant for local maximum packet size. */
	private static final int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;
	/** Constant timeout value in milliseconds. */
	private static final int TIMEOUT = 10 * 1000;

	/** Pool of forwarded ports. */
	private static final List<ForwardedPortData> PORT_POOL = Collections.synchronizedList(new ArrayList<ForwardedPortData>());

	/** Factory for creating sockets. */
	private SocketFactory _factory = SocketFactory.DEFAULT_SOCKET_FACTORY;
	/** Socket for communicating over. */
	private Socket _socket;
	/** Daemon instance to listen to forwarded TCPIP? */
	private ForwardedTCPIPDaemon _daemon;
	/** Class name (fully qualified) to load as daemon OR host name to target socket to.  ??? */
	private String _target;
	/** Local port. */
	private int _localPort;
	/** Remote port. */
	private int _remotePort;


	/**
	 * Creates a new instance of <code>ChannelForwardedTCPIP</code>.
	 *
	 * @param session
	 */
	ChannelForwardedTCPIP(Session session) {
		super(session, ChannelType.FORWARDED_TCP_IP);
		setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
		setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
		setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
		_io = new IO();
		_connected = true;	// Why start connected?
	}

	@Override
	public void run() {
		try {
			if( _localPort == -1 ) {
				_daemon = (ForwardedTCPIPDaemon) Class.forName(_target).newInstance();

				PipedOutputStream out = new PipedOutputStream();
				_io.setInputStream(new PassiveInputStream(out, 32 * 1024), false);

				_daemon.setChannel(this, getInputStream(), out);
				ForwardedPortData foo = getPort(_session, _remotePort);
				_daemon.setArg(foo._arg);

				new Thread(_daemon).start();
			} else {
				_socket = _factory.createSocket(_target, _localPort, TIMEOUT);
				_socket.setTcpNoDelay(true);
				_io.setInputStream(_socket.getInputStream());
				_io.setOutputStream(_socket.getOutputStream());
			}
			sendOpenConfirmation();
		} catch(Exception e) {
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
		} catch(Exception e) {
			/* Ignore error, don't bubble exception. */
			JSch.getLogger().log(Level.WARN, "Failed to run ChannelForwardedTCPIP", e);
		}
		disconnect();
	}

	@Override
	void initChannel(Buffer buffer) {
		super.initChannel(buffer);
		buffer.getString();		// Address
		int port = buffer.getInt();
		buffer.getString();		// Originator address
		buffer.getInt();		// Originator port

		synchronized ( PORT_POOL ) {
			for( ForwardedPortData fpdata : PORT_POOL ) {
				if( fpdata._session == _session && fpdata._remotePort == port ) {
					_remotePort = port;
					_target = fpdata._target;
					if( fpdata._arg != null ) {
						_localPort = -1;
					} else {
						_localPort = fpdata._localPort;
					}
					_factory = fpdata._socketFactory != null ?
						fpdata._socketFactory : SocketFactory.DEFAULT_SOCKET_FACTORY;
					break;
				}
			}
		}
	}

	/**
	 * Returns port forwarding information for the specified session and remote
	 * port.
	 *
	 * @param session
	 * @param remotePort
	 * @return forwarded port data
	 */
	static ForwardedPortData getPort(Session session, int remotePort) {
		synchronized ( PORT_POOL ) {
			for( ForwardedPortData fpdata : PORT_POOL ) {
				if( fpdata._session == session && fpdata._remotePort == remotePort ) {
					return fpdata;
				}
			}
			return null;
		}
	}

	/**
	 * Returns a descriptive list of currently forwarded ports for the specified
	 * session.
	 *
	 * @param session
	 * @return list of descriptive ports being forwarded
	 */
	static List<String> getPortForwarding(Session session) {
		List<String> foo = new ArrayList<String>();
		synchronized ( PORT_POOL ) {
			for( ForwardedPortData fpdata : PORT_POOL ) {
				if( fpdata._session == session ) {
					if( fpdata._arg == null ) {
						foo.add(fpdata._remotePort + ":" + fpdata._target + ":");
					} else {
						foo.add(fpdata._remotePort + ":" + fpdata._target + ":" + fpdata._addressToBind);
					}
				}
			}
		}
		return foo;
	}

	/**
	 * Normalizes the specified address.  (null returns "localhost", empty
	 * String or "*" returns "", or return address.
	 *
	 * @param address
	 * @return normalized address
	 */
	static String normalize(String address) {
		if( address == null ) {
			return SSHConstants.LOCALHOST;
		} else if( address.length() == 0 || "*".equals(address) ) {
			return "";
		} else {
			return address;
		}
	}

	/**
	 * Registers a forwarded port for the specified session, bind address, port,
	 * target, local port and socket factory.
	 * 
	 * @param session
	 * @param bindAddress
	 * @param port
	 * @param target
	 * @param localPort
	 * @param factory
	 * @throws JSchException
	 */
	static void addPort(Session session, String bindAddress, int port, String target, int localPort, SocketFactory factory) throws JSchException {
		synchronized ( PORT_POOL ) {
			if( getPort(session, port) != null ) {
				throw new JSchException("PortForwardingR: remote port " + port + " is already registered.");
			}
			ForwardedPortData fpdata = new ForwardedPortData();
			fpdata._session = session;
			fpdata._remotePort = port;
			fpdata._target = target;
			fpdata._localPort = localPort;
			fpdata._addressToBind = normalize(bindAddress);
			fpdata._socketFactory = factory;
			PORT_POOL.add(fpdata);
		}
	}

	/**
	 * Registers a forwarded port for the specified session, bind address, port,
	 * daemon and argument list.
	 * 
	 * @param session
	 * @param bindAddress
	 * @param port
	 * @param daemon
	 * @param arg
	 * @throws JSchException
	 */
	static void addPort(Session session, String bindAddress, int port, String daemon, Object[] arg) throws JSchException {
		synchronized ( PORT_POOL ) {
			if( getPort(session, port) != null ) {
				throw new JSchException("PortForwardingR: remote port " + port + " is already registered.");
			}
			ForwardedPortData fpdata = new ForwardedPortData();
			fpdata._session = session;
			fpdata._remotePort = port;
			fpdata._target = daemon;
			fpdata._arg = arg;
			fpdata._addressToBind = normalize(bindAddress);
			PORT_POOL.add(fpdata);
		}
	}

	/***
	 * Deletes the specified forwarded port channel.
	 *
	 * @param c
	 */
	static void delPort(ChannelForwardedTCPIP c) {
		delPort(c.getSession(), c.getRemotePort());
	}

	/**
	 * Deletes the forwarded port for the specified session and remote port.
	 *
	 * @param session
	 * @param remotePort
	 */
	static void delPort(Session session, int remotePort) {
		delPort(session, null, remotePort);
	}

	/***
	 * Deletes the forwarded port for the specified session, bind address and
	 * remote port.
	 *
	 * @param session
	 * @param bindAddress
	 * @param remotePort
	 */
	static void delPort(Session session, String bindAddress, int remotePort) {
		synchronized ( PORT_POOL ) {
			ForwardedPortData foo = null;
			for( ForwardedPortData fpdata : PORT_POOL ) {
				if( fpdata._session == session && fpdata._remotePort == remotePort ) {
					foo = fpdata;
					break;
				}
			}
			if( foo == null ) {
				return;
			}
			PORT_POOL.remove(foo);
			if( bindAddress == null ) {
				bindAddress = foo._addressToBind;
			}
			if( bindAddress == null ) {
				bindAddress = "0.0.0.0";
			}
		}

		// byte SSH_MSG_GLOBAL_REQUEST 80
		// string "cancel-tcpip-forward"
		// boolean want_reply
		// string  address_to_bind (e.g. "127.0.0.1")
		// uint32  port number to bind
		Buffer buffer = new Buffer(100); // ??
		Packet packet = new Packet(buffer);
		packet.reset();
		buffer.putByte(SSH_MSG_GLOBAL_REQUEST);
		buffer.putString("cancel-tcpip-forward");
		buffer.putByte((byte) 0);
		buffer.putString(bindAddress);
		buffer.putInt(remotePort);
		try {
			session.write(packet);
		} catch(Exception e) {
			/* Ignore error, don't bubble exception. */
			JSch.getLogger().log(Level.WARN, "Failed to send delete forwarded port", e);
		}
	}

	/**
	 * Deletes all forwarded ports for the specified session.
	 *
	 * @param session
	 */
	static void delPort(Session session) {
		int[] remotePorts;
		int count = 0;
		synchronized ( PORT_POOL ) {
			remotePorts = new int[PORT_POOL.size()];
			for( ForwardedPortData fpdata : PORT_POOL ) {
				if( fpdata._session == session ) {
					remotePorts[count++] = fpdata._remotePort;
				}
			}
		}
		for( int i = 0; i < count; i++ ) {
			delPort(session, remotePorts[i]);
		}
	}

	/**
	 * Returns the remote port.
	 *
	 * @return remote port
	 */
	public int getRemotePort() {
		return _remotePort;
	}

	static class ForwardedPortData {

		Session _session;

		int _remotePort;

		String _target;

		Object[] _arg;

		int _localPort;

		String _addressToBind;

		SocketFactory _socketFactory;

	}

	/**
	 * Wrapper for <code>PipedInputStream</code> to override the close() method
	 * to also close the <code>PipedOutputStream</code> sink.
	 *
	 * @author Atsuhiko Yamanaka
	 */
	class PassiveInputStream extends PipedInputStream {

		/** Sink for piped stream. */
		PipedOutputStream __out;

		/**
		 * Creates a new instance for the specified output stream and size.
		 * 
		 * @param out
		 * @param size
		 * @throws IOException
		 */
		PassiveInputStream(PipedOutputStream out, int size) throws IOException {
			super(out, size);
			__out = out;
		}

		@Override
		public void close() throws IOException {
			if( __out != null ) {
				__out.close();
			}
			__out = null;
		}

	}

}
