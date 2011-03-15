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

import org.vngx.jsch.exception.JSchException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.net.ServerSocketFactory;

/**
 * TODO Synchronization issues...
 * TODO Shouldn't local port monitoring be unique per port... even if you have
 * more than one session, can't only one bind to local port?
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
class PortWatcher implements Runnable {

	/** Pool of registered port watcher instances/ */
	private static final List<PortWatcher> PORT_WATCHER_POOL = Collections.synchronizedList(new ArrayList<PortWatcher>());
	/** TODO ??? */
	private static final InetAddress ANY_LOCAL;
	/** Static initialization of any local address constant. */
	static {
		InetAddress temp = null;
		try {
			temp = InetAddress.getByName("0.0.0.0");
		} catch(UnknownHostException e) { /* Ignore error, let constant be null. */ }
		ANY_LOCAL = temp;
	}

	/** Session port watcher belongs to. */
	Session _session;
	/** Local port bound to port watcher. */
	int _localPort;
	/** Remote port bound to port watcher. */
	int _remotePort;
	/** Host name bound to port watcher. */
	String _host;
	/** Address bound to port watcher. */
	InetAddress _boundAddress;
	/** Thread which is running this port watcher instance. */
	Runnable _thread;
	/** Server socket bound to the address. */
	ServerSocket _serverSocket;


	/**
	 * Returns a collection of string descriptions for the ports which are
	 * currently being forwarded for the specified session.
	 *
	 * @param session to retrieve port information about
	 * @return descriptions of forwarded ports for session
	 */
	static List<String> getPortForwarding(Session session) {
		List<String> ports = new ArrayList<String>();
		synchronized( PORT_WATCHER_POOL ) {
			for( PortWatcher p : PORT_WATCHER_POOL ) {
				if( p._session == session ) {
					ports.add(p._localPort + ":" + p._host + ":" + p._remotePort);
				}
			}
		}
		return ports;
	}

	/**
	 * Returns the <code>PortWatcher</code> instance for the specified session,
	 * address and local port.
	 *
	 * @param session
	 * @param address
	 * @param localPort
	 * @return port watcher instance
	 * @throws JSchException
	 */
	static PortWatcher getPort(Session session, String address, int localPort) throws JSchException {
		InetAddress addr;
		try {
			addr = InetAddress.getByName(address);
		} catch(UnknownHostException uhe) {
			throw new JSchException("PortForwardingL: invalid address " + address + " specified", uhe);
		}
		synchronized( PORT_WATCHER_POOL ) {
			for( PortWatcher p : PORT_WATCHER_POOL ) {
				if( p._session == session && p._localPort == localPort &&
					(ANY_LOCAL != null && p._boundAddress.equals(ANY_LOCAL)) || p._boundAddress.equals(addr) ) {
					return p;
				}
			}
			return null;
		}
	}

	/**
	 * Creates an instance of <code>PortWatcher</code> for the specified values
	 * and registers it with the pool.  If a port watcher already exists for the
	 * specified values, an exception is thrown.
	 *
	 * @param session
	 * @param address
	 * @param localPort
	 * @param host
	 * @param remotePort
	 * @param ssf
	 * @return created port watcher instance
	 * @throws JSchException
	 */
	static PortWatcher addPort(Session session, String address, int localPort, String host, int remotePort, ServerSocketFactory ssf) throws JSchException {
		if( getPort(session, address, localPort) != null ) {
			throw new JSchException("PortForwardingL: local port " + address + ":" + localPort + " is already registered");
		}
		PortWatcher pw = new PortWatcher(session, address, localPort, host, remotePort, ssf);
		PORT_WATCHER_POOL.add(pw);
		return pw;
	}

	/**
	 * Deletes the port watcher instance from the registered pool for the
	 * specified values.
	 *
	 * TODO Shouldn't removing the instance be synchronized on pool?
	 *
	 * @param session
	 * @param address
	 * @param lport
	 * @throws JSchException
	 */
	static void delPort(Session session, String address, int localPort) throws JSchException {
		PortWatcher pw = getPort(session, address, localPort);
		if( pw == null ) {
			throw new JSchException("PortForwardingL: local port " + address + ":" + localPort + " is not registered");
		}
		pw.delete();
		PORT_WATCHER_POOL.remove(pw);
	}

	/**
	 * Deletes all port watcher instances registered for the specified session.
	 *
	 * @param session
	 */
	static void delPort(Session session) {
		synchronized ( PORT_WATCHER_POOL ) {
			PortWatcher[] foo = new PortWatcher[PORT_WATCHER_POOL.size()];
			int count = 0;
			for( PortWatcher p : PORT_WATCHER_POOL ) {
				if( p._session == session ) {
					p.delete();
					foo[count++] = p;
				}
			}
			for( int i = 0; i < count; i++ ) {
				PORT_WATCHER_POOL.remove(foo[i]);
			}
		}
	}


	/**
	 * Creates a new instance of <code>PortWatcher</code> for the specified
	 * session, address, local port, host, remote port and socket factory.
	 * 
	 * @param session
	 * @param address
	 * @param localPort
	 * @param host
	 * @param remotePort
	 * @param factory for creating server sockets
	 * @throws JSchException
	 */
	PortWatcher(Session session, String address, int localPort, String host, int remotePort, ServerSocketFactory factory) throws JSchException {
		_session = session;
		_localPort = localPort;
		_host = host;
		_remotePort = remotePort;
		try {
			_boundAddress = InetAddress.getByName(address);
			_serverSocket = (factory == null)
					? new ServerSocket(localPort, 0, _boundAddress)
					: factory.createServerSocket(localPort, 0, _boundAddress);
		} catch(Exception e) {
			throw new JSchException("PortForwardingL: local port " + address + ":" + localPort + " cannot be bound", e);
		}
		if( localPort == 0 ) {
			int assigned = _serverSocket.getLocalPort();
			if( assigned != -1 ) {
				_localPort = assigned;
			}
		}
	}

	@Override
	public void run() {
		_thread = this;
		try {
			while( _thread != null ) {
				Socket socket = _serverSocket.accept();
				socket.setTcpNoDelay(true);
				ChannelDirectTCPIP channel = new ChannelDirectTCPIP(_session);
				channel.init();
				channel.setInputStream(socket.getInputStream());
				channel.setOutputStream(socket.getOutputStream());
				channel.setHost(_host);
				channel.setPort(_remotePort);
				channel.setOriginatorIPAddress(socket.getInetAddress().getHostAddress());
				channel.setOriginatorPort(socket.getPort());
				channel.connect();
			}
		} catch(Exception e) {
			// TODO Error handling?
		}
		delete();	// Delete after completion of running
	}

	/**
	 * Deletes the instance by stopping the currently running thread and closing
	 * the open socket connection.
	 */
	void delete() {
		_thread = null;
		try {
			if( _serverSocket != null ) {
				_serverSocket.close();
			}
			_serverSocket = null;
		} catch(Exception e) {
			// TODO Error handling?
		}
	}

}
