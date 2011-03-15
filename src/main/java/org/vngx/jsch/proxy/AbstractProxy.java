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

package org.vngx.jsch.proxy;

import org.vngx.jsch.JSch;
import org.vngx.jsch.Util;
import org.vngx.jsch.util.Logger.Level;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Abstract implementation of <code>Proxy</code> to define the base methods and
 * instance variables.
 *
 * @author Michael Laudati
 * @author Atsuhiko Yamanaka
 */
public abstract class AbstractProxy implements Proxy {

	/** Proxy host for routing requests to. */
	protected final String _proxyHost;
	/** Proxy port for routing requests to. */
	protected final int _proxyPort;

	/** Input stream for reading from proxy. */
	protected InputStream _proxyIn;
	/** Output stream for writing to proxy. */
	protected OutputStream _proxyOut;
	/** Socket connection to proxy. */
	protected Socket _socket;

	/** User name for authenticating against proxy. */
	protected String _user;
	/** Password for authenticating against proxy. */
	protected byte[] _password;


	/**
	 * Creates a new instance of <code>AbstractProxy</code> with the specified
	 * host and port.  If the host name contains the port separated by a ':',
	 * then the port in the host String will be used instead of the specified
	 * port value.
	 *
	 * @param proxyHost
	 * @param proxyPort (or default port)
	 */
	protected AbstractProxy(String proxyHost, int proxyPort) {
		if( proxyHost == null || proxyHost.length() == 0 ) {
			throw new IllegalArgumentException("Invalid proxy host: "+proxyHost);
		} else if( proxyPort < 0 ) {
			throw new IllegalArgumentException("Invalid proxy port: "+proxyPort);
		}
		String host = proxyHost;
		int port = proxyPort;
		if( proxyHost.indexOf(':') != -1 ) {
			try {
				host = proxyHost.substring(0, proxyHost.indexOf(':'));
				port = Integer.parseInt(proxyHost.substring(proxyHost.indexOf(':') + 1));
			} catch(Exception e) {
				throw new IllegalArgumentException("Invalid proxy host: "+proxyHost, e);
			}
		}
		_proxyHost = host;
		_proxyPort = port;
	}

	/**
	 * Sets the username and password for authenticating proxy if required.
	 *
	 * @param user
	 * @param passwd
	 */
	public void setUserPassword(String user, byte[] password) {
		_user = user;
		_password = new byte[password.length];
		System.arraycopy(password, 0, _password, 0, password.length);
	}

	@Override
	public InputStream getInputStream() {
		return _proxyIn;
	}

	@Override
	public OutputStream getOutputStream() {
		return _proxyOut;
	}

	@Override
	public Socket getSocket() {
		return _socket;
	}

	/*
	 * Use a separate try/catch/finally for closing the input/output streams and
	 * socket to ensure an exception caused by one doesn't prevent the others
	 * from properly being closed and cleaned up.
	 */
	@Override
	public void close() {
		try {	// Close proxy input stream
			if( _proxyIn != null ) {
				_proxyIn.close();
			}
		} catch(Exception e) {
			JSch.getLogger().log(Level.ERROR, "Failed to close proxy InputStream", e);
		} finally {
			_proxyIn = null;
		}
		try {	// Close proxy output stream
			if( _proxyOut != null ) {
				_proxyOut.close();
			}
		} catch(Exception e) {
			JSch.getLogger().log(Level.ERROR, "Failed to close proxy OutputStream", e);
		} finally {
			_proxyOut = null;
		}
		try {	// Close proxy socket connection
			if( _socket != null ) {
				_socket.close();
			}
		} catch(Exception e) {
			JSch.getLogger().log(Level.ERROR, "Failed to close proxy Socket", e);
		} finally {
			_socket = null;
		}
		Util.bzero(_password);	// Clear password
	}

}
