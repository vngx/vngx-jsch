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

import org.vngx.jsch.Util;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.util.SocketFactory;
import java.io.IOException;

/**
 * An implementation of <code>Proxy</code> for proxying requests over an HTTP
 * connection.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class ProxyHTTP extends AbstractProxy {

	/** Constant for default HTTP port. */
	public static final int DEFAULT_PORT = 80;


	/**
	 * Creates a new instance of <code>ProxyHTTP</code> for the specified host
	 * and using the default HTTP port 80.
	 *
	 * @param proxyHost
	 */
	public ProxyHTTP(String proxyHost) {
		super(proxyHost, DEFAULT_PORT);
	}

	/**
	 * Creates a new instance of <code>ProxyHTTP</code> for the specified host
	 * and port.
	 *
	 * @param proxyHost
	 * @param proxyPort
	 */
	public ProxyHTTP(String proxyHost, int proxyPort) {
		super(proxyHost, proxyPort);
	}

	@Override
	public void connect(SocketFactory socketFactory, String host, int port, int timeout) throws JSchException {
		try {
			socketFactory = socketFactory != null ? socketFactory : SocketFactory.DEFAULT_SOCKET_FACTORY;
			_socket = socketFactory.createSocket(_proxyHost, _proxyPort, timeout);
			_proxyIn = socketFactory.getInputStream(_socket);
			_proxyOut = socketFactory.getOutputStream(_socket);
			if( timeout > 0 ) {
				_socket.setSoTimeout(timeout);
			}
			_socket.setTcpNoDelay(true);

			// Request connection to proxy
			_proxyOut.write(Util.str2byte("CONNECT " + host + ":" + port + " HTTP/1.0\r\n"));

			// If username/password present, attempt to authenticate against proxy
			if( _user != null && _password != null ) {
				byte[] user = Util.str2byte(_user + ":");
				byte[] code = new byte[user.length+_password.length];
				System.arraycopy(user, 0, code, 0, user.length);
				System.arraycopy(_password, 0, code, user.length, _password.length);
				code = Util.toBase64(code, 0, code.length);
				_proxyOut.write(Util.str2byte("Proxy-Authorization: Basic "));
				_proxyOut.write(code);
				_proxyOut.write(Util.str2byte("\r\n"));
			}
			_proxyOut.write(Util.str2byte("\r\n"));
			_proxyOut.flush();

			int foo = 0;
			StringBuilder sb = new StringBuilder();
			while( foo >= 0 ) {
				foo = _proxyIn.read();
				if( foo != 13 ) {
					sb.append((char) foo);
					continue;
				}
				foo = _proxyIn.read();
				if( foo != 10 ) {
					continue;
				}
				break;
			}
			if( foo < 0 ) {
				throw new IOException();
			}

			String response = sb.toString();
			String reason = "Unknown reason";
			int code = -1;
			try {
				foo = response.indexOf(' ');
				int bar = response.indexOf(' ', foo + 1);
				code = Integer.parseInt(response.substring(foo + 1, bar));
				reason = response.substring(bar + 1);
			} catch(Exception e) {
				throw new IOException("Failed to read proxy response: "+response);
			}
			if( code != 200 ) {
				throw new IOException("proxy error: " + reason);
			}

			int count = 0;
			while( true ) {
				count = 0;
				while( foo >= 0 ) {
					foo = _proxyIn.read();
					if( foo != 13 ) {
						count++;
						continue;
					}
					foo = _proxyIn.read();
					if( foo != 10 ) {
						continue;
					}
					break;
				}
				if( foo < 0 ) {
					throw new IOException();
				}
				if( count == 0 ) {
					break;
				}
			}
		} catch(Exception e) {
			close();	// If error occured, close all resources!
			throw new JSchException("Failed to connect ProxyHTTP: "+e, e);
		}
	}

}
