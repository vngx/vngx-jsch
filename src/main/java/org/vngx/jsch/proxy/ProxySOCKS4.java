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
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Implementation of <code>Proxy</code> for proxying a connection using the
 * SOCKS4 protocol.
 *
 * This file depends on following documents:
 *		SOCKS: A protocol for TCP proxy across firewalls, Ying-Da Lee
 *		http://www.socks.nec.com/protocol/socks4.protocol
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class ProxySOCKS4 extends AbstractProxy {

	/** Constant for default SOCKS4 port. */
	public static final int DEFAULT_PORT = 1080;
	

	/**
	 * Creates a new instance of <code>ProxySOCKS4</code> for the specified
	 * host.
	 *
	 * @param proxyHost
	 */
	public ProxySOCKS4(String proxyHost) {
		super(proxyHost, DEFAULT_PORT);
	}

	/**
	 * Creates a new instance of <code>ProxySOCKS4</code> for the specified host
	 * and port.
	 *
	 * @param proxyHost
	 * @param proxyPort
	 */
	public ProxySOCKS4(String proxyHost, int proxyPort) {
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

			byte[] buf = new byte[1024];
			int index = 0;

			/*
			1) CONNECT

			The client connects to the SOCKS server and sends a CONNECT request when
			it wants to establish a connection to an application server. The client
			includes in the request packet the IP address and the port number of the
			destination host, and userid, in the following format.

			+----+----+----+----+----+----+----+----+----+----+....+----+
			| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
			+----+----+----+----+----+----+----+----+----+----+....+----+
			# of bytes:   1    1      2              4           variable       1

			VN is the SOCKS protocol version number and should be 4. CD is the
			SOCKS command code and should be 1 for CONNECT request. NULL is a byte
			of all zero bits.
			 */
			index = 0;
			buf[index++] = 4;
			buf[index++] = 1;
			buf[index++] = (byte) (port >>> 8);
			buf[index++] = (byte) (port & 0xff);

			try {
				InetAddress addr = InetAddress.getByName(host);
				byte[] byteAddress = addr.getAddress();
				for( int i = 0; i < byteAddress.length; i++ ) {
					buf[index++] = byteAddress[i];
				}
			} catch(UnknownHostException uhe) {
				throw new JSchException("ProxySOCKS4: " + uhe, uhe);
			}

			if( _user != null ) {
				System.arraycopy(Util.str2byte(_user), 0, buf, index, _user.length());
				index += _user.length();
			}
			buf[index++] = 0;
			_proxyOut.write(buf, 0, index);

			/*
			The SOCKS server checks to see whether such a request should be granted
			based on any combination of source IP address, destination IP address,
			destination port number, the userid, and information it may obtain by
			consulting IDENT, cf. RFC 1413.  If the request is granted, the SOCKS
			server makes a connection to the specified port of the destination host.
			A reply packet is sent to the client when this connection is established,
			or when the request is rejected or the operation fails.

			+----+----+----+----+----+----+----+----+
			| VN | CD | DSTPORT |      DSTIP        |
			+----+----+----+----+----+----+----+----+
			# of bytes:   1    1      2              4

			VN is the version of the reply code and should be 0. CD is the result
			code with one of the following values:

			90: request granted
			91: request rejected or failed
			92: request rejected becasue SOCKS server cannot connect to
			identd on the client
			93: request rejected because the client program and identd
			report different user-ids

			The remaining fields are ignored.
			 */

			int len = 8, s = 0, i;
			while( s < len ) {
				if( (i = _proxyIn.read(buf, s, len - s)) <= 0 ) {
					throw new JSchException("ProxySOCKS4: stream is closed");
				}
				s += i;
			}
			if( buf[0] != 0 ) {
				throw new JSchException("ProxySOCKS4: server returns VN " + buf[0]);
			}
			if( buf[1] != 90 ) {
				throw new JSchException("ProxySOCKS4: server returns CD " + buf[1]);
			}
		} catch(JSchException e) {
			close();	// If error occured, close all resources!
			throw e;
		} catch(Exception e) {
			close();	// If error occured, close all resources!
			throw new JSchException("Failed to connect ProxySOCKS4: " + e, e);
		}
	}

}
