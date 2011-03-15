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
import java.io.InputStream;

/**
 * Implementation of <code>Proxy</code> for proxying a connection using the
 * SOCKS5 protocol.
 *
 * This file depends on following documents,
 *		- RFC 1928  SOCKS Protocol Version 5
 *		- RFC 1929  Username/Password Authentication for SOCKS V5.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class ProxySOCKS5 extends AbstractProxy {

	/** Constant for default port for SOCKS5 protocol. */
	private static final int DEFAULT_PORT = 1080;


	/**
	 * Creates a new instance of <code>ProxySOCKS5</code> for the specified
	 * host.
	 *
	 * @param proxyHost
	 */
	public ProxySOCKS5(String proxyHost) {
		super(proxyHost, DEFAULT_PORT);
	}

	/**
	 * Creates a new instance of <code>ProxySOCKS5</code> for the specified host
	 * and port.
	 *
	 * @param proxyHost
	 * @param proxyPort
	 */
	public ProxySOCKS5(String proxyHost, int proxyPort) {
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
			+----+----------+----------+
			|VER | NMETHODS | METHODS  |
			+----+----------+----------+
			| 1  |    1     | 1 to 255 |
			+----+----------+----------+

			The VER field is set to X'05' for this version of the protocol.  The
			NMETHODS field contains the number of method identifier octets that
			appear in the METHODS field.

			The values currently defined for METHOD are:

			o  X'00' NO AUTHENTICATION REQUIRED
			o  X'01' GSSAPI
			o  X'02' USERNAME/PASSWORD
			o  X'03' to X'7F' IANA ASSIGNED
			o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
			o  X'FF' NO ACCEPTABLE METHODS
			 */
			buf[index++] = 5;
			buf[index++] = 2;
			buf[index++] = 0;           // NO AUTHENTICATION REQUIRED
			buf[index++] = 2;           // USERNAME/PASSWORD
			_proxyOut.write(buf, 0, index);

			/*
			The server selects from one of the methods given in METHODS, and
			sends a METHOD selection message:

			+----+--------+
			|VER | METHOD |
			+----+--------+
			| 1  |   1    |
			+----+--------+
			 */
			fill(_proxyIn, buf, 2);

			boolean check = false;
			switch( (buf[1]) & 0xff ) {
				case 0:                // NO AUTHENTICATION REQUIRED
					check = true;
					break;
				case 2:                // USERNAME/PASSWORD
					if( _user == null || _password == null ) {
						break;
					}

					/*
					Once the SOCKS V5 server has started, and the client has selected the
					Username/Password Authentication protocol, the Username/Password
					subnegotiation begins.  This begins with the client producing a
					Username/Password request:

					+----+------+----------+------+----------+
					|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
					+----+------+----------+------+----------+
					| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
					+----+------+----------+------+----------+

					The VER field contains the current version of the subnegotiation,
					which is X'01'. The ULEN field contains the length of the UNAME field
					that follows. The UNAME field contains the username as known to the
					source operating system. The PLEN field contains the length of the
					PASSWD field that follows. The PASSWD field contains the password
					association with the given UNAME.
					 */
					index = 0;
					buf[index++] = 1;
					buf[index++] = (byte) (_user.length());
					System.arraycopy(Util.str2byte(_user), 0, buf, index, _user.length());
					index += _user.length();
					buf[index++] = (byte) _password.length;
					System.arraycopy(_password, 0, buf, index, _password.length);
					index += _password.length;

					_proxyOut.write(buf, 0, index);

					/*
					The server verifies the supplied UNAME and PASSWD, and sends the
					following response:

					+----+--------+
					|VER | STATUS |
					+----+--------+
					| 1  |   1    |
					+----+--------+

					A STATUS field of X'00' indicates success. If the server returns a
					`failure' (STATUS value other than X'00') status, it MUST close the
					connection.
					 */
					//in.read(buf, 0, 2);
					fill(_proxyIn, buf, 2);
					if( buf[1] == 0 ) {
						check = true;
					}
					break;
				default:
			}

			if( !check ) {
				throw new JSchException("Failed to connect ProxySOCKS5 (check)");
			}

			/*
			The SOCKS request is formed as follows:

			+----+-----+-------+------+----------+----------+
			|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
			+----+-----+-------+------+----------+----------+
			| 1  |  1  | X'00' |  1   | Variable |    2     |
			+----+-----+-------+------+----------+----------+

			Where:

			o  VER    protocol version: X'05'
			o  CMD
			o  CONNECT X'01'
			o  BIND X'02'
			o  UDP ASSOCIATE X'03'
			o  RSV    RESERVED
			o  ATYP   address type of following address
			o  IP V4 address: X'01'
			o  DOMAINNAME: X'03'
			o  IP V6 address: X'04'
			o  DST.ADDR       desired destination address
			o  DST.PORT desired destination port in network octet
			order
			 */

			index = 0;
			buf[index++] = 5;
			buf[index++] = 1;       // CONNECT
			buf[index++] = 0;

			byte[] hostb = Util.str2byte(host);
			int len = hostb.length;
			buf[index++] = 3;      // DOMAINNAME
			buf[index++] = (byte) (len);
			System.arraycopy(hostb, 0, buf, index, len);
			index += len;
			buf[index++] = (byte) (port >>> 8);
			buf[index++] = (byte) (port & 0xff);

			_proxyOut.write(buf, 0, index);

			/*
			The SOCKS request information is sent by the client as soon as it has
			established a connection to the SOCKS server, and completed the
			authentication negotiations.  The server evaluates the request, and
			returns a reply formed as follows:

			+----+-----+-------+------+----------+----------+
			|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
			+----+-----+-------+------+----------+----------+
			| 1  |  1  | X'00' |  1   | Variable |    2     |
			+----+-----+-------+------+----------+----------+

			Where:

			o  VER    protocol version: X'05'
			o  REP    Reply field:
			o  X'00' succeeded
			o  X'01' general SOCKS server failure
			o  X'02' connection not allowed by ruleset
			o  X'03' Network unreachable
			o  X'04' Host unreachable
			o  X'05' Connection refused
			o  X'06' TTL expired
			o  X'07' Command not supported
			o  X'08' Address type not supported
			o  X'09' to X'FF' unassigned
			o  RSV    RESERVED
			o  ATYP   address type of following address
			o  IP V4 address: X'01'
			o  DOMAINNAME: X'03'
			o  IP V6 address: X'04'
			o  BND.ADDR       server bound address
			o  BND.PORT       server bound port in network octet order
			 */

			//in.read(buf, 0, 4);
			fill(_proxyIn, buf, 4);

			if( buf[1] != 0 ) {
				throw new JSchException("ProxySOCKS5: server returns " + buf[1]);
			}

			switch(buf[3] & 0xff) {
				case 1:
					//in.read(buf, 0, 6);
					fill(_proxyIn, buf, 6);
					break;
				case 3:
					//in.read(buf, 0, 1);
					fill(_proxyIn, buf, 1);
					//in.read(buf, 0, buf[0]+2);
					fill(_proxyIn, buf, (buf[0] & 0xff) + 2);
					break;
				case 4:
					//in.read(buf, 0, 18);
					fill(_proxyIn, buf, 18);
					break;
				default:
			}
		} catch(JSchException e) {
			close();	// If error occured, close all resources!
			throw e;
		} catch(Exception e) {
			close();	// If error occured, close all resources!
			throw new JSchException("Failed to connect ProxySOCKS5: "+e, e);
		}
	}

	/**
	 * Helper method to fill the specified buffer from the input stream.
	 *
	 * @param in
	 * @param buf
	 * @param len
	 * @throws IOException
	 */
	private static void fill(InputStream in, byte[] buf, int len) throws IOException {
		int s = 0, i;
		while( s < len ) {
			if( (i = in.read(buf, s, len - s)) <= 0 ) {
				throw new IOException("ProxySOCKS5: stream is closed");
			}
			s += i;
		}
	}

}
