/*
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
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL N1
 * CONCEPTS LLC OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch;

import static org.vngx.jsch.constants.TransportLayerProtocol.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.vngx.jsch.constants.SSHConstants;
import org.vngx.jsch.exception.JSchException;

/**
 * <p>Implementation of SSH2 Protocol Version Exchange as described in RFC 4253
 * section 4.2.</p>
 *
 * <p>When the connection has been established, both sides MUST send an
 * identification string.  This identification string MUST be
 * <pre>
 *	SSH-protoversion-softwareversion SP comments CR LF
 * </pre>
 *
 * Since the protocol being defined in this set of documents is version 2.0,
 * the 'protoversion' MUST be "2.0".  The 'comments' string is OPTIONAL.  If the
 * 'comments' string is included, a 'space' character (denoted above as SP,
 * ASCII 32) MUST separate the 'softwareversion' and 'comments' strings.  The
 * identification MUST be terminated by a single Carriage Return (CR) and a
 * single Line Feed (LF) character (ASCII 13 and 10, respectively).
 * Implementers who wish to maintain compatibility with older, undocumented
 * versions of this protocol may want to process the identification string
 * without expecting the presence of the carriage return character for reasons
 * described in Section 5 of this document.  The null character MUST NOT be
 * sent. The maximum length of the string is 255 characters, including the
 * Carriage Return and Line Feed.</p>
 *
 * <p>The part of the identification string preceding the Carriage Return and
 * Line Feed is used in the Diffie-Hellman key exchange (see Section 8).</p>
 *
 * <p>The server MAY send other lines of data before sending the version string.
 * Each line SHOULD be terminated by a Carriage Return and Line Feed.  Such
 * lines MUST NOT begin with "SSH-", and SHOULD be encoded in ISO-10646 UTF-8
 * [RFC3629] (language is not specified).  Clients MUST be able to process such
 * lines.  Such lines MAY be silently ignored, or MAY be displayed to the client
 * user.  If they are displayed, control character filtering, as discussed in
 * [SSH-ARCH], SHOULD be used.  The primary use of this feature is to allow TCP-
 * wrappers to display an error message before disconnecting.</p>
 *
 * <p>Both the 'protoversion' and 'softwareversion' strings MUST consist of
 * printable US-ASCII characters, with the exception of whitespace characters
 * and the minus sign (-).  The 'softwareversion' string is primarily used to
 * trigger compatibility extensions and to indicate the capabilities of an
 * implementation.  The 'comments' string SHOULD contain additional information
 * that might be useful in solving user problems.  As such, an example of a
 * valid identification string is
 * <pre>
 *	SSH-2.0-billsSSH_3.6.3q3<CR><LF>
 * </pre>
 *
 * This identification string does not contain the optional 'comments' string
 * and is thus terminated by a CR and LF immediately after the 'softwareversion'
 * string.</p>
 *
 * <p>Key exchange will begin immediately after sending this identifier. All
 * packets following the identification string SHALL use the binary packet
 * protocol, which is described in Section 6.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-4.2">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: Protocol Version Exchange</a>
 * </p>
 *
 * @author Michael Laudati
 */
public class VersionExchange {
	
	/**
	 * The maximum length of the version string is {@value} characters,
	 * including the Carriage Return '\r' and Line Feed '\n'.
	 */
	public final static int MAX_VERSION_LENGTH = 255;
	/**
	 * The maximum number of lines to read in from the server during version
	 * exchange to prevent a denial of service attack against the client.
	 */
	public final static int MAX_READ_LINES = 50;

	/**
	 * Client SSH version sent to server and used during key exchange.  The
	 * version string MUST be in the following format:
	 * <pre>
	 *	SSH-protoversion-softwareversion SP comments
	 * </pre>
	 * Where the 'protoversion' must be 2.0 and the comments are optional.
	 */
	private String _clientVersion;
	/**
	 * Server SSH version received from server and used during key exchange.
	 * The version string MUST be in the following format:
	 * <pre>
	 *	SSH-protoversion-softwareversion SP comments
	 * </pre>
	 */
	private String _serverVersion;
	/**
	 * List which stores any optionally sent lines received before the server's
	 * SSH version response.  The primary use of this feature is to allow TCP-
	 * wrappers to display an error message before disconnecting.
	 */
	private List<String> _debugging;


	/**
	 * Creates a new instance of {@code VersionExchange} with the specified
	 * {@code clientVersion} string to send to server during the exchange.
	 *
	 * @param clientVersion to send to server
	 */
	public VersionExchange(final String clientVersion) {
		if( clientVersion == null || clientVersion.isEmpty() ) {
			throw new IllegalArgumentException("Client version cannot be null/empty");
		} else if( clientVersion.length() > MAX_VERSION_LENGTH ) {
			throw new IllegalArgumentException("Invalid client version, cannot exceed "+MAX_VERSION_LENGTH+" characters");
		} else if( !clientVersion.startsWith(SSHConstants.SSH_VERSION_2_0) ) {
			throw new IllegalArgumentException("Client version must start with '"+SSHConstants.SSH_VERSION_2_0+"'");
		}
		_clientVersion = clientVersion.trim(); // Ensure no whitespace/CR/LF at end
	}

	/**
	 * Exchanges the client and server SSH versions during the initial
	 * connection.  First the client version is sent to the SSH server, then the
	 * server version is read from the response.
	 *
	 * @param in stream from server
	 * @param out stream to server
	 * @throws JSchException if invalid/unsupported server version
	 * @throws IOException if any errors occur during IO
	 */
	public void exchangeVersions(InputStream in, OutputStream out) throws JSchException, IOException {
		// Send client version string to server to start version exchange
		out.write(Util.str2byte(_clientVersion + "\r\n")); // append CR LF
		out.flush();

		Buffer buffer = new Buffer(MAX_VERSION_LENGTH);
		String currentLine;
		int counter = 0;

		// Read in server's response until we find server version, storing any
		// non-relevant lines; limit number of lines read to prevent a denial
		// of service attack on client
		while( counter++ < MAX_READ_LINES ) {	// Arbitrary limit amount
			// Read next line from server into buffer
			currentLine = readLine(in, buffer);

			// Capture any possible debugging lines sent before server version
			if( !currentLine.startsWith("SSH-") ) {
				if( _debugging == null ) {
					_debugging = new LinkedList<String>();
				}
				_debugging.add(Util.sanitize(currentLine));
				continue;	// continue to read next line
			} else {
				// Check server SSH version String and verify it's either 2.0 or
				// 1.99 (supported versions) or thorw exception
				if( currentLine.startsWith(SSHConstants.SSH_VERSION_2_0) || currentLine.startsWith(SSHConstants.SSH_VERSION_1_99) ) {
					_serverVersion = currentLine;	// Set the server version
					return;							// and return from exchange
				}
				// Unsupported version returned from server (not 2.0 or 1.99)
				throw new JSchException("Unsupported server version: "+Util.sanitize(currentLine), SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED);
			}
		}
		// If no supported version has been found after max read attempts, throw
		// an exception as this might have been a denial of service on client
		throw new JSchException("Invalid server version response: exceeds maximum read attempts", SSH_DISCONNECT_PROTOCOL_ERROR);
	}

	/**
	 * Attempts to read the next line from the server input stream until a new
	 * line ('\n') is found or the maximum allowed line length is reached.  An
	 * exception will be thrown if the connection is closed or if the incoming
	 * line is longer than the buffer's length.
	 *
	 * @param in stream to read from server
	 * @param buffer to store string
	 * @return buffer
	 * @throws IOException if connection closed or line exceeds buffer length
	 */
	private String readLine(InputStream in, Buffer buffer) throws IOException {
		int c;
		buffer.reset();
		// Read in response until new line found or max buffer length
		while( buffer.getIndex() < buffer.size() ) {
			if( (c = in.read()) < 0 ) {	// Read response byte at a time
				throw new IOException("Connection closed by remote host");
			}
			buffer.putByte((byte) c);
			if( c == '\n' ) {	// Return buffer once we've reached the end
				return Util.byte2str(buffer.buffer, 0, buffer.index).trim();
			}
		}
		// Throw an exception if response exceeds max allowed length
		throw new IOException("Invalid server version response: exceeds maximum length");
	}

	/**
	 * Returns the client version sent during the protocol version exchange.
	 *
	 * @return client version
	 */
	public String getClientVersion() {
		return _clientVersion;
	}

	/**
	 * Returns the server version received during the protocol version exchange.
	 *
	 * @return server version
	 */
	public String getServerVersion() {
		return _serverVersion;
	}

	/**
	 * Returns the client SSH protocol version.
	 *
	 * @return client SSH protocol version
	 */
	public String getClientProtocol() {
		return _clientVersion.substring(4, _clientVersion.indexOf('-', 4));
	}

	/**
	 * Returns the server SSH protocol version.  If the server exchange has not
	 * yet taken place, then null is returned.
	 *
	 * @return server SSH protocol version
	 */
	public String getServerProtocol() {
		return _serverVersion != null ? _serverVersion.substring(4, _serverVersion.indexOf('-', 4)) : null;
	}

	/**
	 * Returns the client's software version.
	 *
	 * @return client's software version
	 */
	public String getClientSoftware() {
		return _clientVersion.substring(_clientVersion.indexOf('-', 5) + 1,
				_clientVersion.indexOf(' ') > 0 ? _clientVersion.indexOf(' ') : _clientVersion.length());
	}

	/**
	 * Returns the server's software version.  If the server exchange has not
	 * yet taken place, then null is returned.
	 *
	 * @return server's software version
	 */
	public String getServerSoftware() {
		return _serverVersion == null ? null :
				_serverVersion.substring(_serverVersion.indexOf('-', 5) + 1,
				_serverVersion.indexOf(' ') > 0 ? _serverVersion.indexOf(' ') : _serverVersion.length());
	}

	/**
	 * Returns the client's comment String if it exists.
	 *
	 * @return client comment String or null
	 */
	public String getClientComment() {
		return _clientVersion.indexOf(' ') > 0 ? _clientVersion.substring(_clientVersion.indexOf(' ')+1) : null;
	}

	/**
	 * Returns the server's comment String if it exists.
	 *
	 * @return server comment String or null
	 */
	public String getServerComment() {
		return _serverVersion == null ? null : _serverVersion.indexOf(' ') > 0 ? _serverVersion.substring(_serverVersion.indexOf(' ')+1) : null;
	}

	/**
	 * Returns the debugging lines received prior to the version exchange if
	 * any.
	 *
	 * @return debugging lines if they exists
	 */
	public List<String> getDebugging() {
		return _debugging != null ? Collections.unmodifiableList(_debugging) : null;
	}

}
