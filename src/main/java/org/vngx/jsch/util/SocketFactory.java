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

package org.vngx.jsch.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

/**
 * Interface for defining a factory which creates <code>Socket</code>s to a
 * given host and port and supplies methods for retrieving input and output
 * streams to read and write to open sockets.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public interface SocketFactory {

	/** Default <code>SocketFactory</code> implementation. */
	SocketFactory DEFAULT_SOCKET_FACTORY = new DefaultSocketFactory();

	/**
	 * Creates a <code>Socket</code> to the specified host and port.  If the
	 * specified timeout in milliseconds is greater than 0, an exception will be
	 * thrown if a connection is not completed within the timeout.
	 *
	 * @param host to connect
	 * @param port to connect
	 * @param timeout in milliseconds to use when connecting
	 * @return socket to host and port
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	Socket createSocket(String host, int port, int timeout) throws IOException, UnknownHostException;

	/**
	 * Returns an <code>InputStream</code> to read from the specified socket.
	 *
	 * @param socket
	 * @return input stream to read from socket
	 * @throws IOException
	 */
	InputStream getInputStream(Socket socket) throws IOException;

	/**
	 * Returns an <code>OutputStream</code> to write to the specified socket.
	 *
	 * @param socket
	 * @return output stream to write to socket
	 * @throws IOException
	 */
	OutputStream getOutputStream(Socket socket) throws IOException;

	/**
	 * Default implementation of <code>SocketFactory</code> for creating a
	 * socket connection to a host/port with or without a timeout.
	 *
	 * @author Michael Laudati
	 * @author Atsuhiko Yamanaka
	 */
	static class DefaultSocketFactory implements SocketFactory {

		@Override
		public Socket createSocket(final String host, final int port, int timeout) throws IOException, UnknownHostException {
			// If no timeout specified, create and return socket
			if( timeout <= 0 ) {
				return new Socket(host, port);
			}

			// If timeout, create another thread to open socket and wait for
			// specified timeout in milliseconds
			final Socket[] sockp = new Socket[1];		// Socket created in separate thread
			final Exception[] ee = new Exception[1];	// Exception from thread (if error)
			Thread connectThread = new Thread("Opening socket " + host) {
				@Override public void run() {
					try {
						sockp[0] = new Socket(host, port);
					} catch(Exception e) {
						ee[0] = e;
						if( sockp[0] != null && sockp[0].isConnected() ) {
							try {
								sockp[0].close();
							} catch(Exception eee) { /* Ignore error. */ }
						}
						sockp[0] = null;
					}
				}
			};
			connectThread.start();	// Start thread to open socket
			try {					// Wait up to timeout amount for connection
				connectThread.join(timeout);
			} catch(InterruptedException iex) { /* Ignore error. */ }

			// If socket is not null and connected, return
			if( sockp[0] != null && sockp[0].isConnected() ) {
				return sockp[0];
			} else {
				connectThread.interrupt();
				connectThread = null;
				if( ee[0] != null ) {
					if( ee[0] instanceof IOException ) {
						throw (IOException) ee[0];
					}
					throw (UnknownHostException) ee[0];
				}
				throw new IOException("Failed to create socket for host: "+host+", Timeout after "+timeout+" ms");
			}
		}

		@Override
		public InputStream getInputStream(Socket socket) throws IOException {
			return socket.getInputStream();
		}

		@Override
		public OutputStream getOutputStream(Socket socket) throws IOException {
			return socket.getOutputStream();
		}
		
	};

}
