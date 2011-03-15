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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;

/**
 * A helper/utility class for managing input and output streams used for
 * communicating over a <code>Channel</code>.  Provides methods for writing
 * SSH packets to output streams.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
final class IO {

	/** Wrapped input stream. */
	InputStream in;
	/** Wrapped output stream. */
	OutputStream _out;
	/** Wrapped output stream for extended output. */
	private OutputStream _extOut;
	/** True to indicate input stream should not be closed. */
	private boolean _dontCloseIn = false;
	/** True to indicate output stream should not be closed. */
	private boolean _dontCloseOut = false;
	/** True to indicate error output stream should not be closed. */
	private boolean _dontCloseExtOut = false;


	/**
	 * Sets the <code>OutputStream</code> to use.
	 *
	 * @param out
	 */
	void setOutputStream(OutputStream out) {
		_out = out;
	}

	/**
	 * Sets the <code>OutputStream</code> to use and specifies whether it should
	 * be closed.
	 *
	 * @param out
	 * @param dontClose
	 */
	void setOutputStream(OutputStream out, boolean dontClose) {
		_dontCloseOut = dontClose;
		setOutputStream(out);
	}

	/**
	 * Sets the extended <code>OutputStream</code> to use.
	 *
	 * @param out
	 */
	void setExtOutputStream(OutputStream out) {
		_extOut = out;
	}

	/**
	 * Sets the extended <code>OutputStream</code> to use and specifies whether
	 * it should be closed.
	 *
	 * @param out
	 * @param dontClose
	 */
	void setExtOutputStream(OutputStream out, boolean dontClose) {
		_dontCloseExtOut = dontClose;
		setExtOutputStream(out);
	}

	/**
	 * Sets the <code>InputStream</code> to use.
	 * 
	 * @param in
	 * @param dontClose
	 */
	void setInputStream(InputStream in) {
		this.in = in;
	}

	/**
	 * Sets the <code>InputStream</code> to use and specifies whether it should
	 * be closed.
	 *
	 * @param in
	 * @param dontClose
	 */
	void setInputStream(InputStream in, boolean dontClose) {
		_dontCloseIn = dontClose;
		setInputStream(in);
	}

	/**
	 * Writes the specified packet to the output stream.
	 *
	 * @param p packet to write
	 * @throws IOException
	 * @throws SocketException
	 */
	public void put(Packet p) throws IOException, SocketException {
		_out.write(p.buffer.buffer, 0, p.buffer.index);
		_out.flush();
	}

	/**
	 * Writes the specified data to the output stream.
	 *
	 * @param buffer
	 * @param offset
	 * @param length
	 * @throws IOException
	 */
	void put(byte[] buffer, int offset, int length) throws IOException {
		_out.write(buffer, offset, length);
		_out.flush();
	}

	/**
	 * Writes the specified data to the extended output stream.
	 *
	 * @param buffer
	 * @param offset
	 * @param length
	 * @throws IOException
	 */
	void putExt(byte[] buffer, int offset, int length) throws IOException {
		_extOut.write(buffer, offset, length);
		_extOut.flush();
	}

	/**
	 * Reads from the input stream into the specified data buffer.
	 *
	 * @param buffer
	 * @param offset
	 * @param length
	 * @throws IOException
	 */
	void getByte(byte[] buffer, int offset, int length) throws IOException {
		int bytesRead;
		do {
			if( (bytesRead = in.read(buffer, offset, length)) < 0 ) {
				throw new IOException("End of IO InputStream read");
			}
			offset += bytesRead;
			length -= bytesRead;
		} while( length > 0 );
	}

	/**
	 * Closes the output stream only if not specified to not close output.
	 */
	void closeOut() {
		try {
			if( _out != null && !_dontCloseOut ) {
				_out.close();
			}
			_out = null;
		} catch(Exception e) { /* Ignore error on close. */ }
	}

	/**
	 * Closes all the wrapped streams if they are closeable.
	 */
	void close() {
		try {
			if( in != null && !_dontCloseIn ) {
				in.close();
			}
			in = null;
		} catch(Exception e) { /* Ignore error on close. */ }
		closeOut();
		try {
			if( _extOut != null && !_dontCloseExtOut ) {
				_extOut.close();
			}
			_extOut = null;
		} catch(Exception e) { /* Ignore error on close. */ }
	}

}
