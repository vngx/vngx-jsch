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

package org.vngx.jsch.algorithm;

import com.jcraft.jzlib.JZlib;
import com.jcraft.jzlib.ZStream;

/**
 * <p>Implementation of {@code Compression} which uses the JCraft jzlib library
 * to compress and/or uncompress byte data.</p>
 *
 * <p><strong>Note:</strong> This class is not thread-safe and must be
 * externally synchronized.</p>
 *
 * @see com.jcraft.jzlib.JZlib
 * @see com.jcraft.jzlib.ZStream
 * @see org.vngx.jsch.Compression
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class CompressionImpl implements Compression {

	/** Constant buffer size to use when compressing/decompressing. */
	private static final int BUF_SIZE = 4096;

	/** JZlib stream used for inflating/deflating session data. */
	private final ZStream _zstream;
	/** Buffer used when inflating. */
	private byte[] _inflatedBuffer;
	/** Temporary buffer used for performance. */
	private final byte[] _tmp = new byte[BUF_SIZE];


	/**
	 * Creates a new instance of {@code Compression}.
	 */
	public CompressionImpl() {
		_zstream = new ZStream();
	}

	@Override
	public void init(int type, int level) {
		switch( type ) {
			case COMPRESS_MODE:
				_zstream.deflateInit(level);
				break;
			case DECOMPRESS_MODE:
				_zstream.inflateInit();
				_inflatedBuffer = new byte[BUF_SIZE];
				break;
			default:
				throw new IllegalArgumentException("Invalid compression type: "+type);
		}
	}

	@Override
	public int compress(byte[] buffer, int offset, int length) {
		_zstream.next_in = buffer;
		_zstream.next_in_index = offset;
		_zstream.avail_in = length - offset;
		int status, outputLen = offset;

		do {
			_zstream.next_out = _tmp;
			_zstream.next_out_index = 0;
			_zstream.avail_out = BUF_SIZE;
			status = _zstream.deflate(JZlib.Z_PARTIAL_FLUSH);
			switch( status ) {
				case JZlib.Z_OK:
					System.arraycopy(_tmp, 0, buffer, outputLen, BUF_SIZE - _zstream.avail_out);
					outputLen += (BUF_SIZE - _zstream.avail_out);
					break;
				default:
					// TODO Error handling?
					System.err.println("compress: deflate returned " + status);
			}
		} while( _zstream.avail_out == 0 );
		return outputLen;
	}

	@Override
	public byte[] uncompress(byte[] buffer, int offset, int[] length) {
		int inflated_end = 0;
		int status;
		_zstream.next_in = buffer;
		_zstream.next_in_index = offset;
		_zstream.avail_in = length[0];

		while( true ) {
			_zstream.next_out = _tmp;
			_zstream.next_out_index = 0;
			_zstream.avail_out = BUF_SIZE;
			status = _zstream.inflate(JZlib.Z_PARTIAL_FLUSH);
			switch( status ) {
				case JZlib.Z_OK:
					if( _inflatedBuffer.length < inflated_end + BUF_SIZE - _zstream.avail_out ) {
						byte[] foo = new byte[inflated_end + BUF_SIZE - _zstream.avail_out];
						System.arraycopy(_inflatedBuffer, 0, foo, 0, inflated_end);
						_inflatedBuffer = foo;
					}
					System.arraycopy(_tmp, 0, _inflatedBuffer, inflated_end, BUF_SIZE - _zstream.avail_out);
					inflated_end += (BUF_SIZE - _zstream.avail_out);
					length[0] = inflated_end;
					break;
				case JZlib.Z_BUF_ERROR:
					if( inflated_end > buffer.length - offset ) {
						byte[] foo = new byte[inflated_end + offset];
						System.arraycopy(buffer, 0, foo, 0, offset);
						System.arraycopy(_inflatedBuffer, 0, foo, offset, inflated_end);
						buffer = foo;
					} else {
						System.arraycopy(_inflatedBuffer, 0, buffer, offset, inflated_end);
					}
					length[0] = inflated_end;
					return buffer;
				default:
					// TODO Error handling?
					System.err.println("uncompress: inflate returned " + status);
					return null;
			}
		}
	}

}
