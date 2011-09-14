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


/**
 * Static utility class providing some general data manipulation methods.
 *
 * @author Michael Laudati
 * @author Atsuhiko Yamanaka
 */
public final class DataUtil {

	/** Private constructor to prevent instantiation of static utility. */
	private DataUtil() { }

	public static byte a2b(byte c) {
		if( '0' <= c && c <= '9' ) {
			return (byte) (c - '0');
		}
		return (byte) (c - 'a' + 10);
	}

	public static byte b2a(byte c) {
		if( 0 <= c && c <= 9 ) {
			return (byte) (c + '0');
		}
		return (byte) (c - 10 + 'A');
	}

	public static byte[] readINTEGER(int[] index, byte[] plain) {
		index[0]++;
		int length = plain[index[0]++] & 0xff;
		if( (length & 0x80) != 0 ) {
			int foo = length & 0x7f;
			length = 0;
			while( foo-- > 0 ) {
				length = (length << 8) + (plain[index[0]++] & 0xff);
			}
		}
		byte[] sequence = new byte[length];
		System.arraycopy(plain, index[0], sequence, 0, length);
		index[0] += length;
		return sequence;
	}

	public static int writeSEQUENCE(byte[] buf, int index, int len) {
		buf[index++] = 0x30;
		index = writeLength(buf, index, len);
		return index;
	}

	public static int writeINTEGER(byte[] buf, int index, byte[] data) {
		buf[index++] = 0x02;
		index = writeLength(buf, index, data.length);
		System.arraycopy(data, 0, buf, index, data.length);
		index += data.length;
		return index;
	}

	public static int countLength(int len) {
		int i = 1;
		if( len <= 0x7f ) {
			return i;
		}
		while( len > 0 ) {
			len >>>= 8;
			i++;
		}
		return i;
	}

	public static int writeLength(byte[] data, int index, int len) {
		int i = countLength(len) - 1;
		if( i == 0 ) {
			data[index++] = (byte) len;
			return index;
		}
		data[index++] = (byte) (0x80 | i);
		int j = index + i;
		while( i > 0 ) {
			data[index + i - 1] = (byte) (len & 0xff);
			len >>>= 8;
			i--;
		}
		return j;
	}

}
