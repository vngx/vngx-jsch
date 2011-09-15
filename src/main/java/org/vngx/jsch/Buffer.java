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

import java.util.Arrays;

/**
 * <p>A simple byte Buffer implementation which wraps a byte array and provides
 * commonly used functionality for accessing and setting values according to the
 * SSH spec for packets.  SSH packets contain a buffer of bytes which are sent
 * and received between the client and server.</p>
 *
 * <p>{@code Buffer} instances should have limited scope (mostly private or
 * package access) to ensure sensitive, secure information from an SSH session
 * is not externally exposed. Additionally, the {@link clear()} method zeros out
 * the entire internal buffer, clearing any secure data.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4251#section-5">RFC 4251 - The
 * Secure Shell (SSH) Protocol Architecture: Data Type Representations Used in
 * the SSH Protocols</a></p>
 * <p><a href="http://tools.ietf.org/html/rfc4253">RFC 4253 - The Secure Shell
 * (SSH) Transport Layer Protocol: Binary Packet Protocol</a></p>
 *
 * <p><strong>Note:</strong> This class is not thread-safe and must be 
 * externally synchronized.</p>
 *
 * @see org.vngx.jsch.Packet
 *
 * @author Michael Laudati
 */
public final class Buffer {

	// TODO Consider making default buffer size configurable
	/** Default size {@value} bytes when creating new {@code Buffer}s. */
	final static int DEFAULT_SIZE = 1024 * 10 * 2;

	/** Array to serve as data buffer. */
	byte[] buffer;
	/** Current index in the buffer when writing/putting data. */
	int index;
	/** Current offset in the buffer when reading/getting data. */
	private int _offset;


	/**
	 * Creates a new instance of {@code Buffer} with the default size of
	 * {@value #DEFAULT_SIZE} bytes.
	 */
	public Buffer() {
		this(DEFAULT_SIZE);
	}

	/**
	 * Creates a new instance of {@code Buffer} with the specified {@code size}
	 * in bytes.
	 *
	 * @param size of buffer in bytes
	 */
	public Buffer(final int size) {
		if( size < 0 ) {
			throw new IllegalArgumentException("Buffer must have a positive size: "+size);
		} else if( size > Packet.MAX_SIZE ) {
			throw new IllegalArgumentException("Buffer cannot exceed maximum packet size: "+size);
		}
		buffer = new byte[size];
	}

	/**
	 * Creates a new instance of {@code Buffer} wrapping the specified byte
	 * {@code buffer}.
	 *
	 * @param buffer to wrap
	 */
	public Buffer(final byte[] buffer) {
		if( buffer == null ) {
			throw new IllegalArgumentException("Cannot wrap a null byte[]");
		} else if( buffer.length > Packet.MAX_SIZE ) {
			throw new IllegalArgumentException("Buffer cannot exceed maximum packet size: "+buffer.length);
		}
		this.buffer = buffer;
	}

	/**
	 * Puts the specified {@code byte} into the buffer at the current index.
	 *
	 * @param b byte to put in buffer
	 * @return this instance
	 */
	public Buffer putByte(final byte b) {
		buffer[index++] = b;
		return this;
	}

	/**
	 * Puts the entire contents of the specified {@code bytes} into the buffer
	 * at the current index.
	 *
	 * @param bytes to put in buffer
	 * @return this instance
	 */
	public Buffer putBytes(final byte[] bytes) {
		return putBytes(bytes, 0, bytes.length);
	}

	/**
	 * Puts the contents of the specified {@code bytes} into the buffer at the
	 * current index starting at {@code offset} position in the specified
	 * {@code bytes} through the specified {@code length}.
	 *
	 * @param bytes to put in buffer
	 * @param offset position in specified {@code bytes}
	 * @param length of specified {@code bytes} to put
	 * @return this instance
	 */
	public Buffer putBytes(final byte[] bytes, int offset, int length) {
		System.arraycopy(bytes, offset, buffer, index, length);
		index += length;
		return this;
	}

	/**
	 * Puts the contents of the specified {@code Buffer} into the buffer at the
	 * current index starting at {@code offset} position in the specified
	 * {@code buffer} through the specified {@code length}.
	 *
	 * @param buffer to put in this buffer
	 * @param offset position in specified {@code buffer}
	 * @param length of specified {@code buffer} to put
	 * @return this instance
	 */
	public Buffer putBytes(final Buffer buffer, int offset, int length) {
		return putBytes(buffer.getArray(), offset, length);
	}

	/**
	 * Puts the specified {@code string} in the buffer at the current index.
	 * Same as calling {@code putString(CharacterUtil.str2byte(string))}.
	 *
	 * @param string to put in buffer
	 * @return this instance
	 */
	public Buffer putString(final String string) {
		return putString(Util.str2byte(string));
	}

	/**
	 * Puts the specified {@code string} data into this buffer at the current
	 * index.
	 *
	 * @param string to put in buffer
	 * @return this instance
	 */
	public Buffer putString(final byte[] string) {
		return putString(string, 0, string.length);
	}

	/**
	 * Puts the specified {@code string} data into this buffer at the current
	 * index starting at {@code offset} position in the specified {@code string}
	 * through the specified {@code length}.
	 *
	 * @param string to put in buffer
	 * @param offset position in specified {@code string}
	 * @param length of {@code string} to put in buffer
	 * @return this instance
	 */
	public Buffer putString(final byte[] string, int offset, int length) {
		putInt(length);
		return putBytes(string, offset, length);
	}

	/**
	 * Puts the specified {@code int} into this buffer at the current index.
	 * The value is stored as four bytes in the order of decreasing significance
	 * (network byte order).  For example: the value 699921578 (0x29b7f4aa) is
	 * stored as 29 b7 f4 aa.  (Assumes JVM standard size of 4 bytes for
	 * {@code int} data type).
	 *
	 * @param value to put in buffer
	 * @return this instance
	 */
	public Buffer putInt(final int value) {
		buffer[index++] = (byte) (value >>> 24);
		buffer[index++] = (byte) (value >>> 16);
		buffer[index++] = (byte) (value >>> 8);
		buffer[index++] = (byte) (value);
		return this;
	}

	/**
	 * Puts the specified {@code long} into this buffer at the current index.
	 * The value is stored as eight bytes in the order of decreasing
	 * significance (network byte order).  (Assumes JVM standard size of 8 bytes
	 * for the {@code long} data type).
	 *
	 * @param value to put in buffer
	 * @return this instance
	 */
	public Buffer putLong(final long value) {
		buffer[index++] = (byte) (value >>> 56);
		buffer[index++] = (byte) (value >>> 48);
		buffer[index++] = (byte) (value >>> 40);
		buffer[index++] = (byte) (value >>> 32);
		buffer[index++] = (byte) (value >>> 24);
		buffer[index++] = (byte) (value >>> 16);
		buffer[index++] = (byte) (value >>> 8);
		buffer[index++] = (byte) (value);
		return this;
	}

	/**
	 * Places the specified boolean {@code b} into the buffer at the current
	 * index.  A boolean value of {@code true} is placed as a byte with value 1
	 * and {@code false} is placed as a byte with value 0.
	 *
	 * @param b boolean to put in buffer
	 * @return this instance
	 */
	public Buffer putBoolean(final boolean b) {
		buffer[index++] = b ? (byte) 1 : (byte) 0;
		return this;
	}

	/**
	 * Puts the multiple precision integer value {@code mpint} at the current
	 * index.  Multiple precision integers are represented in two's complement
	 * format, stored as a string, 8 bits per byte, MSB first.  Negative numbers
	 * have the value 1 as the most significant bit of the first byte of the
	 * data partition.  If the most significant bit would be set for a positive
	 * number, the number MUST be preceded by a zero byte.  Unnecessary leading
	 * bytes with the value 0 or 255 MUST NOT be included.  The value zero MUST
	 * be stored as a string with zero bytes of data.
	 *
	 * @param mpint to put in buffer
	 * @return this instance
	 */
	public Buffer putMPInt(final byte[] mpint) {
		int length = mpint.length;
		if( length > 0 && (mpint[0] & 0x80) != 0 ) {	// If first bit of mpint
			putInt(length+1);			// is 1, then it's a negative number, it
			putByte((byte) 0);			// needs to be encoded correctly
		} else {
			putInt(length);
		}
		return putBytes(mpint);
	}

	/**
	 * Skips the current index forward by the specified amount {@code n}.
	 *
	 * @param n bytes to skip forward
	 * @return this instance
	 * @throws IndexOutOfBoundsException if n skip index past buffer length
	 * @throws IllegalArgumentException if n is negative
	 */
	public Buffer skip(final int n) {
		if( (n + index) > buffer.length ) {
			throw new IndexOutOfBoundsException("Cannot skip index past buffer length");
		} else if( n < 0 ) {
			throw new IllegalArgumentException("Cannot skip backwards");
		}
		index += n;
		return this;
	}

	/**
	 * Returns the size of the internal buffer.
	 *
	 * @return size of internal buffer in bytes
	 */
	public int size() {
		return buffer.length;
	}

	/**
	 * Returns the current length of buffer (current index - offset).
	 *
	 * @return length of buffer
	 */
	public int getLength() {
		return index - _offset;
	}

	/**
	 * Returns the current index position of buffer.  The index maintains the
	 * current write position where the next call to {@code putXxx} will insert
	 * data.
	 *
	 * @return current index position
	 */
	public int getIndex() {
		return index;
	}

	/**
	 * Returns the current offset position of buffer.  The offset maintains the
	 * current read position where the next call to {@code getXxx} will retrieve
	 * data.
	 *
	 * @return current offset position
	 */
	public int getOffSet() {
		return _offset;
	}

	/**
	 * Sets the current offset position of buffer.  The offset maintains the
	 * current read position where the next call to {@code getXxx} will retrieve
	 * data.
	 *
	 * @param offset position to set
	 * @return this instance
	 * @throws IndexOutOfBoundsException if specified offset is greater than
	 *		buffer length or less than zero
	 */
	public Buffer setOffSet(final int offset) {
		if( offset > buffer.length ) {
			throw new IndexOutOfBoundsException("Offset cannot be greater than buffer length: "+offset);
		} else if( offset < 0 ) {
			throw new IndexOutOfBoundsException("Offset cannot be less than 0: "+offset);
		}
		_offset = offset;
		return this;
	}

	/**
	 * Returns the internal backing {@code byte[]}.
	 *
	 * @return internal backing byte array
	 */
	public byte[] getArray() {
		return buffer;
	}

	/**
	 * Returns the {@code long} value from the current offset position.
	 *
	 * @return {@code long} value from current offset
	 */
	public long getLong() {
		return  ((getInt() & 0xFFFFFFFFL) << 32) |
				 (getInt() & 0xFFFFFFFFL);
	}

	/**
	 * Returns the {@code int} value from the current offset position.  An
	 * integer is made up of four bytes with the most significant bytes first.
	 *
	 * @return {@code int} value from current offset
	 */
	public int getInt() {
		return  ((buffer[_offset++] << 24) & 0xFF000000) |
				((buffer[_offset++] << 16) & 0x00FF0000) |
				((buffer[_offset++] <<  8) & 0x0000FF00) |
				((buffer[_offset++]      ) & 0x000000FF);
	}

	/**
	 * Returns the unsigned {@code int} value from the current offset as a
	 * {@code long}.  An unsigned int is made up of four bytes with the most
	 * significant bytes first.  As an {@code int} in Java is always signed, the
	 * value needs to be stored in a long so that large positive integer values
	 * do not appear to be negative.
	 *
	 * @return unsigned {@code int} value as a long
	 */
	public long getUInt() {
		return  (((long) getShort() << 16) & 0xFFFF0000L) |	// First 16 bytes
				((       getShort()      ) & 0x0000FFFFL);	// second 16 bytes
	}

	/**
	 * Returns the {@code short} value from the current offset position.  A
	 * short is made up of two bytes with the most significant bytes first.
	 *
	 * @return {@code short} value from current offset
	 */
	public int getShort() {
		return  ((buffer[_offset++] << 8) & 0xFF00) | 
				((buffer[_offset++]     ) & 0x00FF);
	}

	/**
	 * Returns the {@code byte} value from the current offset position.  The
	 * value is returned as an {@code int} as bytes are unsigned, and may not
	 * fit in a Java {@code byte} (i.e. values {@literal 127 < b < 256}).
	 *
	 * @return {@code byte} value from current offset as an {@code int}
	 */
	public int getByte() {
		return buffer[_offset++] & 0xFF;
	}

	/**
	 * Returns the {@code boolean} value from the current offset position.  A
	 * boolean is stored as a {@code byte} value; {@code true} is any non-zero
	 * byte value.
	 *
	 * @return {@code true} if byte at current offset does not equal zero
	 */
	public boolean getBoolean() {
		return getByte() != 0;
	}

	/**
	 * Fills the specified {@code bytes} buffer with bytes from this buffer
	 * starting from the current offset position through the length of
	 * {@code bytes}.
	 *
	 * @param bytes array to fill with data
	 * @return {@code bytes} passed to method
	 */
	public byte[] getBytes(final byte[] bytes) {
		return getBytes(bytes, 0, bytes.length);
	}

	/**
	 * Fills the specified {@code bytes} buffer with bytes from this buffer
	 * starting from the current offset position and filling {@ccode bytes}
	 * starting at the specified {@code offset} through the specified
	 * {@code length}.
	 *
	 * @param bytes array to fill with data
	 * @param offset position in {@code bytes}
	 * @param length to copy
	 * @return {@code bytes} passed to method
	 */
	public byte[] getBytes(final byte[] bytes, int offset, int length) {
		System.arraycopy(buffer, _offset, bytes, offset, length);
		_offset += length;
		return bytes;
	}

	/**
	 * Returns the multiple precision integer value from the current offset
	 * position.
	 *
	 * @return multiple precision integer at the current offset
	 */
	public byte[] getMPInt() {
		final int mpIntLen = getInt();
		// bigger than 0x7fffffff, will get OOME, throw exception
		if( mpIntLen < 0 || mpIntLen > 8 * 1024 ) {
			throw new IllegalStateException("MPInt exceeds maximum size: "+mpIntLen);
		}
		return getBytes(new byte[mpIntLen], 0, mpIntLen);
	}

	/**
	 * Returns the multiple precision integer bits from the current offset.
	 *
	 * @return multiple precision integer bits
	 */
	public byte[] getMPIntBits() {
		int bits = getInt();
		int bytes = (bits + 7) / 8;
		byte[] mpintBits = getBytes(new byte[bytes], 0, bytes);
		if( (mpintBits[0] & 0x80) != 0 ) {
			mpintBits = Util.join(new byte[1], mpintBits); // Set leading bit to 0, and shift rest down
		}
		return mpintBits;
	}

	/**
	 * Returns the bytes of a {@code String} read from the current offset.
	 *
	 * @return bytes of a {@code String} from buffer
	 */
	public byte[] getString() {
		int strlen = getInt();
		// bigger than 0x7fffffff, will get OOME, throw exception
		if( strlen < 0 || strlen > Packet.MAX_SIZE ) {
			throw new IllegalStateException("String length exceeds maximum: "+strlen);
		}
		return getBytes(new byte[strlen], 0, strlen);
	}

	/**
	 * Reads the string from the buffer and returns the offset and length of the
	 * internal buffer which holds the string, advancing the index to after the
	 * string value. (Performance gain to create String from internal buffer
	 * rather than create new byte[] and copying buffer content.)
	 *
	 * <p>Note: Use arrays with length 1 as parameters to allow for returning
	 * multiple values (arrays passed by reference).</p>
	 *
	 * @param offset array to store the offset position of String at index 0
	 * @param length array to store the length of String at index 0
	 */
	void getString(int[] offset, int[] length) {
		length[0] = getInt();	// Read length of String
		offset[0] = _offset;	// Set offset of String as current offset
		_offset += length[0];	// Advance offset by length of String
	}

	/**
	 * Resets the buffer to set the current index and offset positions to 0.
	 *
	 * @return this instance
	 */
	public Buffer reset() {
		index = _offset = 0;
		return this;
	}

	/**
	 * Shifts the data in the internal buffer from its current offset to the
	 * beginning of the array.
	 *
	 * @return this instance
	 */
	public Buffer shift() {
		if( _offset == 0 ) {
			return this;
		}
		System.arraycopy(buffer, _offset, buffer, 0, index - _offset);
		index -= _offset;
		_offset = 0;
		return this;
	}

	/**
	 * Rewinds the current state by setting the offset to zero.
	 *
	 * @return this instance
	 */
	public Buffer rewind() {
		_offset = 0;
		return this;
	}

	/**
	 * Returns the SSH command code.
	 *
	 * @return SSH command code
	 */
	public byte getCommand() {
		return buffer[5];
	}

	/**
	 * Ensures the capacity of the buffer to fit the specified {@code required}
	 * amount by creating and copying data into a new internal buffer if the
	 * current buffer does not have enough space starting from the current
	 * index.  If the requested size exceeds the maximum packet size, then an
	 * {@code IllegalStateException} will be thrown.
	 *
	 * @param required amount in bytes to ensure
	 * @return this instance
	 * @throws IllegalStateException if total size is larger than max packet size
	 */
	public Buffer ensureCapacity(final int required) {
		if( (index + required) > buffer.length ) {
			if( (index + required) > Packet.MAX_SIZE ) {
				throw new IllegalStateException("Buffer cannot exceed max packet size: "+(index+required));
			}
			buffer = Arrays.copyOf(buffer, index + required);
		}
		return this;
	}

	/**
	 * Clears the entire internal buffer by setting all values to 0.
	 *
	 * @return this instance
	 */
	public Buffer clear() {
		reset();
		Arrays.fill(buffer, (byte) 0);
		return this;
	}

}
