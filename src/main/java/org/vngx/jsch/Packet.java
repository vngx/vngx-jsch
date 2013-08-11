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

import org.vngx.jsch.algorithm.Random;

/**
 * <p>Implementation of an SSH2 binary data packet.  Every packet consists of
 * several distinct parts as defined in the SSH spec. The minimum size of a
 * packet is 16 (or the cipher block size, whichever is larger) bytes (plus
 * 'mac'). All implementations MUST be able to process packets with an
 * uncompressed payload length of 32768 bytes or less and a total packet size of
 * 35000 bytes or less (including 'packet_length', 'padding_length', 'payload',
 * 'random padding', and 'mac').</p>
 *
 * <p>Each packet is in the following format:
 * <pre>
 *		uint32    packet_length
 *		byte      padding_length
 *		byte[n1]  payload; n1 = packet_length - padding_length - 1
 *		byte[n2]  random padding; n2 = padding_length
 *		byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 *
 *		packet_length
 *			The length of the packet in bytes, not including 'mac' or the
 *			'packet_length' field itself.
 *		padding_length
 *			Length of 'random padding' (bytes).
 *		payload
 *			The useful contents of the packet.  If compression has been
 *			negotiated, this field is compressed.  Initially, compression MUST
 *			be "none".
 *		random padding
 *			Arbitrary-length padding, such that the total length of
 *			(packet_length || padding_length || payload || random padding)
 *			is a multiple of the cipher block size or 8, whichever is larger.
 *			There MUST be at least four bytes of padding.  The padding SHOULD
 *			consist of random bytes. The maximum amount of padding is 255 bytes.
 *		mac
 *			Message Authentication Code.  If message authentication has been
 *			negotiated, this field contains the MAC bytes.  Initially, the MAC
 *			algorithm MUST be "none".
 * </pre>
 *
 * <p><strong>Note:</strong> This class is not thread-safe and must be externally
 * synchronized.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253">RFC 4253 - The Secure Shell
 * (SSH) Transport Layer Protocol: Binary Packet Protocol</a></p>
 *
 * @see org.vngx.jsch.Buffer
 *
 * @author Michael Laudati
 */
public final class Packet {

	/**
	 * <p>Maximum number of bytes ({@value}) allowed in a binary SSH packet.</p>
	 * 
	 * <p>All implementations MUST be able to process packets with an
	 * uncompressed payload length of 32768 bytes or less and a total packet
	 * size of 35000 bytes or less (including 'packet_length', 'padding_length',
	 * 'payload', 'random padding', and 'mac').  The maximum of 35000 bytes is
	 * an arbitrarily chosen value that is larger than the uncompressed length
	 * noted above.  Implementations SHOULD support longer packets, where they 
	 * might be needed.  For example, if an implementation wants to send a very 
	 * large number of certificates, the larger packets MAY be sent if the 
	 * identification string indicates that the other party is able to process 
	 * them.  However, implementations SHOULD check that the packet length is 
	 * reasonable in order for the implementation to avoid denial of service 
	 * and/or buffer overflow attacks.</p>
	 *
	 * <p><a href="http://tools.ietf.org/html/rfc4253#section-6.1">RFC 4253 - 
	 * The Secure Shell (SSH) Transport Layer Protocol: Maximum Packet Length
	 * </a></p>
	 */
	public static final int MAX_SIZE = 256 * 1024;

	/** Internal data buffer of packet. */
	final Buffer buffer;

	
	/**
	 * Creates a new instance of <code>Packet</code> wrapping the specified
	 * buffer.
	 *
	 * @param buffer to wrap as a packet
	 */
	public Packet(Buffer buffer) {
		if( buffer == null ) {
			throw new IllegalArgumentException("Buffer cannot be null");
		}
		this.buffer = buffer;
	}

	/**
	 * Resets the packet by setting the internal buffer's index to position 5.
	 * The first 4 bytes are the packet length and the 5th byte is the padding
	 * length, so any packet data should start after these initial values.
	 */
	public void reset() {
		buffer.index = 5;
	}

	/**
	 * Sets the padding for the packet using the specified block size. The size
	 * of the random padding block is determined by the block size and the
	 * length is set as the 5th byte of the packet.  The total length of the
	 * packet is then calculated using the length of the buffer plus length of
	 * the padding and 1 byte for the padding length.
	 *
	 * @param blockSize to determine padding length
	 * @param random instance used for generating random padding data
	 */
	void setPadding(int blockSize, Random random) {
		// Calculate length of random padding and total length of packet
		int packetLength = buffer.index;
		int paddingLength = (-packetLength) & (blockSize - 1);
		if( paddingLength < blockSize ) {
			paddingLength += blockSize;
		}
		packetLength += paddingLength - 4;

		// Set the total length of packet as first 4 bytes of buffer
		// Set the fifth byte to length of random padding (as per spec)
		buffer.buffer[0] = (byte) (packetLength >>> 24);
		buffer.buffer[1] = (byte) (packetLength >>> 16);
		buffer.buffer[2] = (byte) (packetLength >>> 8);
		buffer.buffer[3] = (byte) (packetLength);
		buffer.buffer[4] = (byte) paddingLength;

		// Fill end of buffer with random padding and skip index by padding length
		random.fill(buffer.buffer, buffer.index, paddingLength);
		buffer.skip(paddingLength);
	}

	/**
	 * Shifts the data in the packet by the specified {@code length} when
	 * writing channel data to the transport layer.  After shifting, the proper
	 * amount of padding is appended to the data portion and the packet length
	 * and padding length are set.
	 *
	 * @param length
	 * @param mac
	 * @return offset
	 */
	int shift(int length, int mac) {
		int offset = length + 5 + 9;
		int paddingLength = (-offset) & 15;	// Create random padding size by
		if( paddingLength < 16 ) {
			paddingLength += 16;
		}
		offset += paddingLength + mac;

		/* If shifting to add the MAC to end of packet is greater than the packet
		 * length, then create new larger buffer to hold packet and copy data
		 * into it and replace internal byte array of buffer. */
		buffer.ensureCapacity(offset - 5 - 9 - length);

		System.arraycopy(buffer.buffer, length + 5 + 9, buffer.buffer, offset, buffer.index - 5 - 9 - length);

		buffer.index = 10;
		buffer.putInt(length);	// Why put int length at 11th byte?
		buffer.index = length + 5 + 9;
		return offset;
	}

	/**
	 * Unshifts channel packet data to the beginning of the packet from the
	 * specified {@code offset} through {@code length}.
	 *
	 * @param command
	 * @param recipient
	 * @param offset
	 * @param packetLength
	 */
	void unshift(byte command, int recipient, int offset, int length) {
		System.arraycopy(buffer.buffer, offset, buffer.buffer, 5 + 9, length);
		buffer.buffer[5] = command;
		buffer.index = 6;
		buffer.putInt(recipient);
		buffer.putInt(length);
		buffer.index = length + 5 + 9;
	}

}
