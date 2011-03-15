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

package org.vngx.jsch.algorithm;

/**
 * <p>Interface for defining an algorithm which supports compressing and
 * decompressing byte data for an SSH session.</p>
 *
 * <p>If compression has been negotiated, the 'payload' field (and only it) will
 * be compressed using the negotiated algorithm.  The 'packet_length' field and
 * 'mac' will be computed from the compressed payload.  Encryption will be done
 * after compression.</p>
 *
 * <p>Compression MAY be stateful, depending on the method.  Compression MUST be
 * independent for each direction, and implementations MUST allow independent
 * choosing of the algorithm for each direction.  In practice however, it is
 * RECOMMENDED that the compression method be the same in both directions.</p>
 *
 * <p>The following compression methods are currently defined:</p>
 * <pre>
 *		none     REQUIRED        no compression
 *		zlib     OPTIONAL        ZLIB (LZ77) compression
 * </pre>
 *
 * <p><strong>Note:</strong> Implementations may not be thread-safe and should
 * be externally synchronized.</p>
 *
 * <p><strong>Note:</strong> Instances should be created using the
 * {@code AlgorithmManager} factory.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-6.2">RFC4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: 6.2. Compression</a></p>
 *
 * @see org.vngx.jsch.algorithm.AlgorithmManager
 * 
 * @author Michael Laudati
 */
public interface Compression extends Algorithm {

	/** Algorithm name {@value} for using 'none' {@code Compression}. */
	String COMPRESSION_NONE	= "none";
	/** Algorithm name {@value} for using 'zlib' {@code Compression.} */
	String COMPRESSION_ZLIB	= "zlib";
	/** Algorithm name {@value} for using 'zlib@openssh.com' {@code Compression}. */
	String COMPRESSION_ZLIB_OPENSSH	= "zlib@openssh.com";

	/** Constant for initializing decompression mode. */
	int DECOMPRESS_MODE = 0;
	/** Constant for initializing compression mode. */
	int COMPRESS_MODE = 1;

	/**
	 * Initializes the compression stream with the specified mode and level.
	 * 
	 * @param mode (compress or decompress)
	 * @param level of compression
	 */
	void init(int mode, int level);

	/**
	 * Compresses the specified buffer data from offset through length.
	 * 
	 * @param buffer to compress
	 * @param offset position in buffer
	 * @param length of buffer to compress
	 * @return compressed output length in bytes
	 */
	int compress(byte[] buffer, int offset, int length);

	/**
	 * Decompresses the specified buffer data from offset through length.
	 *
	 * @param buffer to decompress
	 * @param offset position in buffer
	 * @param length in buffer (updated to hold decompressed length)
	 * @return decompressed data
	 */
	byte[] uncompress(byte[] buffer, int offset, int[] length);

}
