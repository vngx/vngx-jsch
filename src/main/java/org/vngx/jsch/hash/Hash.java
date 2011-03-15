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

package org.vngx.jsch.hash;

import org.vngx.jsch.algorithm.Algorithm;

/**
 * <p>Interface to define a cryptographic hash algorithm.  A cryptographic hash
 * function is a deterministic procedure that takes an arbitrary block of data
 * and returns a fixed-size bit string, the (cryptographic) hash value, such
 * that an accidental or intentional change to the data will change the hash
 * value. The data to be encoded is often called the "message", and the hash
 * value is sometimes called the message digest or simply digest.</p>
 *
 * <p><strong>Note:</strong> Implementations may not be thread-safe and should
 * be externally synchronized.</p>
 *
 * <p><strong>Note:</strong> Instances should be created using the
 * {@code HashManager} factory.</p>
 *
 * @see org.vngx.jsch.hash.HashManager
 *
 * @author Michael Laudati
 */
public interface Hash extends Algorithm {

	/** Algorithm name {@value} for SHA-1 {@code Hash} algorithm. */
	String HASH_SHA1 = "sha-1";
	/** Algorithm name {@value} for MD5 {@code Hash} algorithm. */
	String HASH_MD5	= "md5";
	/** Algorithm name {@value} for SHA-256 {@code Hash} algorithm. */
	String HASH_SHA256 = "sha-256";

	/**
	 * Returns the block size for the hash function.
	 *
	 * @return block size of message digest
	 */
	int getBlockSize();

	/**
	 * Updates the hash with the specified data.
	 *
	 * @param buffer
	 * @param offset
	 * @param length
	 */
	void update(byte[] buffer, int offset, int length);

	/**
	 * Generates and returns the message digest.
	 *
	 * @return message digest
	 */
	byte[] digest();

}
