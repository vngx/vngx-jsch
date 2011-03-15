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
 * <p>A MAC (message authentication code) algorithm, sometimes called a keyed
 * (cryptographic) hash function, accepts as input a secret key and an
 * arbitrary-length message to be authenticated, and outputs a MAC (sometimes
 * known as a tag). The MAC value protects both a message's data integrity as
 * well as its authenticity, by allowing verifiers (who also possess the secret
 * key) to detect any changes to the message content.</p>
 *
 * <p>Data integrity is protected by including with each packet a MAC that is
 * computed from a shared secret, packet sequence number, and the contents of
 * the packet.</p>
 *
 * <p>The message authentication algorithm and key are negotiated during key
 * exchange.  Initially, no MAC will be in effect, and its length MUST be zero.
 * After key exchange, the 'mac' for the selected MAC algorithm will be computed
 * before encryption from the concatenation of packet data:
 * <pre>
 *		mac = MAC(key, sequence_number || unencrypted_packet)
 * </pre>
 * where unencrypted_packet is the entire packet without 'mac' (the length
 * fields, 'payload' and 'random padding'), and sequence_number is an implicit
 * packet sequence number represented as uint32.  The sequence_number is
 * initialized to zero for the first packet, and is incremented after every
 * packet (regardless of whether encryption or MAC is in use).  It is never
 * reset, even if keys/algorithms are renegotiated later.  It wraps around to
 * zero after every 2^32 packets.  The packet sequence_number itself is not
 * included in the packet sent over the wire.</p>
 *
 * <p>The MAC algorithms for each direction MUST run independently, and
 * implementations MUST allow choosing the algorithm independently for both
 * directions.  In practice however, it is RECOMMENDED that the same algorithm
 * be used in both directions.</p>
 * 
 * <p>The value of 'mac' resulting from the MAC algorithm MUST be transmitted
 * without encryption as the last part of the packet.  The number of 'mac' bytes
 * depends on the algorithm chosen.</p>
 *
 * <p>The following MAC algorithms are currently defined:
 * <pre>
 *	hmac-sha1    REQUIRED     HMAC-SHA1 (digest length = key length = 20)
 *	hmac-sha1-96 RECOMMENDED  first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
 *	hmac-md5     OPTIONAL     HMAC-MD5 (digest length = key length = 16)
 *	hmac-md5-96  OPTIONAL     first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
 *	none         OPTIONAL     no MAC; NOT RECOMMENDED
 * </pre></p>
 * 
 * <p>The "hmac-*" algorithms are described in [RFC2104].  The "*-n" MACs use
 * only the first n bits of the resulting value.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-6.4">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: Data Integrity</a></p>
 * <p><a href="http://tools.ietf.org/html/rfc2104">RFC 2104 - HMAC: Keyed-
 * Hashing for Message Authentication</a></p>
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
public interface MAC extends Algorithm {

	/** 
	 * Algorithm name {@value} for {@code MAC} algorithm using SHA-1 for hash.
	 * (digest length = key length = 20)
	 */
	String HMAC_SHA1 = "hmac-sha1";
	/** 
	 * Algorithm name {@value} for {@code MAC} algorithm using first 96 bits of
	 * SHA-1 hash. (digest length = 12, key length = 20)
	 */
	String HMAC_SHA1_96	= "hmac-sha1-96";
	/** 
	 * Algorithm name {@value} for {@code MAC} algorithm using SHA-256 for hash.
	 * (digest length = key length = 32)
	 */
	String HMAC_SHA_256 = "hmac-sha256";
	/**
	 * Algorithm name {@value} for {@code MAC} algorithm using MD5 for hash.
	 * (digest length = key length = 16)
	 */
	String HMAC_MD5	= "hmac-md5";
	/**
	 * Algorithm name {@value} for {@code MAC} algorithm using first 96 bits of
	 * MD5 hash. (digest length = 12, key length = 16)
	 */
	String HMAC_MD5_96 = "hmac-md5-96";

	/**
	 * Returns the message digest block size.
	 *
	 * @return block size of message digest
	 */
	int getBlockSize();

	/**
	 * Initializes the MAC with the specified {@code key}.
	 *
	 * @param key to initialize the MAC algorithm
	 * @throws MACException if any errors occur
	 */
	void init(byte[] key) throws MACException;

	/**
	 * Updates the message with the specified data from the specified offset
	 * through length.
	 *
	 * @param buffer
	 * @param offset
	 * @param length
	 */
	void update(byte[] buffer, int offset, int length);

	/**
	 * Updates the message with the specified integer.
	 *
	 * @param value
	 */
	void update(int value);

	/**
	 * Hashes the current state of MAC and places the result in the specified
	 * buffer at the specified offset.
	 * 
	 * @param buffer
	 * @param offset
	 * @throws MACException if any errors occur
	 */
	void doFinal(byte[] buffer, int offset) throws MACException;

}
