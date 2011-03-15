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

package org.vngx.jsch.kex;

import org.vngx.jsch.exception.JSchException;

/**
 * <p>Implementation of {@code KexAlgorithm} for "diffie-hellman-group1-sha1"
 * key exchange for SSH.  The "diffie-hellman-group1-sha1" method specifies the
 * Diffie-Hellman key exchange with SHA-1 as HASH, and Oakley Group 2 [RFC2409]
 * (1024- bit MODP Group).  This method MUST be supported for interoperability
 * as all of the known implementations currently support it.  Note that this
 * method is named using the phrase "group1" even though it specifies the use of
 * Oakley Group 2.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-8.1">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: 8.1. diffie-hellman-group1-sha1
 * </a></p>
 * <p><a href="http://tools.ietf.org/html/rfc2409">RFC 2409 - The Internet Key 
 * Exchange (IKE)</a></p>
 *
 * @see org.vngx.jsch.kex.DHGroupKexAlgorithm
 * @see org.vngx.jsch.kex.KexAlgorithm
 *
 * @author Michael Laudati
 */
public final class DHGroup1KexAlgorithm extends DHGroupKexAlgorithm {

	/**
	 * <p>Constant value 'g' is a generator for a subgroup of GF(p).</p>
	 * 
	 * <p>It is recommended to use 2 as generator because it improves efficiency
	 * in multiplication performance.  It is usable even when it is not a 
	 * primitive root, as it still covers half of the space of possible 
	 * residues. [RFC-4419]</p>
	 */
	private static final byte[] G = { 2 };
	/** 
	 * <p>Constant value p for Second Oakley Group.</p>
	 *
	 * <p>The prime is 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.  Its
	 * hexadecimal value is:
	 * <pre>
	 * FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
	 * 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
	 * EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
	 * E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
	 * EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
	 * FFFFFFFF FFFFFFFF
	 * </pre></p>
	 */
	private static final byte[] P = {
		(byte) 0x00,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xC9, (byte) 0x0F, (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2, (byte) 0x34,
		(byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B, (byte) 0x80, (byte) 0xDC, (byte) 0x1C, (byte) 0xD1,
		(byte) 0x29, (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67, (byte) 0xCC, (byte) 0x74,
		(byte) 0x02, (byte) 0x0B, (byte) 0xBE, (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B, (byte) 0x22,
		(byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E, (byte) 0x34, (byte) 0x04, (byte) 0xDD,
		(byte) 0xEF, (byte) 0x95, (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43, (byte) 0x1B,
		(byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D, (byte) 0xF2, (byte) 0x5F, (byte) 0x14, (byte) 0x37,
		(byte) 0x4F, (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51, (byte) 0xC2, (byte) 0x45,
		(byte) 0xE4, (byte) 0x85, (byte) 0xB5, (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E, (byte) 0xC6,
		(byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6, (byte) 0x37, (byte) 0xED, (byte) 0x6B,
		(byte) 0x0B, (byte) 0xFF, (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7, (byte) 0xED,
		(byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB, (byte) 0x5A, (byte) 0x89, (byte) 0x9F, (byte) 0xA5,
		(byte) 0xAE, (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B, (byte) 0x1F, (byte) 0xE6,
		(byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE6, (byte) 0x53, (byte) 0x81,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
	};


	/**
	 * Creates a new instance of {@code DHGroup1KexAlgorithm} using a generator
	 * value of 2 and the Second Oakley Group for p.
	 *
	 * @throws JSchException if any errors occur
	 */
	public DHGroup1KexAlgorithm() throws JSchException {
		super(G, P);
	}

}
