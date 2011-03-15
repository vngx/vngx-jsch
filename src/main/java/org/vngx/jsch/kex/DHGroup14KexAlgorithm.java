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
 * <p>Implementation of {@code KexAlgorithm} for "diffie-hellman-group14-sha1"
 * key exchange for SSH.  The "diffie-hellman-group1-sha1" method specifies the
 * Diffie-Hellman key exchange with SHA-1 as HASH, and Oakley Group 14 [RFC3526]
 * (2048- bit MODP Group).  This method MUST also be supported.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-8.2">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: 8.2. diffie-hellman-group14-sha1
 * </a></p>
 * <p><a href="http://tools.ietf.org/html/rfc3526#section-3">RFC 3526 - More
 * Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange 
 * (IKE): 2048-bit MODP Group</a></p>
 *
 * <p><strong>Note:</strong> The default JCE implementation of Diffie-Hellman
 * does not support key sizes greater than 1024 bits.  This implementation must
 * use a security provider (e.g. BouncyCastle) which supports a key size of at
 * least 2048 bits.</p>
 *
 * @see org.vngx.jsch.kex.DHGroupKexAlgorithm
 * @see org.vngx.jsch.kex.KexAlgorithm
 *
 * @author Michael Laudati
 */
public final class DHGroup14KexAlgorithm extends DHGroupKexAlgorithm {

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
	 * <p>Constant value p for Oakley Group 14.</p>
	 *
	 * <p>This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
	 * Its hexadecimal value is:
	 * <pre>
	 *	FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
	 *	29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
	 *	EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
	 *	E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
	 *	EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
	 *	C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
	 *	83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
	 *	670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
	 *	E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
	 *	DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
	 *	15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
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
		(byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE4, (byte) 0x5B, (byte) 0x3D,
		(byte) 0xC2, (byte) 0x00, (byte) 0x7C, (byte) 0xB8, (byte) 0xA1, (byte) 0x63, (byte) 0xBF, (byte) 0x05,
		(byte) 0x98, (byte) 0xDA, (byte) 0x48, (byte) 0x36, (byte) 0x1C, (byte) 0x55, (byte) 0xD3, (byte) 0x9A,
		(byte) 0x69, (byte) 0x16, (byte) 0x3F, (byte) 0xA8, (byte) 0xFD, (byte) 0x24, (byte) 0xCF, (byte) 0x5F,
		(byte) 0x83, (byte) 0x65, (byte) 0x5D, (byte) 0x23, (byte) 0xDC, (byte) 0xA3, (byte) 0xAD, (byte) 0x96,
		(byte) 0x1C, (byte) 0x62, (byte) 0xF3, (byte) 0x56, (byte) 0x20, (byte) 0x85, (byte) 0x52, (byte) 0xBB,
		(byte) 0x9E, (byte) 0xD5, (byte) 0x29, (byte) 0x07, (byte) 0x70, (byte) 0x96, (byte) 0x96, (byte) 0x6D,
		(byte) 0x67, (byte) 0x0C, (byte) 0x35, (byte) 0x4E, (byte) 0x4A, (byte) 0xBC, (byte) 0x98, (byte) 0x04,
		(byte) 0xF1, (byte) 0x74, (byte) 0x6C, (byte) 0x08, (byte) 0xCA, (byte) 0x18, (byte) 0x21, (byte) 0x7C,
		(byte) 0x32, (byte) 0x90, (byte) 0x5E, (byte) 0x46, (byte) 0x2E, (byte) 0x36, (byte) 0xCE, (byte) 0x3B,
		(byte) 0xE3, (byte) 0x9E, (byte) 0x77, (byte) 0x2C, (byte) 0x18, (byte) 0x0E, (byte) 0x86, (byte) 0x03,
		(byte) 0x9B, (byte) 0x27, (byte) 0x83, (byte) 0xA2, (byte) 0xEC, (byte) 0x07, (byte) 0xA2, (byte) 0x8F,
		(byte) 0xB5, (byte) 0xC5, (byte) 0x5D, (byte) 0xF0, (byte) 0x6F, (byte) 0x4C, (byte) 0x52, (byte) 0xC9,
		(byte) 0xDE, (byte) 0x2B, (byte) 0xCB, (byte) 0xF6, (byte) 0x95, (byte) 0x58, (byte) 0x17, (byte) 0x18,
		(byte) 0x39, (byte) 0x95, (byte) 0x49, (byte) 0x7C, (byte) 0xEA, (byte) 0x95, (byte) 0x6A, (byte) 0xE5,
		(byte) 0x15, (byte) 0xD2, (byte) 0x26, (byte) 0x18, (byte) 0x98, (byte) 0xFA, (byte) 0x05, (byte) 0x10,
		(byte) 0x15, (byte) 0x72, (byte) 0x8E, (byte) 0x5A, (byte) 0x8A, (byte) 0xAC, (byte) 0xAA, (byte) 0x68,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
	};

	/**
	 * Creates a new instance of {@code DHGroup14KexAlgorithm} using a generator
	 * value of 2 and the Oakley Group 14 for p.
	 *
	 * @throws JSchException if any errors occur
	 */
	public DHGroup14KexAlgorithm() throws JSchException {
		super(G, P);
	}

}
