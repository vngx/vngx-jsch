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
 * CONCEPTS, INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch.algorithm;

/**
 * <p>Interface for defining a key-pair generator using the RSA algorithm.</p>
 *
 * <p><a href="http://www.rsa.com/rsalabs/node.asp?id=2125">RSA Cryptography
 * Standard</a></p>
 *
 * @author Michael Laudati
 */
public interface KeyPairGenRSA extends Algorithm {

	/**
	 * Initializes the key-pair generator and creates the public and private
	 * keys along with the parameters p, q, eq, ep, c, n, d and e used to
	 * generate the keys.
	 *
	 * @param keySize to generate keys
	 * @throws Exception if any errors occur
	 */
	void init(int keySize) throws Exception;

	/**
	 * Returns the private key exponent 'd' used for key generation.
	 *
	 * @return private key exponent 'd'
	 */
	byte[] getD();

	/**
	 * Returns the public key exponent 'e' used for key generation.
	 *
	 * @return public key exponent 'e'
	 */
	byte[] getE();

	/**
	 * Returns the modulus 'n' calculated from (p * q) used for key generation.
	 *
	 * @return modulus 'n'
	 */
	byte[] getN();

	/**
	 * Returns the coefficient 'c' used for key generation.
	 *
	 * @return coefficient 'c'
	 */
	byte[] getC();

	/**
	 * Returns the exponent of 'p' used for key generation.
	 *
	 * @return exponent of 'p'
	 */
	byte[] getEP();

	/**
	 * Returns the exponent of 'q' used for key generation.
	 *
	 * @return exponent of 'q'
	 */
	byte[] getEQ();

	/**
	 * Returns the prime number 'p' used for key generation.
	 *
	 * @return prime number 'p'
	 */
	byte[] getP();

	/**
	 * Returns the prime number 'q' used for key generation.
	 *
	 * @return prime number 'q'
	 */
	byte[] getQ();
	
}
