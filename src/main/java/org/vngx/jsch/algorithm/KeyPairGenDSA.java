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
 * <p>Interface for defining a key-pair generator using the Digital Signature
 * Standard (DSS).</p>
 *
 * <p><a href="http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf">
 * Digital Signature Standard (DSS)</a></p>
 *
 * @author Michael Laudati
 */
public interface KeyPairGenDSA extends Algorithm {

	/**
	 * Initializes the key-pair generator and creates the public and private
	 * keys along with the parameters p, q and g used to generate the keys.
	 *
	 * @param keySize to generate keys
	 * @throws Exception if any errors occur
	 */
	void init(int keySize) throws Exception;

	/**
	 * Returns the generated private key.
	 *
	 * @return private key
	 */
	byte[] getX();

	/**
	 * Returns the generated public key.
	 *
	 * @return public key
	 */
	byte[] getY();

	/**
	 * Returns the prime modulus 'p' used to generate keys.
	 *
	 * @return prime module 'p'
	 */
	byte[] getP();

	/**
	 * Returns the prime number 'q' used to generate keys.
	 *
	 * @return prime number 'q'
	 */
	byte[] getQ();

	/**
	 * Returns the number whose multiplicative order modulo p is q used for
	 * generating keys.
	 *
	 * @return g value
	 */
	byte[] getG();
	
}
