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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Implementation of <code>KeyPairGenRSA</code> for generating key pairs using
 * RSA encryption.
 *
 * @author Michael Laudati
 */
public final class KeyPairGenRSAImpl implements KeyPairGenRSA {

	/** Private key value. */
	private byte[] _d;
	/** Public key value. */
	private byte[] _e;
	/** Modulus 'n' calculated from (p * q). */
	private byte[] _n;
	/** Coefficient value. */
	private byte[] _c;
	/** Exponent of p value. */
	private byte[] _ep;
	/** Exponent of q value. */
	private byte[] _eq;
	/** Prime number p. */
	private byte[] _p;
	/** Prime number q. */
	private byte[] _q;


	@Override
	public void init(int keySize) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(keySize, new SecureRandom());
		KeyPair pair = keyGen.generateKeyPair();
		RSAPublicKey pubKey = (RSAPublicKey) pair.getPublic();
		RSAPrivateCrtKey prvKey = (RSAPrivateCrtKey) pair.getPrivate();

		_d  = prvKey.getPrivateExponent().toByteArray();
		_e  = pubKey.getPublicExponent().toByteArray();
		_n  = prvKey.getModulus().toByteArray();
		_c  = prvKey.getCrtCoefficient().toByteArray();
		_ep = prvKey.getPrimeExponentP().toByteArray();
		_eq = prvKey.getPrimeExponentQ().toByteArray();
		_p  = prvKey.getPrimeP().toByteArray();
		_q  = prvKey.getPrimeQ().toByteArray();
	}

	@Override
	public byte[] getD() {
		return _d;
	}

	@Override
	public byte[] getE() {
		return _e;
	}

	@Override
	public byte[] getN() {
		return _n;
	}

	@Override
	public byte[] getC() {
		return _c;
	}

	@Override
	public byte[] getEP() {
		return _ep;
	}

	@Override
	public byte[] getEQ() {
		return _eq;
	}

	@Override
	public byte[] getP() {
		return _p;
	}

	@Override
	public byte[] getQ() {
		return _q;
	}

}
