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
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

/**
 * Implementation of <code>KeyPairGenDSA</code> for generating key pairs using
 * DSA encryption.
 *
 * @author Michael Laudati
 */
public final class KeyPairGenDSAImpl implements KeyPairGenDSA {

	/** Private key value. */
	private byte[] _x;
	/** Public key value. */
	private byte[] _y;
	/** Prime modulus 'p'. */
	private byte[] _p;
	/** Prime number 'q'. */
	private byte[] _q;
	/** Number whose multiplicative order modulo p is q. */
	private byte[] _g;


	@Override
	public void init(int keySize) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		keyGen.initialize(keySize, new SecureRandom());
		KeyPair pair = keyGen.generateKeyPair();
		_x = ((DSAPrivateKey) pair.getPrivate()).getX().toByteArray();
		_y = ((DSAPublicKey) pair.getPublic()).getY().toByteArray();

		DSAParams params = ((DSAKey) pair.getPrivate()).getParams();
		_p = params.getP().toByteArray();
		_q = params.getQ().toByteArray();
		_g = params.getG().toByteArray();
	}

	@Override
	public byte[] getX() {
		return _x;
	}

	@Override
	public byte[] getY() {
		return _y;
	}

	@Override
	public byte[] getP() {
		return _p;
	}

	@Override
	public byte[] getQ() {
		return _q;
	}

	@Override
	public byte[] getG() {
		return _g;
	}

}
