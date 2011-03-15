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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.vngx.jsch.Buffer;

/**
 * Implementation of <code>SignatureRSA</code>.
 *
 * @author Michael Laudati
 */
public final class SignatureRSAImpl implements SignatureRSA {

	/** Java JCE signature instance. */
	private final Signature _signature;
	/** Java JCE key factory. */
	private final KeyFactory _keyFactory;


	public SignatureRSAImpl() throws NoSuchAlgorithmException {
		_signature = Signature.getInstance("SHA1withRSA");
		_keyFactory = KeyFactory.getInstance("RSA");
	}

	@Override
	public void setPubKey(byte[] e, byte[] n) throws Exception {
		RSAPublicKeySpec rsaPubKeySpec = new RSAPublicKeySpec(new BigInteger(n), new BigInteger(e));
		PublicKey pubKey = _keyFactory.generatePublic(rsaPubKeySpec);
		_signature.initVerify(pubKey);
	}

	@Override
	public void setPrvKey(byte[] d, byte[] n) throws Exception {
		RSAPrivateKeySpec rsaPrivKeySpec = new RSAPrivateKeySpec(new BigInteger(n), new BigInteger(d));
		PrivateKey prvKey = _keyFactory.generatePrivate(rsaPrivKeySpec);
		_signature.initSign(prvKey);
	}

	@Override
	public byte[] sign() throws Exception {
		return _signature.sign();
	}

	@Override
	public void update(byte[] data) throws Exception {
		_signature.update(data);
	}

	@Override
	public boolean verify(byte[] signature) throws Exception {
		if( (signature[0] | signature[1] | signature[2]) == 0 ) {
			Buffer sigBuffer = new Buffer(signature);
			sigBuffer.getString();				// Skip first string
			signature = sigBuffer.getString();	// second is signature
		}
		return _signature.verify(signature);
	}

}
