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
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import org.vngx.jsch.Buffer;

/**
 * Implementation of <code>SignatureDSA</code>.
 *
 * @author Michael Laudati
 */
public final class SignatureDSAImpl implements SignatureDSA {

	/** Java JCE signature for signing using DSA encryption. */
	private final Signature _signature;
	/** Java JCE key factory. */
	private final KeyFactory _keyFactory;


	public SignatureDSAImpl() throws NoSuchAlgorithmException {
		_signature = Signature.getInstance("SHA1withDSA");
		_keyFactory = KeyFactory.getInstance("DSA");
	}

	@Override
	public void setPubKey(byte[] y, byte[] p, byte[] q, byte[] g) throws Exception {
		DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(new BigInteger(y), new BigInteger(p), new BigInteger(q), new BigInteger(g));
		PublicKey pubKey = _keyFactory.generatePublic(dsaPubKeySpec);
		_signature.initVerify(pubKey);
	}

	@Override
	public void setPrvKey(byte[] x, byte[] p, byte[] q, byte[] g) throws Exception {
		DSAPrivateKeySpec dsaPrivKeySpec = new DSAPrivateKeySpec(new BigInteger(x), new BigInteger(p), new BigInteger(q), new BigInteger(g));
		PrivateKey prvKey = _keyFactory.generatePrivate(dsaPrivKeySpec);
		_signature.initSign(prvKey);
	}

	@Override
	public byte[] sign() throws Exception {
		Buffer signature = new Buffer(_signature.sign());
		// signature is in ASN.1
		// SEQUENCE::={ r INTEGER, offset INTEGER }
		signature.setOffSet(3);
		byte[] r = signature.getBytes(new byte[signature.getByte()]);
		byte[] s = signature.getBytes(new byte[signature.getByte()]);
		
		// result must be 40 bytes, but length of r and offset may not be 20 bytes
		byte[] result = new byte[40];
		System.arraycopy(r, (r.length > 20) ? 1 : 0,
				result, (r.length > 20) ? 0 : 20 - r.length,
				(r.length > 20) ? 20 : r.length);
		System.arraycopy(s, (s.length > 20) ? 1 : 0,
				result, (s.length > 20) ? 20 : 40 - s.length,
				(s.length > 20) ? 20 : s.length);
		return result;
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

		// ASN.1
		int frst = (signature[0]  & 0x80) != 0 ? 1 : 0;
		int scnd = (signature[20] & 0x80) != 0 ? 1 : 0;
	
		byte[] tmp = new byte[signature.length + 6 + frst + scnd];
		tmp[0] = (byte) 0x30;
		tmp[1] = (byte) ((byte) 0x2c + (byte) frst + (byte) scnd);
		tmp[2] = (byte) 0x02;
		tmp[3] = (byte) ((byte) 0x14 + (byte) frst);
		System.arraycopy(signature, 0, tmp, 4 + frst, 20);
		tmp[4 + tmp[3]] = (byte) 0x02;
		tmp[5 + tmp[3]] = (byte) ((byte) 0x14 + (byte) scnd);
		System.arraycopy(signature, 20, tmp, 6 + tmp[3] + scnd, 20);
		signature = tmp;

		return _signature.verify(signature);
	}

}
