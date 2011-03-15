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

import org.vngx.jsch.Buffer;
import org.vngx.jsch.Util;
import org.vngx.jsch.algorithm.AlgorithmManager;
import org.vngx.jsch.algorithm.Algorithms;
import org.vngx.jsch.algorithm.UnsupportedAlgorithmException;
import org.vngx.jsch.hash.Hash;
import org.vngx.jsch.hash.HashManager;
import org.vngx.jsch.util.KeyType;
import org.vngx.jsch.algorithm.SignatureDSA;
import org.vngx.jsch.algorithm.SignatureRSA;

/**
 * <p>Abstract implementation of {@code KexAlgorithm} for Diffie-Hellman based
 * key exchange algorithms.</p>
 *
 * @author Michael Laudati
 */
public abstract class AbstractDHKexAlgorithm extends KexAlgorithm {

	/** Instance of DH for calculating the Diffie-Hellman values. */
	protected final DiffieHellman _dh;
	

	protected AbstractDHKexAlgorithm() throws UnsupportedAlgorithmException {
		this(HashManager.getManager().createHash(Hash.HASH_SHA1));
	}

	protected AbstractDHKexAlgorithm(Hash hash) throws UnsupportedAlgorithmException {
		super(hash);

		// Create Diffie-Hellman instance for kex
		_dh = AlgorithmManager.getManager().createAlgorithm(Algorithms.DIFFIE_HELLMAN, _session);
	}

	/**
	 * Verifies the server's host key received during the key exchange by
	 * determining the host key algorithm type and using the appropriate
	 * signature (DSA or RSA) to check if supplied key matches.
	 *
	 * @param signatureOfH received in key exchange
	 * @return true if the server's host key is verified
	 * @throws KexException if any errors occur
	 */
	protected boolean verifyHostKey(byte[] signatureOfH) throws KexException {
		Buffer hostKeyBuffer = new Buffer(K_S);
		String keyAlgorithm = Util.byte2str(hostKeyBuffer.getString());	// Read in key algorithm name
		if( KeyType.SSH_DSS.equals(keyAlgorithm) ) {
			_hostKeyType = KeyType.SSH_DSS;
			return verifyHostDSA(hostKeyBuffer, signatureOfH);
		} else if( KeyType.SSH_RSA.equals(keyAlgorithm) ) {
			_hostKeyType = KeyType.SSH_RSA;
			return verifyHostRSA(hostKeyBuffer, signatureOfH);
		}
		throw new KexException("Failed to verify host key, unknown algorithm: "+keyAlgorithm);
	}

	/**
	 * Verifies the server's host key using the RSA signature.
	 *
	 * @param hostKeyBuffer
	 * @param signatureOfH
	 * @return true if server's host key is verified by RSA signature
	 * @throws KexException if any errors occur
	 */
	protected boolean verifyHostRSA(Buffer hostKeyBuffer, byte[] signatureOfH) throws KexException {
		try {
			byte[] ee = hostKeyBuffer.getMPInt();
			byte[] n = hostKeyBuffer.getMPInt();

			// Create SignatureRSA instance for verifying server host
			SignatureRSA sig = AlgorithmManager.getManager().createAlgorithm(Algorithms.SIGNATURE_RSA, _session);
			sig.setPubKey(ee, n);
			sig.update(_H);
			return sig.verify(signatureOfH);
		} catch(Exception e) {
			throw new KexException("Failed to verify host key (RSA)", e);
		}
	}

	/**
	 * Verifies the server's host key using the DSA signature.
	 *
	 * @param hostKeyBuffer
	 * @param signatureOfH
	 * @return true if server's host key is verified by DSA signature
	 * @throws KexException if any errors occur
	 */
	protected boolean verifyHostDSA(Buffer hostKeyBuffer, byte[] signatureOfH) throws KexException {
		try {
			byte[] p = hostKeyBuffer.getMPInt();	// impint p of dsa
			byte[] q = hostKeyBuffer.getMPInt();	// impint q of dsa
			byte[] g = hostKeyBuffer.getMPInt();	// impint g of dsa
			byte[] y = hostKeyBuffer.getMPInt();	// impint public key of dsa

			// Create SignatureDSA instance for verifying server host
			SignatureDSA sig = AlgorithmManager.getManager().createAlgorithm(Algorithms.SIGNATURE_DSS, _session);
			sig.setPubKey(y, p, q, g);
			sig.update(_H);
			return sig.verify(signatureOfH);
		} catch(Exception e) {
			throw new KexException("Failed to verify host key (DSA)", e);
		}
	}

}
