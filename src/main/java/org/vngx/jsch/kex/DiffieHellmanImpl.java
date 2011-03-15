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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import org.vngx.jsch.config.JSchConfig;

/**
 * Implementation of {@code DiffieHellman} using the implementation provided
 * through JCE.
 *
 * @see org.vngx.jsch.DiffieHellman
 *
 * @author Michael Laudati
 */
public final class DiffieHellmanImpl implements DiffieHellman {

	/** JCE key pair generator. */
	private final KeyPairGenerator _keyPairGenerator;
	/** JCE key agreement. */
	private final KeyAgreement _keyAgreement;

	/** Prime number. */
	private BigInteger _p;
	/** Generator value. */
	private BigInteger _g;
	/** My public key. */
	private BigInteger _e;
	/** Byte value of public key e. */
	private byte[] _eArray;
	/** Public key. */
	private BigInteger _f;
	/** Shared secret key. */
	private BigInteger _K;
	/** Byte value of shared secret key. */
	private byte[] _KArray;


	/**
	 * Creates a new instance of {@code DiffieHellmanImpl}.
	 * 
	 * @throws NoSuchAlgorithmException if DH algorithm cannot be found
	 * @throws NoSuchProviderException if default provider cannot be found
	 */
	public DiffieHellmanImpl() throws NoSuchAlgorithmException, NoSuchProviderException {
		String provider = JSchConfig.getConfig().getString(JSchConfig.DEFAULT_SECURITY_PROVIDER);
		if( provider.isEmpty() ) {
			_keyPairGenerator = KeyPairGenerator.getInstance("DH");
			_keyAgreement = KeyAgreement.getInstance("DH");
		} else {
			_keyPairGenerator = KeyPairGenerator.getInstance("DH", provider);
			_keyAgreement = KeyAgreement.getInstance("DH", provider);
		}
	}

	@Override
	public byte[] getE() throws Exception {
		if( _e == null ) {
			_keyPairGenerator.initialize(new DHParameterSpec(_p, _g));
			KeyPair myKpair = _keyPairGenerator.generateKeyPair();
			_keyAgreement.init(myKpair.getPrivate());
			//byte[] myPubKeyEnc = myKpair.getPublic().getEncoded();
			_e = ((DHPublicKey) (myKpair.getPublic())).getY();
			_eArray = _e.toByteArray();
		}
		return _eArray;
	}

	@Override
	public byte[] getK() throws Exception {
		if( _K == null ) {
			KeyFactory myKeyFac = KeyFactory.getInstance("DH");
			PublicKey yourPubKey = myKeyFac.generatePublic(new DHPublicKeySpec(_f, _p, _g));
			_keyAgreement.doPhase(yourPubKey, true);
			byte[] mySharedSecret = _keyAgreement.generateSecret();
			_K = new BigInteger(mySharedSecret);
			//_KArray = _K.toByteArray();	// TODO Why assign twice?
			_KArray = mySharedSecret;
		}
		return _KArray;
	}

	@Override
	public void setP(byte[] p) {
		_p = new BigInteger(p);
	}

	@Override
	public void setG(byte[] g) {
		_g = new BigInteger(g);
	}

	@Override
	public void setF(byte[] f) {
		_f = new BigInteger(f);
	}

}
