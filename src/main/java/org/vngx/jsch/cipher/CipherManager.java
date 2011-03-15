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

package org.vngx.jsch.cipher;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.vngx.jsch.Session;
import org.vngx.jsch.algorithm.AlgorithmFactory;
import org.vngx.jsch.algorithm.DefaultAlgorithmFactory;
import org.vngx.jsch.algorithm.UnsupportedAlgorithmException;

/**
 * Manager for maintaining the {@code AlgorithmFactory} instance used to create
 * instances of {@code Cipher}.
 *
 * @see org.vngx.jsch.algorithm.AlgorithmFactory
 * @see org.vngx.jsch.cipher.Cipher
 *
 * @author Michael Laudati
 */
public final class CipherManager {

	/** Singleton instance of {@code CipherManager}. */
	private final static CipherManager INSTANCE = new CipherManager();

	/** Algorithm factory for generating {@code Cipher} instances. */
	private AlgorithmFactory<Cipher> _cipherFactory;


	/**
	 * Private constructor to prevent direct instantiation of singleton.
	 */
	private CipherManager() { }

	/**
	 * Returns the singleton instance of the {@code CipherManager}.
	 *
	 * @return singleton instance
	 */
	public static CipherManager getManager() {
		return INSTANCE;
	}

	/**
	 * Creates a new instance of the specified {@code cipherName}.  If the
	 * cipher is not supported, an exception is thrown.  The method
	 * {@link CipherManager#isSupported(java.lang.String)} can be called to
	 * check if a certain cipher is supported without throwing an exception.
	 *
	 * @param cipherName to create
	 * @return cipher instance
	 * @throws UnsupportedAlgorithmException if cipher is not supported
	 */
	public Cipher createCipher(String cipherName) throws UnsupportedAlgorithmException {
		return getCipherFactory().create(cipherName);
	}

	/**
	 * Creates a new instance of the specified {@code cipherName} for the
	 * specified {@code session}.  Specifying the {@code Session} instance
	 * allows for custom logic for creating {@code Cipher} instances.  If the
	 * cipher is not supported, an exception must be thrown.  The method
	 * {@link CipherManager#isSupported(java.lang.String)} can be called to
	 * check if a certain cipher is supported without throwing an exception.
	 *
	 * @param cipherName to create
	 * @param session to create cipher for
	 * @return cipher instance
	 * @throws UnsupportedAlgorithmException if cipher is not supported
	 */
	public Cipher createCipher(String cipherName, Session session) throws UnsupportedAlgorithmException {
		return getCipherFactory().create(cipherName, session);
	}

	/**
	 * Returns true if the specified cipher name is supported.  This method
	 * should not throw any exceptions; rather {@code false} should be returned
	 * if a cipher is not supported.
	 *
	 * @param cipherName to check if supported
	 * @return true if cipher is supported
	 */
	public boolean isSupported(String cipherName) {
		return getCipherFactory().isSupported(cipherName);
	}

	/**
	 * Returns a list containing only the cipher names found in the specified
	 * {@code cipherList} which are supported by the manager.
	 *
	 * @param cipherList
	 * @return list of supported cipher names
	 */
	public List<String> supportedCiphers(List<String> cipherList) {
		if( cipherList == null || cipherList.isEmpty() ) {
			return Collections.emptyList();
		}
		List<String> checkedCiphers = new LinkedList<String>();
		for( String cipherName : cipherList ) {
			if( isSupported(cipherName) ) {
				checkedCiphers.add(cipherName);
			}
		}
		return checkedCiphers;
	}

	/**
	 * Sets the {@code AlgorithmFactory} instance used by the manager to create
	 * {@code Cipher} instances.
	 *
	 * @param factory used to create ciphers in manager
	 */
	public void setCipherFactory(AlgorithmFactory<Cipher> factory) {
		if( factory == null ) {
			throw new IllegalArgumentException("CipherFactory cannot be null");
		}
		_cipherFactory = factory;
	}

	/**
	 * Returns the {@code AlgorithmFactory} used for generating instances of
	 * {@code Cipher}.  If a factory has not yet been created, then a new
	 * default instance is created.
	 *
	 * @return algorithm factory to use when creating Cipher instances
	 */
	private AlgorithmFactory<Cipher> getCipherFactory() {
		if( _cipherFactory == null ) {
			// Lazy initialization of a default algorithm factory for creating
			// the packaged Cipher instances
			_cipherFactory = new DefaultAlgorithmFactory<Cipher>(Cipher.class) {
				{
					setAlgorithmImpl(Cipher.CIPHER_3DES_CBC,		CipherImpl.TripleDESCBC.class);
					setAlgorithmImpl(Cipher.CIPHER_3DES_CTR,		CipherImpl.TripleDESCTR.class);
					setAlgorithmImpl(Cipher.CIPHER_AES128_CBC,		CipherImpl.AES128CBC.class);
					setAlgorithmImpl(Cipher.CIPHER_AES128_CTR,		CipherImpl.AES128CTR.class);
					setAlgorithmImpl(Cipher.CIPHER_AES192_CBC,		CipherImpl.AES192CBC.class);
					setAlgorithmImpl(Cipher.CIPHER_AES192_CTR,		CipherImpl.AES192CTR.class);
					setAlgorithmImpl(Cipher.CIPHER_AES256_CBC,		CipherImpl.AES256CBC.class);
					setAlgorithmImpl(Cipher.CIPHER_AES256_CTR,		CipherImpl.AES256CTR.class);
					setAlgorithmImpl(Cipher.CIPHER_ARCFOUR,		CipherImpl.ARCFOUR.class);
					setAlgorithmImpl(Cipher.CIPHER_ARCFOUR128,		CipherImpl.ARCFOUR128.class);
					setAlgorithmImpl(Cipher.CIPHER_ARCFOUR256,		CipherImpl.ARCFOUR256.class);
					setAlgorithmImpl(Cipher.CIPHER_BLOWFISH_CBC,	CipherImpl.BlowfishCBC.class);
					setAlgorithmImpl(Cipher.CIPHER_NONE,			CipherNone.class);
				}

				@Override
				protected boolean validateImpl(Cipher algorithmImpl) throws UnsupportedAlgorithmException {
					try {
						algorithmImpl.init(Cipher.ENCRYPT_MODE, new byte[algorithmImpl.getBlockSize()], new byte[algorithmImpl.getIVSize()]);
						return true;
					} catch(Exception e) {
						return false;
					}
				}
			};
		}
		return _cipherFactory;
	}

}
