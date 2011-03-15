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

package org.vngx.jsch.hash;

import org.vngx.jsch.algorithm.AlgorithmFactory;
import org.vngx.jsch.algorithm.DefaultAlgorithmFactory;
import org.vngx.jsch.algorithm.UnsupportedAlgorithmException;

/**
 *
 * @see org.vngx.jsch.hash.Hash
 * @see org.vngx.jsch.hash.MAC
 * @see org.vngx.jsch.algorithm.AlgorithmFactory
 *
 * @author Michael Laudati
 */
public final class HashManager {

	/** Singleton instance of {@code HashManager}. */
	private final static HashManager INSTANCE = new HashManager();

	/** Algorithm factory for generating {@code Hash} instances. */
	private AlgorithmFactory<Hash> _hashFactory;
	/** Algorithm factory for generating {@code MAC} instances. */
	private AlgorithmFactory<MAC> _macFactory;


	/**
	 * Private constructor to prevent direct instantiation of singleton.
	 */
	private HashManager() { }

	/**
	 * Returns the singleton instance of {@code HashManager}.
	 *
	 * @return singleton instance of manager
	 */
	public static HashManager getManager() {
		return INSTANCE;
	}

	/**
	 * Creates a new instance of the specified {@code hashName}.  If the
	 * hash is not supported, an exception is thrown.  The method
	 * {@link HashManager#isHashSupported(java.lang.String)} can be called to
	 * check if a certain hash is supported without throwing an exception.
	 *
	 * @param hashName to create
	 * @return hash instance
	 * @throws UnsupportedAlgorithmException if hash is not supported
	 */
	public Hash createHash(String hashName) throws UnsupportedAlgorithmException {
		return getHashFactory().create(hashName);
	}

	/**
	 * Creates a new instance of the specified {@code macName}.  If the
	 * MAC is not supported, an exception is thrown.  The method
	 * {@link HashManager#isMACSupported(java.lang.String)} can be called to
	 * check if a certain MAC is supported without throwing an exception.
	 *
	 * @param macName to create
	 * @return MAC instance
	 * @throws UnsupportedAlgorithmException if MAC is not supported
	 */
	public MAC createMAC(String macName) throws UnsupportedAlgorithmException {
		return getMACFactory().create(macName);
	}

	/**
	 * Returns true if the specified hash name is supported.  This method
	 * should not throw any exceptions; rather {@code false} should be
	 * returned if a hash is not supported.
	 *
	 * @param hashName to check if supported
	 * @return true if hash is supported
	 */
	public boolean isHashSupported(String hashName) {
		return getHashFactory().isSupported(hashName);
	}

	/**
	 * Returns true if the specified MAC name is supported.  This method
	 * should not throw any exceptions; rather {@code false} should be
	 * returned if a MAC is not supported.
	 *
	 * @param macName to check if supported
	 * @return true if MAC is supported
	 */
	public boolean isMACSupported(String macName) {
		return getMACFactory().isSupported(macName);
	}

	/**
	 * Sets the {@code AlgorithmFactory} used to create {@code Hash} instances.
	 *
	 * @param factory to use to create Hash instances
	 */
	public void setHashFactory(AlgorithmFactory<Hash> factory) {
		if( factory == null ) {
			throw new IllegalArgumentException("Hash AlgorithmFactory cannot be null");
		}
		_hashFactory = factory;
	}

	/**
	 * Sets the {@code AlgorithmFactory} used to create {@code MAC} instances.
	 *
	 * @param factory to use to create MAC instances
	 */
	public void setMACFactory(AlgorithmFactory<MAC> factory) {
		if( factory == null ) {
			throw new IllegalArgumentException("MAC AlgorithmFactory cannot be null");
		}
		_macFactory = factory;
	}

	/**
	 * Returns the {@code AlgorithmFactory} used for generating instances 
	 * of {@code Hash}.  If a factory has not yet been created, then a new
	 * default instance is created.
	 * 
	 * @return algorithm factory to use when creating Hash instances
	 */
	private AlgorithmFactory<Hash> getHashFactory() {
		if( _hashFactory == null ) {
			// Lazy initialization of a default algorithm factory for creating
			// the packaged Hash instances
			_hashFactory = new DefaultAlgorithmFactory<Hash>(Hash.class) {
				{
					setAlgorithmImpl(Hash.HASH_MD5,		HashImpl.MD5.class);
					setAlgorithmImpl(Hash.HASH_SHA1,	HashImpl.SHA1.class);
					setAlgorithmImpl(Hash.HASH_SHA256,	HashImpl.SHA256.class);
				}
			};
		}
		return _hashFactory;
	}

	/**
	 * Returns the {@code AlgorithmFactory} used for generating instances
	 * of {@code MAC}.  If a factory has not yet been created, then a new
	 * default instance is created.
	 *
	 * @return algorithm factory to use when creating MAC instances
	 */
	private AlgorithmFactory<MAC> getMACFactory() {
		if( _macFactory == null ) {
			// Lazy initialization of a default algorithm factory for creating
			// the packaged MAC instances
			_macFactory = new DefaultAlgorithmFactory<MAC>(MAC.class) {
				{
					setAlgorithmImpl(MAC.HMAC_MD5,		MACImpl.HMAC_MD5.class);
					setAlgorithmImpl(MAC.HMAC_MD5_96,	MACImpl.HMAC_MD5_96.class);
					setAlgorithmImpl(MAC.HMAC_SHA1,		MACImpl.HMAC_SHA1.class);
					setAlgorithmImpl(MAC.HMAC_SHA1_96,	MACImpl.HMAC_SHA1_96.class);
					setAlgorithmImpl(MAC.HMAC_SHA_256,	MACImpl.HMAC_SHA_256.class);
				}
			};
		}
		return _macFactory;
	}

}
