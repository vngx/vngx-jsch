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

package org.vngx.jsch.algorithm;

import org.vngx.jsch.Session;
import org.vngx.jsch.kex.DHGexSha1KexAlgorithm;
import org.vngx.jsch.kex.DHGexSha256KexAlgorithm;
import org.vngx.jsch.kex.DHGroup14KexAlgorithm;
import org.vngx.jsch.kex.DHGroup1KexAlgorithm;
import org.vngx.jsch.kex.DiffieHellmanImpl;

/**
 * Algorithm manager provides a central location for creating {@code Algorithm}
 * instances using the manager's {@code AlgorithmFactory}.
 *
 * @author Michael Laudati
 */
public final class AlgorithmManager {

	/** Singleton instance of algorithm manager. */
	private final static AlgorithmManager INSTANCE = new AlgorithmManager();

	/** Factory used for creating algorithm instances. */
	private AlgorithmFactory<Algorithm> _algorithmFactory;


	/**
	 * Private constructor to prevent direct instantiation of singleton.
	 */
	private AlgorithmManager() { }

	/**
	 * Returns the singleton instance of {@code AlgorithmManager}.
	 *
	 * @return singleton instance
	 */
	public static AlgorithmManager getManager() {
		return INSTANCE;
	}

	@SuppressWarnings("unchecked")
	public <T extends Algorithm> T createAlgorithm(String algorithmName) throws UnsupportedAlgorithmException {
		return (T) getAlgorithmFactory().create(algorithmName);
	}

	@SuppressWarnings("unchecked")
	public <T extends Algorithm> T createAlgorithm(String algorithmName, Session session) throws UnsupportedAlgorithmException {
		return (T) getAlgorithmFactory().create(algorithmName, session);
	}

	/**
	 * Sets the algorithm factory to use when creating algorithm instances.
	 *
	 * @param factory to create algorithm instances
	 */
	public void setAlgorithmFactory(AlgorithmFactory<Algorithm> factory) {
		if( factory == null ) {
			throw new IllegalArgumentException("Algorithm factory cannot be null");
		}
		_algorithmFactory = factory;
	}

	/**
	 * Returns the {@code AlgorithmFactory} used by the manager to create
	 * instances of {@code Algorithm}.  If a factory has not been set, then a
	 * default factory is initialized.
	 *
	 * @return factory for creating algorithms
	 */
	private AlgorithmFactory<Algorithm> getAlgorithmFactory() {
		if( _algorithmFactory == null ) {
			// Lazy initialization of default algorithm factory
			_algorithmFactory = new DefaultAlgorithmFactory<Algorithm>(Algorithm.class) {
				{
					setAlgorithmImpl(Compression.COMPRESSION_ZLIB, CompressionImpl.class);
					setAlgorithmImpl(Compression.COMPRESSION_ZLIB_OPENSSH, CompressionImpl.class);
					setAlgorithmImpl(Algorithms.DIFFIE_HELLMAN, DiffieHellmanImpl.class);
					setAlgorithmImpl(Algorithms.DIFFIE_HELLMAN_GROUP1_SHA1, DHGroup1KexAlgorithm.class);
					setAlgorithmImpl(Algorithms.DIFFIE_HELLMAN_GROUP14_SHA1, DHGroup14KexAlgorithm.class);
					setAlgorithmImpl(Algorithms.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1, DHGexSha1KexAlgorithm.class);
					setAlgorithmImpl(Algorithms.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256, DHGexSha256KexAlgorithm.class);
					setAlgorithmImpl(Algorithms.RANDOM, RandomImpl.class);
					setAlgorithmImpl(Algorithms.KEYPAIRGEN_DSA, KeyPairGenDSAImpl.class);
					setAlgorithmImpl(Algorithms.KEYPAIRGEN_RSA, KeyPairGenRSAImpl.class);
					setAlgorithmImpl(Algorithms.SIGNATURE_DSS, SignatureDSAImpl.class);
					setAlgorithmImpl(Algorithms.SIGNATURE_RSA, SignatureRSAImpl.class);
				}
			};
		}
		return _algorithmFactory;
	}

}
