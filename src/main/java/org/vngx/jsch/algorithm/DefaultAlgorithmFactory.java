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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.vngx.jsch.Session;

/**
 * <p>Default implementation of the {@code AlgorithmFactory} factory pattern
 * which supports the use of generics to create instances of {@code Algorithm}
 * of the specified type {@code T}.  Instances store a map containing algorithm
 * names mapped to their respective implementation {@code Class}, which is used
 * to create new instances through reflection to the default no-arg constructor.
 * The implementation caches requests to the {@code isSupported} method for
 * additional performance.</p>
 *
 * <p><strong>Note:</strong> Algorithm implementations MUST have a default empty
 * constructor in order to be supported by this factory.</p>
 *
 * <p><strong>Note:</strong> This implementation is thread-safe.</p>
 *
 * @see org.vngx.jsch.algorithm.Algorithm
 * @see org.vngx.jsch.algorithm.AlgorithmFactory
 *
 * @author Michael Laudati
 *
 * @param <T> type of algorithm
 */
public class DefaultAlgorithmFactory<T extends Algorithm> implements AlgorithmFactory<T> {

	/** Type of algorithms the factory creates. */
	protected final String _algorithmType;

	/** Map which maintains the algorithm implementation class for each algorithm name. */
	protected final ConcurrentMap<String,Class<? extends T>> _algorithmImplMap =
			new ConcurrentHashMap<String,Class<? extends T>>();
	/** Map which stores which algorithms are checked based on fully qualified class. */
	protected final ConcurrentMap<String,Boolean> _checkedAlgorithms =
			new ConcurrentHashMap<String,Boolean>();


	/**
	 * Creates a new instance of {@code DefaultAlgorithmFactory} which
	 * generates instances of the specified algorithm type {@code T}.
	 *
	 * @param algorithmType
	 */
	public DefaultAlgorithmFactory(Class<T> algorithmType) {
		_algorithmType = algorithmType.getSimpleName();
	}

	@Override
	public T create(String algorithmName) throws UnsupportedAlgorithmException {
		if( algorithmName == null ) {
			throw new UnsupportedAlgorithmException(_algorithmType + " name cannot be null");
		} else if( !_algorithmImplMap.containsKey(algorithmName) ) {
			throw new UnsupportedAlgorithmException(_algorithmType + " implementation does not exist for: " + algorithmName);
		}
		try {
			return _algorithmImplMap.get(algorithmName).newInstance();
		} catch(Exception e) {
			throw new UnsupportedAlgorithmException("Failed to create " + _algorithmType + " for: " + algorithmName, e);
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	public T create(String algorithmName, Session session) throws UnsupportedAlgorithmException {
		if( session == null || session.getConfig().getString(algorithmName).isEmpty() ) {
			return create(algorithmName);
		}
		try {
			return (T) Class.forName(session.getConfig().getString(algorithmName)).newInstance();
		} catch(Exception e) {
			throw new UnsupportedAlgorithmException("Failed to create " + _algorithmType + " for: " + algorithmName, e);
		}
	}

	@Override
	public boolean isSupported(String algorithmName) {
		if( algorithmName == null || !_algorithmImplMap.containsKey(algorithmName) ) {
			return false;
		}
		String algorithmClassName = _algorithmImplMap.get(algorithmName).getName();
		Boolean supported;
		if( (supported = _checkedAlgorithms.get(algorithmClassName)) == null ) {
			try {
				// Attempt to create an instance of algorithm to validate it has
				// a no-arg constructor and it is capable of being instantiated
				T algImpl = create(algorithmName);
				_checkedAlgorithms.put(algorithmClassName, supported = validateImpl(algImpl));
			} catch(Exception e) {
				_checkedAlgorithms.put(algorithmClassName, supported = false);
			}
		}
		return supported;
	}

	/**
	 * Returns true if the specified algorithm implementation is valid, allowing
	 * implementations to provide custom logic for validation.
	 *
	 * @param algorithmImpl
	 * @return true if implementation class is valid
	 * @throws UnsupportedAlgorithmException if any errors occur
	 */
	protected boolean validateImpl(T algorithmImpl) throws UnsupportedAlgorithmException {
		return true;
	}

	/**
	 * Sets the specified algorithm implementation class for the specified
	 * algorithm name.
	 *
	 * @param algorithmName
	 * @param algorithmImpl
	 */
	public void setAlgorithmImpl(final String algorithmName, final Class<? extends T> algorithmImpl) {
		if( algorithmName == null || algorithmName.isEmpty() ) {
			throw new IllegalArgumentException(_algorithmType + " name cannot be null/empty: " + algorithmName);
		} else if( algorithmImpl == null ) {
			throw new IllegalArgumentException(_algorithmType + " implementation class cannot be null");
		}
		// Add algorithm implementation class
		_algorithmImplMap.put(algorithmName, algorithmImpl);
	}

	/**
	 * Sets the specified algorithm implementation (fully qualified class name)
	 * for the specified algorithm name.
	 *
	 * @param algorithmName
	 * @param algorithmImpl
	 */
	@SuppressWarnings("unchecked")
	public void setAlgorithmImpl(final String algorithmName, final String algorithmImpl) {
		if( algorithmName == null || algorithmName.isEmpty() ) {
			throw new IllegalArgumentException(_algorithmType + " name cannot be null/empty: " + algorithmName);
		} else if( algorithmImpl == null ) {
			throw new IllegalArgumentException(_algorithmType + " implementation class cannot be null");
		} else if( algorithmImpl.isEmpty() ) {
			throw new IllegalArgumentException(_algorithmType + " implementation cannot be null/empty");
		}
		try {	// Add algorithm implementation class if it validates
			_algorithmImplMap.put(algorithmName, (Class<? extends T>) Class.forName(algorithmImpl));
		} catch(Exception e) {
			throw new IllegalArgumentException("Failed to validate " + _algorithmType + " implementation for: "+algorithmImpl, e);
		}
	}

	/**
	 * Returns the implementation class used for creating {@code Algorithm}
	 * instances of the specified factory type.
	 *
	 * @param algorithmName
	 * @return algorithm implementation class
	 */
	public Class<? extends T> getAlgorithmImpl(String algorithmName) {
		return _algorithmImplMap.get(algorithmName);
	}

}
