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

/**
 * Interface to define a factory which can generate instances of 
 * {@code Algorithm} from a specified algorithm name.
 *
 * @author Michael Laudati
 *
 * @param <T> type of algorithms created by factory
 */
public interface AlgorithmFactory<T extends Algorithm> {

	/**
	 * Creates a new instance of the specified {@code algorithmName}.  If the
	 * algorithm is not supported, an exception must be thrown.  The method
	 * {@link AlgorithmFactory#isSupported(java.lang.String)} can be called to
	 * check if a certain algorithm is supported without throwing an exception.
	 *
	 * @param algorithmName to create
	 * @return algorithm instance
	 * @throws UnsupportedAlgorithmException if algorithm is not supported
	 */
	T create(String algorithmName) throws UnsupportedAlgorithmException;

	/**
	 * Creates a new instance of the specified {@code algorithmName} for the
	 * specified {@code session}.  Specifying the {@code Session} instance
	 * allows for custom logic for creating {@code Algorithm} instances.  If the
	 * algorithm is not supported, an exception must be thrown. The method
	 * {@link AlgorithmFactory#isSupported(java.lang.String)} can be called to
	 * check if a certain algorithm is supported without throwing an exception.
	 *
	 * @param algorithmName to create
	 * @param session to create cipher for
	 * @return algorithm instance
	 * @throws UnsupportedAlgorithmException if algorithm is not supported
	 */
	T create(String algorithmName, Session session) throws UnsupportedAlgorithmException;

	/**
	 * Returns true if the specified algorithm name is supported.  This method
	 * should not throw any exceptions; rather {@code false} should be returned
	 * if an algorithm is not supported.
	 *
	 * @param algorithmName to check if supported
	 * @return true if algorithm is supported
	 */
	boolean isSupported(String algorithmName);

}
