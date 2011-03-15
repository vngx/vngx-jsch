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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Implementation of {@code Random} which wraps a {@code SecureRandom} instance
 * to create cryptographically strong random numbers.
 *
 * @see org.vngx.jsch.Random
 * @see java.security.SecureRandom
 *
 * @author Michael Laudati
 */
public final class RandomImpl implements Random {

	/** Cryptographically strong RNG to create random data. */
	private final SecureRandom _secureRandom;
	/** Temporary buffer to fill with random data to copy into specified buffer. */
	private final byte[] _tmp = new byte[256];


	/**
	 * Creates a new instance of {@code RandomImpl}.
	 */
	public RandomImpl() {
		_secureRandom = new SecureRandom();
	}

	/**
	 * Creates a new instance of {@code RandomImpl} which uses the specified JCE
	 * algorithm for creating random numbers.
	 *
	 * @param algorithm to use
	 * @throws NoSuchAlgorithmException
	 */
	public RandomImpl(String algorithm) throws NoSuchAlgorithmException {
		_secureRandom = SecureRandom.getInstance(algorithm);
	}

	/**
	 * Fills the specified array with random data from the specified offset
	 * through length using the wrapped RNG instance.
	 * 
	 * @param buffer array to fill with random data
	 * @param offset position
	 * @param length
	 */
	@Override
	public void fill(byte[] buffer, int offset, int length) {
		if( length <= _tmp.length ) {
			_secureRandom.nextBytes(_tmp);
			System.arraycopy(_tmp, 0, buffer, offset, length);
		} else {
			byte[] temp = new byte[length];
			_secureRandom.nextBytes(temp);
			System.arraycopy(temp, 0, buffer, offset, length);
		}
		
	}

}
