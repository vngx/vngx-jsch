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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.vngx.jsch.config.JSchConfig;

/**
 * Implementation of {@code Hash} providing a wrapper for Java's built in
 * message digest algorithms.  The security provider for creating instances is
 * set with the {@code JSchConfig} property defined as
 * {@link org.vngx.jsch.config.JSchConfig#DEFAULT_SECURITY_PROVIDER}; by
 * default the default security provider will be used. If another security
 * provider has been registered, then the security provider name in the
 * configuration will be used when creating instances.
 *
 * @see java.security.MessageDigest
 * @see org.vngx.jsch.hash.Hash
 * @see org.vngx.jsch.config.JSchConfig
 * @see org.vngx.jsch.config.JSchConfig#DEFAULT_SECURITY_PROVIDER
 *
 * @author Michael Laudati
 */
public class HashImpl implements Hash {

	/** Message digest provided through Java for hashing. */
	private final MessageDigest _md;
	/** Block size of message digest. */
	private final int _blockSize;

	/**
	 * Creates a new instance of {@code HashImpl}.
	 *
	 * @param messageDigest algorithm name
	 * @param blockSize of hash
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public HashImpl(String messageDigest, int blockSize) throws NoSuchAlgorithmException, NoSuchProviderException {
		String provider = JSchConfig.getConfig().getString(JSchConfig.DEFAULT_SECURITY_PROVIDER);
		_md = provider.length()==0 ? MessageDigest.getInstance(messageDigest) :
									 MessageDigest.getInstance(messageDigest, provider);
		_blockSize = blockSize;
	}

	@Override
	public int getBlockSize() {
		return _blockSize;
	}

	@Override
	public void update(byte[] buffer, int offset, int length) {
		_md.update(buffer, offset, length);
	}

	@Override
	public byte[] digest() {
		return _md.digest();
	}

	/**
	 * Implementation of {@code HashImpl} using Java's MD5 message digest.
	 *
	 * @author Michael Laudati
	 */
	public static class MD5 extends HashImpl {
		/**
		 * Creates a new instance of {@code MD5}.
		 * 
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException 
		 */
		public MD5() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("MD5", 16);
		}
	}

	/**
	 * Implementation of {@code HashImpl} using Java's SHA1 message digest.
	 *
	 * @author Michael Laudati
	 */
	public static class SHA1 extends HashImpl {
		/**
		 * Creates a new instance of {@code SHA1}.
		 *
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 */
		public SHA1() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("SHA-1", 20);
		}
	}

	/**
	 * Implementation of {@code HashImpl} using Java's SHA-256 message digest.
	 *
	 * @author Michael Laudati
	 */
	public static class SHA256 extends HashImpl {
		/**
		 * Creates a new instance of {@code SHA256}.
		 * 
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 */
		public SHA256() throws NoSuchAlgorithmException, NoSuchProviderException {
			super("SHA-256", 32);
		}
	}

}
