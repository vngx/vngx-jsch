/*
 * Copyright (c) 2002-2010 Atsuhiko Yamanaka, JCraft,Inc.  All rights reserved.
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
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
 * INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch.util;

import java.util.Arrays;
import org.vngx.jsch.algorithm.Random;
import org.vngx.jsch.Util;
import org.vngx.jsch.algorithm.AlgorithmManager;
import org.vngx.jsch.algorithm.Algorithms;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.hash.HashManager;
import org.vngx.jsch.hash.MAC;

/**
 * Implementation of <code>HostKey</code> where the host value is stored as a
 * hashed value rather than plaintext.  When comparing against the key, the host
 * to compare is hashed with the same hash/salt and then compared to this hashed
 * host.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
class HashedHostKey extends HostKey {

	/** Constant for start of host indicating to create hash. */
	static final String HASH_MAGIC = "|1|";
	/** Constant for delimiter in host when HASH_MAGIC is present. */
	static final String HASH_DELIM = "|";
	
	/** Instance of random for creating hashed keys. */
	private static Random $random;
	/** Message authentication code instance for creating hashes. */
	private static MAC $hmacsha1;

	/** Salt value used to hash the host value. */
	private byte[] _salt;
	/** Hash retrieved from host. */
	private byte[] _hashedHost;


	/**
	 * Creates a new instance of <code>HashedHostKey</code> with the specified
	 * host value and key.
	 *
	 * @param host value
	 * @param key value
	 * @throws JSchException
	 */
	HashedHostKey(String host, byte[] key) throws JSchException {
		this(host, null, key);
	}

	/**
	 * Creates a new instance of <code>HashedHostKey</code> with the specified
	 * host value, key type and key value.  If the host value is not yet hashed,
	 * then the host value will be hashed using a randomly generated salt and
	 * set accordingly.<p>
	 *
	 * Hashed hosts follow the known hosts format as follows:<br>
	 *		|1|salt_value|hashed_host_value key_value
	 *
	 * @param host
	 * @param type
	 * @param key
	 * @throws JSchException
	 */
	HashedHostKey(String host, KeyType type, byte[] key) throws JSchException {
		super(host, type, key);

		// If host value contains hash flags, attempt to extract hashed host and salt
		if( _host.startsWith(HASH_MAGIC) && _host.substring(HASH_MAGIC.length()).indexOf(HASH_DELIM) > 0 ) {
			String data = _host.substring(HASH_MAGIC.length());
			String salt = data.substring(0, data.indexOf(HASH_DELIM));
			String hash = data.substring(data.indexOf(HASH_DELIM) + 1);
			_salt = Util.fromBase64(Util.str2byte(salt), 0, salt.length());
			_hashedHost = Util.fromBase64(Util.str2byte(hash), 0, hash.length());

			// If invalid salt/hash, then generate hash and salt for session
			if( _salt.length != 20 || _hashedHost.length != 20 ) {	// SHA-1 block size must be 20!
				throw new JSchException("Invalid format, salt/hashed host lengths are wrong size: "+_host);
			}
		} else {
			// Host is not yet hashed, so generate hash
			generateHash();
		}
	}

	/**
	 * Generates the hashed version of host key for either a first time creation
	 * of hashed key or if hashed value is invalid.  The salt used to hash is
	 * randomly generated and stored with the host value to hash hosts during
	 * matching.
	 */
	private void generateHash() throws JSchException {
		// Create random salt for session
		MAC macsha1 = getMAC();
		_salt = new byte[macsha1.getBlockSize()];
		getRandom().fill(_salt, 0, _salt.length);

		try {	// Create the hashed host using salt and MAC-SHA1
			synchronized( macsha1 ) {	// MAC is not thread-safe
				macsha1.init(_salt);
				byte[] hostBytes = Util.str2byte(_host);
				macsha1.update(hostBytes, 0, hostBytes.length);
				_hashedHost = new byte[macsha1.getBlockSize()];
				macsha1.doFinal(_hashedHost, 0);
			}
		} catch(Exception e) {
			throw new JSchException("Failed to create HashedHostKey: " + e, e);
		}

		// Update the host value to the proper hashed format
		StringBuilder buffer = new StringBuilder(2000);
		buffer.append(HASH_MAGIC).append(Util.byte2str(Util.toBase64(_salt, 0, _salt.length)));
		buffer.append(HASH_DELIM).append(Util.byte2str(Util.toBase64(_hashedHost, 0, _hashedHost.length)));
		_host = buffer.toString();
	}

	/**
	 * Returns true if the specified host matches this host key.  If the host
	 * key is hashed, then the host value is hashed using the same salt and hash
	 * and checked against this host key's hash.
	 *
	 * @param host to check if matches host key
	 * @return true if specified host matches key
	 */
	@Override
	public boolean isMatched(String host) {
		try {
			MAC macsha1 = getMAC();
			synchronized( macsha1 ) {	// MAC is not thread-safe
				macsha1.init(_salt);
				byte[] hostBytes = Util.str2byte(host);
				macsha1.update(hostBytes, 0, hostBytes.length);
				byte[] hashValue = new byte[macsha1.getBlockSize()];
				macsha1.doFinal(hashValue, 0);
				return Arrays.equals(_hashedHost, hashValue);
			}
		} catch(Exception e) {
			throw new IllegalStateException("Failed to check HashedHostKey isMatched(): "+e, e);
		}
	}

	@Override
	protected boolean removeHost(String host) {
		throw new UnsupportedOperationException("Unsupported operation for HashedHostKey");
	}

	/**
	 * Returns the <code>MAC</code> instance for creating hashes for host keys.
	 *
	 * @return HMAC-SHA1 MAC instance
	 */
	private synchronized static MAC getMAC() throws JSchException {
		if( $hmacsha1 == null ) {
			$hmacsha1 = HashManager.getManager().createMAC(MAC.HMAC_SHA1);
		}
		return $hmacsha1;
	}

	/**
	 * Returns the instance of <code>Random</code> for creating hashed keys.
	 *
	 * @return instance of random
	 */
	private synchronized static Random getRandom() throws JSchException {
		if( $random == null ) {
			$random = AlgorithmManager.getManager().createAlgorithm(Algorithms.RANDOM);
		}
		return $random;
	}

}
