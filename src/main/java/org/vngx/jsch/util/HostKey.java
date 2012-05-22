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

import java.util.LinkedHashSet;
import java.util.Set;

import org.vngx.jsch.Util;
import org.vngx.jsch.exception.JSchException;

/**
 * <p>Host key implementation as outlined in the RFC4251 spec for SSH.</p>
 *
 * <p>Each server host SHOULD have a host key.  Hosts MAY have multiple host
 * keys using multiple different algorithms.  Multiple hosts MAY share the same
 * host key.  If a host has keys at all, it MUST have at least one key that uses
 * each REQUIRED public key algorithm (DSS[FIPS-186-2]).</p>
 *
 * <p>The server host key is used during key exchange to verify that the client
 * is really talking to the correct server.  For this to be possible, the client
 * must have a prior knowledge of the server's public host key.</p>
 *
 * {@link http://www.ietf.org/rfc/rfc4251.txt}
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class HostKey {

	/** Host name (or list of host names separated by commas ",". */
	String _host;
	/** Type of host key. */
	final KeyType _type;
	/** Key value. */
	final byte[] _key;
	/** Set of hosts stored for this host key. */
	final Set<String> _hosts = new LinkedHashSet<String>();


	/**
	 * Creates a new instance of <code>HostKey</code> for the specified host and
	 * key value.  Attempts to determine key type from the key value; if it
	 * cannot be determined, an exception is thrown.
	 * 
	 * @param host name (or comma delimited list of hosts)
	 * @param key data
	 * @throws JSchException if any errors occur
	 */
	public HostKey(String host, byte[] key) throws JSchException {
		this(host, null, key);
	}

	/**
	 * Creates a new instance of <code>HostKey</code> for the specified host and
	 * key value and of the specified type.  If the specified key type is null,
	 * attempts to determine key type from key value.  If the key type is
	 * unknown after guessing, an exception will be thrown.
	 *
	 * @param host name (or comma delimited list of hosts)
	 * @param keyType of host key (null to guess key type)
	 * @param key data
	 * @throws JSchException if key type cannot be determined
	 */
	public HostKey(String host, KeyType keyType, byte[] key) throws JSchException {
		if( host == null || host.length() == 0 ) {
			throw new IllegalArgumentException("Host(s) cannot be null/empty");
		} else if( key == null ) {
			throw new IllegalArgumentException("Key value cannot be null");
		}
		_host = host;
		_key = Util.copyOf(key, key.length);	// Copy key for security
		if( keyType == null ) {
			_type = guessType(key);
			if( _type == KeyType.UNKNOWN ) {
				throw new JSchException("Failed to determine key type");
			}
		} else {
			_type = keyType;
		}

		// Split (if multiple hosts) and add to set of hosts for this key
		if( _type != KeyType.UNKNOWN ) {
			for( String h : _host.split(",") ) {
				_hosts.add(h.toLowerCase());	// Lowercase for comparisons
			}
		}
	}

	/**
	 * Returns the host value of this host key which is a comma delimited list
	 * of host names and IPs for this host key.
	 *
	 * @return host value (comma delimited list of host names/IPs for key)
	 */
	public String getHost() {
		return _host;
	}

	/**
	 * Returns the type of host key.
	 *
	 * @return type of host key
	 */
	public KeyType getType() {
		return _type;
	}

	/**
	 * Returns the key value as a base-64 encoded String.
	 *
	 * @return key value encoded in base-64
	 */
	public String getKey() {
		return Util.byte2str(Util.toBase64(_key, 0, _key.length));
	}

	/**
	 * Returns a hashed fingerprint for this host key using the MD5 instance
	 * specified in the <code>Jsch</code> configuration.
	 *
	 * @return fingerprint hash
	 * @throws JSchException if any errors occur
	 */
	public String getFingerPrint() throws JSchException {
		return Util.getFingerPrint(_key);
	}

	/**
	 * Returns true if the specified host matches this host key.
	 *
	 * @param host to check
	 * @return true if host matches this host key
	 */
	public boolean isMatched(String host) {
		return host != null && _hosts.contains(host.toLowerCase());
	}

	/**
	 * Returns the number of hosts in this key.
	 *
	 * @return number of hosts in key
	 */
	public int getHostCount() {
		return _hosts.size();
	}

	/**
	 * Removes a single host from the list of hosts which belong to this key. If
	 * the host key only has a single host which matches the specified host, an
	 * exception will be thrown.
	 *
	 * @param host to remove, if multiple hosts defined in key
	 * @return true if host was successfully removed
	 * @throws IllegalArgumentException if host is the only host value
	 */
	protected boolean removeHost(String host) {
		if( host == null ) {
			return false;
		} else if( _hosts.size() == 1 && _hosts.contains(host.toLowerCase()) ) {
			throw new IllegalStateException("Cannot remove last host from key");
		}
		boolean removed = _hosts.remove(host.toLowerCase());
		if( removed ) {
			// Update host list if a host was removed
			_host = Util.join(_hosts, ",");
		}
		return removed;
	}

	/**
	 * Attempts to determine the host key type by checking the value of the 9th
	 * bit of the key.  If the type cannot be determined, then UNKNOWN is
	 * returned.
	 *
	 * Note: Assumes key type is only 'ssh-dss' or 'ssh-rsa'.
	 *
	 * @param key blob for host key
	 * @return host key type guessed from key value
	 */
	protected static KeyType guessType(byte[] key) {
		switch( key[8] ) {
			case 'd': return KeyType.SSH_DSS;
			case 'r': return KeyType.SSH_RSA;
			default: return KeyType.UNKNOWN;
		}
	}

	/**
	 * Creates a new instance of <code>HostKey</code> for the specified host and
	 * key value.  If <code>hash</code> is true, then the host value will be
	 * hashed accordingly.<p>
	 *
	 * Please note this method does not add the newly created host key to the
	 * known hosts.
	 *
	 * @param host
	 * @param key
	 * @param hashed true to indicate host value should be hashed
	 * @return new HostKey instance
	 * @throws JSchException if any errors occur
	 */
	public static HostKey createHostKey(String host, byte[] key, boolean hashed) throws JSchException {
		return hashed ? new HashedHostKey(host, key) : new HostKey(host, key);
	}

}
