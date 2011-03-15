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

package org.vngx.jsch.userauth;

import org.vngx.jsch.Util;
import org.vngx.jsch.exception.JSchException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Singleton for managing <code>Identity</code> instances.
 *
 * @author Michael Laudati
 */
public final class IdentityManager {

	/** Singleton instance of IdentityManager. */
	private static final IdentityManager INSTANCE = new IdentityManager();

	/** Set of registered identities. */
	private final Set<Identity> _identities = Collections.synchronizedSet(new LinkedHashSet<Identity>());


	/** Private constructor to prevent direct instantiation of singleton. */
	private IdentityManager() { }

	/**
	 * Returns the singleton instance of <code>IdentityManager</code>.
	 *
	 * @return singleton instance
	 */
	public static IdentityManager getManager() {
		return INSTANCE;
	}

	/**
	 * Returns an unmodifiable set  view of the registered identities.
	 *
	 * @return unmodifiable set of registered identities
	 */
	public Set<Identity> getIdentities() {
		return Collections.unmodifiableSet(_identities);
	}

	/**
	 * Adds an identity to the manager.
	 *
	 * @param privateKey for identity to add
	 * @throws JSchException if any errors occur
	 */
	public void addIdentity(String privateKey) throws JSchException {
		addIdentity(privateKey, (byte[]) null);
	}

	/**
	 * Adds the specified identity to the manager.
	 *
	 * @param privateKey for identity to add
	 * @param passphrase for identity
	 * @throws JSchException if any errors occur
	 */
	public void addIdentity(String privateKey, String passphrase) throws JSchException {
		byte[] bPassphrase = null;
		try {
			addIdentity(privateKey, bPassphrase = Util.str2byte(passphrase));
		} finally {
			Util.bzero(bPassphrase);
		}
	}

	/**
	 * Adds the specified identity to the manager.
	 *
	 * @param privateKey for identity to add
	 * @param passphrase for identity
	 * @throws JSchException if any errors occur
	 */
	public void addIdentity(String privateKey, byte[] passphrase) throws JSchException {
		addIdentity(IdentityFile.newInstance(privateKey, null), passphrase);
	}

	/**
	 * Adds the specified identity to the manager.
	 *
	 * @param privateKey
	 * @param publicKey
	 * @param passphrase
	 * @throws JSchException
	 */
	public void addIdentity(String privateKey, String publicKey, byte[] passphrase) throws JSchException {
		addIdentity(IdentityFile.newInstance(privateKey, publicKey), passphrase);
	}

	/**
	 * Adds the specified identity to the manager.
	 *
	 * @param name
	 * @param privateKey
	 * @param publicKey
	 * @param passphrase
	 * @throws JSchException
	 */
	public void addIdentity(String name, byte[] privateKey, byte[] publicKey, byte[] passphrase) throws JSchException {
		addIdentity(IdentityFile.newInstance(name, privateKey, publicKey), passphrase);
	}

	/**
	 * Adds the specified identity to the manager.
	 *
	 * @param identity
	 * @param passphrase
	 * @throws JSchException
	 */
	public void addIdentity(Identity identity, byte[] passphrase) throws JSchException {
		if( passphrase != null ) {
			try {
				byte[] passphraseCopy = new byte[passphrase.length];
				System.arraycopy(passphrase, 0, passphraseCopy, 0, passphrase.length);
				passphrase = passphraseCopy;
				identity.setPassphrase(passphrase);
			} finally {
				Util.bzero(passphrase);	// Always clear passphrase!
			}
		}
		synchronized( _identities ) {
			if( !_identities.contains(identity) ) {
				_identities.add(identity);
			}
		}
	}

	/**
	 * Removes the identity with the specified name from the manager.
	 *
	 * @param name of identity to remove
	 * @throws JSchException if any errors occur
	 */
	public void removeIdentity(String name) throws JSchException {
		synchronized( _identities ) {
			for( Identity identity : _identities ) {
				if( identity.getName().equals(name) ) {
					_identities.remove(identity);
					identity.clear();
					break;
				}
			}
		}
	}

	/**
	 * Returns a list of the identity names stored in the manager.
	 *
	 * @return list of identity names in manager
	 * @throws JSchException
	 */
	public List<String> getIdentityNames() throws JSchException {
		List<String> identityNames = new ArrayList<String>(_identities.size());
		synchronized( _identities ) {
			for( Identity identity : _identities ) {
				identityNames.add(identity.getName());
			}
		}
		return identityNames;
	}

	/**
	 * Removes all identities stored in the manager.
	 *
	 * @throws JSchException if any errors occur
	 */
	public void removeAllIdentities() throws JSchException {
		synchronized( _identities ) {
			for( String name : getIdentityNames() ) {
				removeIdentity(name);
			}
		}
	}

}
