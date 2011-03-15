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

import org.vngx.jsch.UserInfo;
import java.util.List;

/**
 * An interface for defining a repository which manages and validates host keys
 * from the local file system.
 *
 * @see org.vngx.jsch.util.HostKey
 * @see org.vngx.jsch.util.KnownHosts
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public interface HostKeyRepository {

	/**
	 * Enum constants for the available results which can be returned when
	 * checking repository for host key.
	 */
	enum Check {
		/** Constant indicating host and key are valid (matched in repository). */
		OK,
		/** Constant indicating host and key are not included in repository. */
		NOT_INCLUDED,
		/** Constant indicating key for host has changed in repository. */
		CHANGED;
	}

	/**
	 * Checks if the specified host and public key is valid by checking against
	 * the local repository of known hosts.
	 *
	 * @param host to check
	 * @param key from host
	 * @return validation result
	 */
	Check check(String host, byte[] key);

	/**
	 * Adds the specified host key to the repository and uses the specified ui
	 * for prompting user for input if necessary.
	 *
	 * @param hostkey to add
	 * @param ui if user needs to be prompted
	 */
	void add(HostKey hostkey, UserInfo ui);

	/**
	 * Removes the specified host from the repository.
	 *
	 * @param host
	 * @param type
	 */
	void remove(String host, KeyType type);

	/**
	 * Removes the specified host from the repository.
	 *
	 * @param host
	 * @param type
	 * @param key
	 */
	void remove(String host, KeyType type, byte[] key);

	/**
	 * Returns a unique ID for the repository instance.  Implementations can use
	 * the known hosts file location from which the keys were loaded.
	 *
	 * @return repository ID
	 */
	String getKnownHostsRepositoryID();

	/**
	 * Returns the loaded host keys stored in the repository.
	 *
	 * @return loaded host keys
	 */
	List<HostKey> getHostKeys();

	/**
	 * Returns any loaded host keys which match the specified host and type.
	 *
	 * @param host
	 * @param type
	 * @return loaded host keys
	 */
	List<HostKey> getHostKeys(String host, KeyType type);

}
