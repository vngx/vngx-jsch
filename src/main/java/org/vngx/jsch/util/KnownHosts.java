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
import org.vngx.jsch.Util;
import org.vngx.jsch.constants.MessageConstants;
import org.vngx.jsch.exception.JSchException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Implementation of <code>HostKeyRepository</code> for registering and checking
 * host keys on the local system.  The registered host keys are backed to
 * persistent storage on the file system whenever keys are added or removed.
 *
 * SSH clients typically save a server's host key locally in a file named
 * "$HOME/.ssh/known_hosts" (where $HOME is the user's home directory). This
 * file is, effectively, a personal Certificate Authority -- it is the list of
 * all SSH server host keys that the user has determined are accurate.
 *
 * Each entry in known_hosts is one big line with three or more whitespace
 * separated fields as follows:
 *		One or more server names or IP addresses, joined together by commas.
 *		The type of key (described later).
 *		The public key data itself (encoded to stay within the ASCII range).
 *		Any optional comment data (not present in the above output).
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class KnownHosts implements HostKeyRepository {

	/** Pool of registered host keys. (TODO Consider using Set) */
	private final List<HostKey> _hostKeyPool = Collections.synchronizedList(new ArrayList<HostKey>());
	/** Local file containing known hosts. */
	private String _knownHostsFile;
	

	/**
	 * Creates a new instance of <code>KnownHosts</code>.
	 */
	public KnownHosts() { }

	/**
	 * Sets the specified hosts file and attempts to load any host keys found
	 * in the specified location.
	 *
	 * @param hostsFile where host keys are stored
	 * @throws JSchException if any errors occur
	 */
	public void setKnownHosts(String hostsFile) throws JSchException {
		try {
			_knownHostsFile = hostsFile;
			//setKnownHosts(new FileInputStream(hostsFile));
			loadKnownHosts(new FileInputStream(hostsFile));
		} catch(FileNotFoundException e) {
			// Ignore error, as client may not have a known hosts file
			// TODO Optionally log missing hosts file?
		}
	}

	/**
	 * Attempts to load known hosts from the specified input stream.
	 *
	 * TODO Shouldn't method be synchronized?
	 *
	 * @param hostsStream containing host keys
	 * @throws JSchException if any errors occur
	 */
	public void loadKnownHosts(InputStream hostsStream) throws JSchException {
		_hostKeyPool.clear();	// Clear any loaded host keys, only load from stream

		BufferedReader reader = new BufferedReader(new InputStreamReader(hostsStream));
		try {
			String line;
			String[] keyEntry;
			KeyType type;
			while( (line = reader.readLine()) != null ) {
				if( line.indexOf('#') > -1 ) {
					continue;	// Invalid line
				}
				keyEntry = line.split("\\s+");	// Split by whitespace
				if( keyEntry == null || keyEntry.length < 3 ) {
					continue;	// Invalid line
				}

				if( KeyType.SSH_DSS.equals(keyEntry[1]) ) {
					type = KeyType.SSH_DSS;
				} else if( KeyType.SSH_RSA.equals(keyEntry[1]) ) {
					type = KeyType.SSH_RSA;
				} else {
					continue;	// Invalid key type
				}

				if( keyEntry[0].startsWith(HashedHostKey.HASH_MAGIC) ) {
					_hostKeyPool.add(new HashedHostKey(keyEntry[0], type, Util.fromBase64(Util.str2byte(keyEntry[2]), 0, keyEntry[2].length())));
				} else {
					_hostKeyPool.add(new HostKey(keyEntry[0], type, Util.fromBase64(Util.str2byte(keyEntry[2]), 0, keyEntry[2].length())));
				}
			}
		} catch(JSchException e) {
			throw e;
		} catch(Exception e) {
			throw new JSchException("Failed to load known hosts", e);
		} finally {
			if( hostsStream != null ) {
				try { hostsStream.close(); } catch(Exception e) { /* Ignore Error */ }
			}
		}
	}

	/*
	 * Returns the known hosts file location as the repository ID for the
	 * <code>HostKeyRepository</code> interface.
	 */
	@Override
	public String getKnownHostsRepositoryID() {
		return _knownHostsFile;
	}

	@Override
	public Check check(String host, byte[] key) {
		if( host == null ) {
			return Check.NOT_INCLUDED;
		}
		KeyType type = HostKey.guessType(key);

		Check result = Check.NOT_INCLUDED;
		synchronized( _hostKeyPool ) {
			for( HostKey hostKey : _hostKeyPool ) {
				if( hostKey.isMatched(host) && hostKey.getType() == type ) {
					if( Arrays.equals(hostKey._key, key) ) {
						return Check.OK;	// If keys match
					} else {
						result = Check.CHANGED;
					}
				}
			}
		}

		if( result == Check.NOT_INCLUDED && host.startsWith("[") && host.indexOf("]:") > 1 ) {
			return check(host.substring(1, host.indexOf("]:")), key);
		}
		return result;
	}

	/*
	 * Adds the specified host key to the repository.  Attempts to save the
	 * updated repository to the known hosts file.
	 */
	@Override
	public void add(HostKey hostkey, UserInfo userinfo) {
		// TODO Add check to ensure same host key doesn't already exist in pool
		// Add host key to pool of registered keys
		_hostKeyPool.add(hostkey);

		String hostsFileName = getKnownHostsRepositoryID();
		if( hostsFileName != null ) {
			boolean foo = true;
			File hostsFile = new File(hostsFileName);
			if( !hostsFile.exists() ) {
				foo = false;
				if( userinfo != null ) {
					foo = userinfo.promptYesNo(String.format(MessageConstants.PROMPT_CREATE_KNOWN_HOSTS, hostsFileName));
					hostsFile = hostsFile.getParentFile();
					if( foo && hostsFile != null && !hostsFile.exists() ) {
						foo = userinfo.promptYesNo(String.format(MessageConstants.PROMPT_CREATE_HOSTS_DIR, hostsFile));
						if( foo ) {
							if( !hostsFile.mkdirs() ) {
								userinfo.showMessage(String.format(MessageConstants.MSG_KNOWN_HOSTS_NOT_CREATED, hostsFile));
								foo = false;
							} else {
								userinfo.showMessage(String.format(MessageConstants.MSG_KNOWN_HOSTS_CREATED, hostsFile));
							}
						}
					}
					if( hostsFile == null ) {
						foo = false;
					}
				}
			}
			if( foo ) {
				try {
					sync(hostsFileName);
				} catch(Exception e) {
					// TODO Error handling?
					System.err.println("sync known_hosts: " + e);
				}
			}
		}
	}

	@Override
	public List<HostKey> getHostKeys() {
		return getHostKeys(null, null);
	}

	@Override
	public List<HostKey> getHostKeys(String host, KeyType type) {
		synchronized( _hostKeyPool ) {
			List<HostKey> matches = new ArrayList<HostKey>();
			for( HostKey hk : _hostKeyPool ) {
				if( hk.getType() == KeyType.UNKNOWN ) {
					continue;
				} else if( host == null || (hk.isMatched(host) && (type == null || hk.getType() == type)) ) {
					matches.add(hk);
				}
			}
			return matches;
		}
	}

	@Override
	public void remove(String host, KeyType type) {
		remove(host, type, null);
	}

	@Override
	public void remove(String host, KeyType type, byte[] key) {
		boolean sync = false;
		synchronized( _hostKeyPool ) {
			for( HostKey hk : _hostKeyPool ) {
				if( host == null || (hk.isMatched(host)
						&& (type == null || (hk.getType() == type
						&& (key == null || Arrays.equals(key, hk._key))))) ) {
					if( hk.getHost().equalsIgnoreCase(host) ||  hk instanceof HashedHostKey ) {
						_hostKeyPool.remove(hk);
					} else {
						hk.removeHost(host);
					}
					sync = true;
				}
			}
		}
		if( sync ) {
			try {
				sync();	// Save to known hosts file
			} catch(Exception e) {
				// TODO Error handling?
			}
		}
	}

	/**
	 * Syncs the host keys currently stored in the repository with the known
	 * hosts file if it's not null.
	 *
	 * @throws IOException
	 */
	void sync() throws IOException {
		sync(_knownHostsFile);
	}

	/**
	 * Syncs the host keys currently stored in the repository with the specified
	 * known hosts file if it's not null.
	 *
	 * @param knownHostsFile
	 * @throws IOException
	 */
	void sync(String knownHostsFile) throws IOException {
		if( knownHostsFile == null ) {
			return;
		}
		BufferedWriter writer = new BufferedWriter(new FileWriter(knownHostsFile));
		try {
			synchronized( _hostKeyPool ) {
				for( HostKey hk : _hostKeyPool ) {
					if( hk.getType() == KeyType.UNKNOWN ) {
						continue;
					}
					writer.append(hk.getHost());
					writer.append(' ').append(hk.getType().toString());
					writer.append(' ').append(hk.getKey()).append('\n');
				}
			}
		} finally {
			writer.flush();
			writer.close();
		}
	}

}
