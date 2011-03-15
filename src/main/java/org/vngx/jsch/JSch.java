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

package org.vngx.jsch;

import org.vngx.jsch.config.SessionConfig;
import org.vngx.jsch.constants.SSHConstants;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.util.HostKeyRepository;
import org.vngx.jsch.util.KnownHosts;
import org.vngx.jsch.util.Logger;
import java.io.InputStream;

/**
 * Factory for creating instances of {@code Session} and provides some general
 * static methods for working with the vngx-jsch library.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class JSch {

	/** 
	 * Constant client version {@value} for vngx-jsch library (sent to SSH
	 * server during initial connection).  The first version number represents
	 * the library version; the second version number represents the JSch 
	 * version the code base is forked from.
	 */
	public static final String VERSION = "vngx-jsch-0.9-1.44";

	/** Singleton instance of {@code JSch}. */
	private final static JSch INSTANCE = new JSch();

	
	/** Repository for managing known hosts (host keys). */
	private final HostKeyRepository _hostKeyRepository = new KnownHosts();

	/** Logger instance (null by default). */
	private static Logger $logger = Logger.NULL_LOGGER;


	/**
	 * Private constructor to prevent direct instantiation of singleton.
	 */
	private JSch() { }

	/**
	 * Returns the singleton instance of <code>JSch</code>.
	 *
	 * @return singleton instance
	 */
	public static JSch getInstance() {
		return INSTANCE;
	}

	/**
	 * Creates a new instance of <code>Session</code> for the specified host and
	 * username. The default standard SSH port 22 will be used for connecting.
	 *
	 * @param username
	 * @param host
	 * @return session
	 * @throws JSchException
	 */
	public Session createSession(String username, String host) throws JSchException {
		return createSession(username, host, SSHConstants.DEFAULT_SSH_PORT);
	}

	/**
	 * Creates a new instance of <code>Session</code> for the specified host,
	 * port and username.
	 *
	 * @param username
	 * @param host
	 * @param port
	 * @return session
	 * @throws JSchException
	 */
	public Session createSession(String username, String host, int port) throws JSchException {
		return createSession(username, host, port, null);
	}

	/**
	 * Creates a new instance of <code>Session</code> for the specified host,
	 * port, username and session configuration.
	 *
	 * @param username
	 * @param host
	 * @param port
	 * @param config
	 * @return session
	 * @throws JSchException
	 */
	public Session createSession(String username, String host, int port, SessionConfig config) throws JSchException {
		try {
			return new Session(host, port, username, config);
		} catch(Exception e) {
			throw new JSchException("Failed to create Session: "+e, e);
		}
	}

	public void setKnownHosts(String filename) throws JSchException {
		if( _hostKeyRepository instanceof KnownHosts ) {
			synchronized( _hostKeyRepository ) {
				((KnownHosts) _hostKeyRepository).setKnownHosts(filename);
			}
		}
	}

	public void setKnownHosts(InputStream stream) throws JSchException {
		if( _hostKeyRepository instanceof KnownHosts ) {
			synchronized( _hostKeyRepository ) {
				((KnownHosts) _hostKeyRepository).loadKnownHosts(stream);
			}
		}
	}

	public HostKeyRepository getHostKeyRepository() {
		return _hostKeyRepository;
	}

	/**
	 * Returns the client version of the vngx-jsch library.  The version String
	 * is passed to the SSH server during the opening connection.
	 *
	 * @return client version String
	 */
	public static String getVersion() {
		return VERSION;
	}
	
	/**
	 * Returns the <code>Logger</code> instance to use for logging.
	 *
	 * @return logger instance
	 */
	public static Logger getLogger() {
		return $logger;
	}

	/**
	 * Sets the <code>Logger</code> instance to use for logging.  Setting the
	 * logger to null turns off all internal logging.
	 *
	 * @param logger to use
	 */
	public static void setLogger(Logger logger) {
		$logger = logger != null ? logger : Logger.NULL_LOGGER;
	}

}
