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

package org.vngx.jsch.userauth;

import org.vngx.jsch.exception.JSchException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

/**
 * Implementation of <code>com.jcraft.jsch.GSSContext</code> to perform user
 * authentication.
 *
 * @see org.vngx.jsch.GSSContext
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class GSSContextKrb5 implements org.vngx.jsch.userauth.GSSContext {

	/** Constant for System property to use subject credentials only. */
	private static final String USE_SUBJECT_CREDS_ONLY = "javax.security.auth.useSubjectCredsOnly";

	/** Property value to use subject credentials only. */
	private static String $useSubjectCredsOnly = getSystemProperty(USE_SUBJECT_CREDS_ONLY);
	/** Generic security services context. */
	private GSSContext _context;


	@Override
	public void create(String user, String host) throws JSchException {
		try {
			// RFC 1964
			Oid krb5 = new Oid("1.2.840.113554.1.2.2");
			// Kerberos Principal Name Form
			Oid principalName = new Oid("1.2.840.113554.1.2.2.1");

			GSSManager mgr = GSSManager.getInstance();
			GSSCredential crd = null;
			/*
			try{
				GSSName _user=mgr.createName(user, principalName);
				crd=mgr.createCredential(_user, GSSCredential.DEFAULT_LIFETIME, krb5, GSSCredential.INITIATE_ONLY);
			} catch(GSSException crdex){ }
			 */

			String cname = host;
			try {
				cname = InetAddress.getByName(cname).getCanonicalHostName();
			} catch(UnknownHostException e) {
				// TODO Error handling?
			}
			GSSName gssHost = mgr.createName("host/" + cname, principalName);
			_context = mgr.createContext(gssHost, krb5, crd, GSSContext.DEFAULT_LIFETIME);

			// RFC4462  3.4.  GSS-API Session
			//
			// When calling GSS_Init_sec_context(), the client MUST set
			// integ_req_flag to "true" to request that per-message integrity
			// protection be supported for this context.  In addition,
			// deleg_req_flag MAY be set to "true" to request access delegation, if
			// requested by the user.
			//
			// Since the user authentication process by its nature authenticates
			// only the client, the setting of mutual_req_flag is not needed for
			// this process.  This flag SHOULD be set to "false".

			// TODO: OpenSSH's sshd does accept 'false' for mutual_req_flag
			//context.requestMutualAuth(false);
			_context.requestMutualAuth(true);
			_context.requestConf(true);
			_context.requestInteg(true);             // for MIC
			_context.requestCredDeleg(true);
			_context.requestAnonymity(false);
		} catch(GSSException ex) {
			throw new JSchException("Failed to create GSSContextKrb5: "+ex, ex);
		}
	}

	@Override
	public boolean isEstablished() {
		return _context.isEstablished();
	}

	@Override
	public byte[] init(byte[] token, int offset, int length) throws JSchException {
		try {
			// Without setting "javax.security.auth.useSubjectCredsOnly" to "false",
			// Sun'offset JVM for Un*x will show messages to stderr in
			// processing context.initSecContext().
			// This hack is not thread safe ;-<.
			// If that property is explicitly given as "true" or "false",
			// this hack must not be invoked.
			if( $useSubjectCredsOnly == null ) {
				setSystemProperty(USE_SUBJECT_CREDS_ONLY, "false");
			}
			return _context.initSecContext(token, 0, length);
		} catch(GSSException ex) {
			throw new JSchException("Failed to init GSSContextKrb5: "+ex, ex);
		} catch(SecurityException ex) {
			throw new JSchException("Failed to init GSSContextKrb5: "+ex, ex);
		} finally {
			if( $useSubjectCredsOnly == null ) {
				// By default, it must be "true".
				setSystemProperty(USE_SUBJECT_CREDS_ONLY, "true");
			}
		}
	}

	@Override
	public byte[] getMIC(byte[] message, int offset, int length) {
		try {
			return _context.getMIC(message, offset, length, new MessageProp(0, true));
		} catch(GSSException ex) {
			return null;
		}
	}

	@Override
	public void dispose() {
		try {
			_context.dispose();
		} catch(GSSException ex) {
			// TODO Error handling?
		}
	}

	/**
	 * Utility method for retrieving a property value from System properties.
	 *
	 * @param key
	 * @return property value or null if error occurs
	 */
	private static String getSystemProperty(String key) {
		try {
			return System.getProperty(key);
		} catch(SecurityException e) {
			return null;	// Not allowed to get the System properties
		}
	}

	/**
	 * Utility method for setting a property value in System properties.
	 *
	 * @param key
	 * @param value
	 */
	private static void setSystemProperty(String key, String value) {
		try {
			System.setProperty(key, value);
		} catch(SecurityException e) { /* Not allowed to set the System properties */ }
	}

}
