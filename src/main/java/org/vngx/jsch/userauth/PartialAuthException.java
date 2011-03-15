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
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Implementation of <code>JSchException</code> for partial authentication
 * exceptions.  When a user authentication method receives a
 * SSH_MSG_USERAUTH_FAILURE response from the server, the server may pass back
 * a list of user authentication methods which can still proceed.  This response
 * generates a <code>JSchPartialAuthException</code> which contains the parsed
 * set of user auth methods.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
final class PartialAuthException extends JSchException {

	/** Set of user authentication methods which can proceed from server. */
	private final Set<String> _nameList;

	/**
	 * Creates a new instance of <code>JSchPartialAuthException</code> with the
	 * specified name list of user authentication methods which can proceed.
	 *
	 * @param nameList of auth methods from server
	 */
	PartialAuthException(String nameList) {
		if( nameList != null ) {
			_nameList = new LinkedHashSet<String>(Arrays.asList(nameList.split(",")));
		} else {
			_nameList = Collections.emptySet();
		}
	}

	/**
	 * Set of server supported authentication methods which can proceed.
	 *
	 * @return set of server supported user auth methods
	 */
	Set<String> getUserAuthMethods() {
		return _nameList;
	}
	
}
