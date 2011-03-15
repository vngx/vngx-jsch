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

import org.vngx.jsch.exception.JSchException;

/**
 * Implementation of <code>ChannelSession</code> which can be used for creating
 * a shell to allow input and output streams for communicating over SSH.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class ChannelShell extends ChannelSession {

	/**
	 * Creates a new instance of <code>ChannelShell</code>.
	 *
	 * @param session
	 */
	ChannelShell(Session session) {
		super(session, ChannelType.SHELL);
		_pty = true;	// TODO If pty is always true, setPty() should be overridden to disable
	}

	@Override
	public void start() throws JSchException {
		try {
			sendRequests();
			new RequestShell().request(_session, this);
		} catch(JSchException e) {
			throw e;
		} catch(Exception e) {
			throw new JSchException("Failed to start ChannelShell", e);
		}

		if( _io.in != null ) {
			_thread = new Thread(this, "Shell for " + _session.getHost());
			_thread.setDaemon(_session.isDaemonThread());
			_thread.start();
		}
	}

	@Override
	void init() throws JSchException {
		_io.setInputStream(_session._in);
		_io.setOutputStream(_session._out);
	}

}
