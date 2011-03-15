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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Implementation of <code>ChannelSubsystem</code>.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class ChannelSubsystem extends ChannelSession {

	/** True if channel wants a reply from the server. */
	private boolean _wantReply = true;
	/** The subsystem to request from server. */
	private String _subsystem = "";


	/**
	 * Creates a new instance of <code>ChannelSubsystem</code>.
	 *
	 * @param session
	 */
	ChannelSubsystem(Session session) {
		super(session, ChannelType.SUBSYSTEM);
	}

	@Override
	public void start() throws JSchException {
		try {
			// Send X11 request if x-forwarding is enabled
			if( _x11Forwarding ) {
				new RequestX11().request(_session, this);
			}
			// Send Psuedo terminal request if pty is enabled
			if( _pty ) {
				new RequestPtyReq().request(_session, this);
			}
			// Send subsystem request
			RequestSubsystem subsystemRequest = new RequestSubsystem();
			subsystemRequest.setSubsystem(_subsystem);
			subsystemRequest.setReply(_wantReply);
			subsystemRequest.request(_session, this);
		} catch(JSchException e) {
			throw e;
		} catch(Exception e) {
			throw new JSchException("Failed to start ChannelSubsystem", e);
		}
		if( _io.in != null ) {
			_thread = new Thread(this, "Subsystem for " + _session.getHost());
			_thread.setDaemon(_session.isDaemonThread());
			_thread.start();
		}
	}

	/*
	 * Initializes the IO with the input and output streams from the session.
	 */
	@Override
	void init() throws JSchException {
		_io.setInputStream(_session._in);
		_io.setOutputStream(_session._out);
	}

	/**
	 * Sets if the channel wants a reply.
	 *
	 * @param wantReply
	 */
	public void setWantReply(boolean wantReply) {
		_wantReply = wantReply;
	}

	/**
	 * Sets the subsystem to start.
	 *
	 * @param subsystem
	 */
	public void setSubsystem(String subsystem) {
		_subsystem = subsystem;
	}

	/**
	 * Sets the error output stream.
	 *
	 * @param out
	 */
	public void setErrStream(OutputStream out) {
		setExtOutputStream(out);
	}

	/**
	 * Returns the error input stream.
	 *
	 * @return error input stream
	 * @throws IOException
	 */
	public InputStream getErrStream() throws IOException {
		return getExtInputStream();
	}

}
