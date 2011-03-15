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
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Implementation of <code>ChannelSession</code> which allows for the execution
 * of a single command at a time and pipes the output from command to a stream.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public class ChannelExec extends ChannelSession {

	/** Command to send over channel (by default empty command). */
	private byte[] _command = new byte[0];


	/**
	 * Creates a new instance of <code>ChannelExec</code>.
	 *
	 * @param session
	 */
	ChannelExec(Session session) {
		super(session, ChannelType.EXEC);
	}

	@Override
	public void start() throws JSchException {
		try {
			sendRequests();
			new RequestExec(_command).request(_session, this);
		} catch(JSchException je) {
			throw je;
		} catch(Exception e) {
			throw new JSchException("Failed to start ChannelExec", e);
		}

		if( _io.in != null ) {
			_thread = new Thread(this, "Exec thread " + _session.getHost());
			_thread.setDaemon(_session.isDaemonThread());
			_thread.start();
		}
	}

	/*
	 * Initializes the channel by setting the input and output streams for the
	 * channel to the same as used by its session.
	 */
	@Override
	void init() throws JSchException {
		_io.setInputStream(_session._in);
		_io.setOutputStream(_session._out);
	}

	/**
	 * Sets the command to send over channel.
	 *
	 * @param command to send
	 */
	public void setCommand(String command) {
		_command = Util.str2byte(command);
	}

	/**
	 * Sets the command to send over channel.
	 *
	 * @param command to send
	 */
	public void setCommand(byte[] command) {
		_command = command;
	}

	/**
	 * Sets the error output stream to use.
	 *
	 * @param out
	 */
	public void setErrStream(OutputStream out) {
		setExtOutputStream(out);
	}

	/**
	 * Sets the error output stream to use and specifies if the stream should
	 * not be closed.
	 *
	 * @param out
	 * @param dontclose
	 */
	public void setErrStream(OutputStream out, boolean dontclose) {
		setExtOutputStream(out, dontclose);
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
