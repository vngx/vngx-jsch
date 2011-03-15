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

package org.vngx.jsch.constants;

/**
 * <p>SSH message code constants for the SSH file transfer protocol.  The
 * Message Number is a byte value that describes the payload of a packet.</p>
 *
 * <p><a href="http://tools.ietf.org/html/draft-ietf-secsh-filexfer-02">SSH File
 * Transfer Protocol</a></p>
 * 
 * @author Michael Laudati
 */
public interface SftpProtocol {

	/** Constant SFTP code to indicate successful completion of the operation. */
	int SSH_FX_OK = 0;

	/**
	 * Constant SFTP code to indicate end-of-file condition; for SSH_FX_READ it
	 * means that no more data is available in the file, and for SSH_FX_READDIR
	 * it indicates that no more files are contained in the directory.
	 */
	int SSH_FX_EOF = 1;

	/**
	 * Constant SFTP code returned when a reference is made to a file which
	 * should exist.
	 */
	int SSH_FX_NO_SUCH_FILE = 2;

	/**
	 * Constant SFTP code is returned when the authenticated user does not have
	 * sufficient permissions to perform the operation.
	 */
	int SSH_FX_PERMISSION_DENIED = 3;

	/**
	 * Constant SFTP code is a generic catch-all error message; it should be
	 * returned if an error occurs for which there is no more specific error
	 * code defined.
	 */
	int SSH_FX_FAILURE = 4;

	/**
	 * Constant SFTP code may be returned if a badly formatted packet or
	 * protocol incompatibility is detected.
	 */
	int SSH_FX_BAD_MESSAGE = 5;

	/**
	 * Constant SFTP code is a pseudo-error which indicates that the client has
	 * no connection to the server (it can only be generated locally by the
	 * client, and MUST NOT be returned by servers).
	 */
	int SSH_FX_NO_CONNECTION = 6;

	/**
	 * Constant SFTP code is a pseudo-error which indicates that the connection
	 * to the server has been lost (it can only be generated locally by the
	 * client, and MUST NOT be returned by servers).
	 */
	int SSH_FX_CONNECTION_LOST = 7;

	/**
	 * Constant SFTP code to indicate that an attempt was made to perform an
	 * operation which is not supported for the server (it may be generated
	 * locally by the client if e.g. the version number exchange indicates that
	 * a required feature is not supported by the server, or it may be returned
	 * by the server if the server does not implement an operation).
	 */
	int SSH_FX_OP_UNSUPPORTED = 8;

	/** SFTP constant code to initialize the SFTP session. */
	byte SSH_FXP_INIT = 1;
	byte SSH_FXP_VERSION = 2;
	byte SSH_FXP_OPEN = 3;
	byte SSH_FXP_CLOSE = 4;
	byte SSH_FXP_READ = 5;
	byte SSH_FXP_WRITE = 6;
	byte SSH_FXP_LSTAT = 7;
	byte SSH_FXP_FSTAT = 8;
	byte SSH_FXP_SETSTAT = 9;
	byte SSH_FXP_FSETSTAT = 10;
	byte SSH_FXP_OPENDIR = 11;
	byte SSH_FXP_READDIR = 12;
	byte SSH_FXP_REMOVE = 13;
	byte SSH_FXP_MKDIR = 14;
	byte SSH_FXP_RMDIR = 15;
	/** SFTP constant code to request real path for a relative path. */
	byte SSH_FXP_REALPATH = 16;
	byte SSH_FXP_STAT = 17;
	byte SSH_FXP_RENAME = 18;
	byte SSH_FXP_READLINK = 19;
	byte SSH_FXP_SYMLINK = 20;
	/** SFTP constant code response to indicate a status message from server. */
	byte SSH_FXP_STATUS = 101;
	byte SSH_FXP_HANDLE = 102;
	byte SSH_FXP_DATA = 103;
	byte SSH_FXP_NAME = 104;
	byte SSH_FXP_ATTRS = 105;
	byte SSH_FXP_EXTENDED = (byte) 200;
	byte SSH_FXP_EXTENDED_REPLY = (byte) 201;

	//=== Permission Flags by user, group and owner ===
	/** Constant code for set user ID on execution. */
	int S_ISUID = 2048;
	/** Constant code for set group ID on execution. */
	int S_ISGID = 1024;
	/** Constant code for sticky bit (****** NOT DOCUMENTED *****). */
	int S_ISVTX = 512;
	/** Constant code for read by owner. */
	int S_IRUSR = 256;
	/** Constant code for write by owner. */
	int S_IWUSR = 128;
	/** Constant code for execute/search by owner. */
	int S_IXUSR = 64;
	/** Constant code for read by owner. */
	int S_IREAD = 256;
	/** Constant code for write by owner. */
	int S_IWRITE = 128;
	/** Constant code for execute/search by owner. */
	int S_IEXEC = 64;
	/** Constant code for read by group. */
	int S_IRGRP = 32;
	/** Constant code for write by group. */
	int S_IWGRP = 16;
	/** Constant code for execute/search by group. */
	int S_IXGRP = 8;
	/** Constant code for read by others. */
	int S_IROTH = 4;
	/** Constant code for write by others. */
	int S_IWOTH = 2;
	/** Constant code for execute/search by others. */
	int S_IXOTH = 1;
	/** Constant code for file/dir indicator. */
	int S_IFDIR = 16384;
	/** Constant code for indicating if file link. */
	int S_IFLNK = 40960;

	//=== Permissions flags ===
	int SSH_FXF_READ = 1;
	int SSH_FXF_WRITE = 2;
	int SSH_FXF_APPEND = 4;
	int SSH_FXF_CREAT = 8;
	int SSH_FXF_TRUNC = 16;
	int SSH_FXF_EXCL = 32;
	
	/** Constant for SFTP bit flag indicating file attribute size. */
	int SSH_FILEXFER_ATTR_SIZE = 1;
	/** Constant for SFTP bit flag indicating user ID and group ID. */
	int SSH_FILEXFER_ATTR_UIDGID = 2;
	/** Constant for SFTP bit flag indicating file permissions. */
	int SSH_FILEXFER_ATTR_PERMISSIONS = 4;
	/** Constant for SFTP bit flag indicating create/modified timestamps. */
	int SSH_FILEXFER_ATTR_ACMODTIME = 8;
	/** Constant for SFTP bit flag indicating extended information. */
	int SSH_FILEXFER_ATTR_EXTENDED = -2147483648;

}
