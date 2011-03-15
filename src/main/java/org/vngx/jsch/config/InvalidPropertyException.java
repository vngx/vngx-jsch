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

package org.vngx.jsch.config;

/**
 * An exception which can be thrown when an invalid property value has been
 * found.
 * 
 * @author Michael Laudati
 */
public class InvalidPropertyException extends IllegalArgumentException {

    /** Property name which has invalid value. */
    protected final String _propertyName;
    /** Invalid property value. */
    protected final String _propertyValue;
    
    
    /**
     * Creates a new empty instance of {@code InvalidPropertyException}.
     */
    public InvalidPropertyException() {
        this(null, null, null, null);
    }
    
    /**
     * Creates a new instance of {@code InvalidPropertyException} with the
     * specified property name and property value.
     * 
     * @param propName which was invalid
     * @param propValue which was invalid
     */
    public InvalidPropertyException(String propName, String propValue) {
        this(propName, propValue, null, null);
    }
    
    /**
     * Creates a new instance of {@code InvalidPropertyException} with the
     * specified property name and property value and error message.
     * 
     * @param propName which was invalid
     * @param propValue which was invalid
     * @param message about error
     */
    public InvalidPropertyException(String propName, String propValue, String message) {
        this(propName, propValue, message, null);
    }
    
    /**
     * Creates a new instance of {@code InvalidPropertyException} with the
     * specified property name and property value and error message and cause.
     * 
     * @param propName which was invalid
     * @param propValue which was invalid
     * @param message about error
     * @param cause of error
     */
    public InvalidPropertyException(String propName, String propValue, String message, Throwable cause) {
        super(generateErrorMessage(message, propName, propValue), cause);
        _propertyName = propName;
        _propertyValue = propValue;
    }
    
    /**
     * Returns the name of the invalid property.
     * 
     * @return name of the invalid property
     */
    public String getPropertyName() {
        return _propertyName;
    }
    
    /**
     * Returns the value of the invalid property.
     * 
     * @return value of invalid property
     */
    public String getPropertyValue() {
        return _propertyValue;
    }
    
    /**
     * Generates the message to pass to constructor.
     * 
     * @param message sent by callee to constructor
     * @param propName property name
     * @param propValue property value
     * @return error message to pass to super constuctor
     */
    protected static String generateErrorMessage(String message, String propName, String propValue) {
        StringBuilder buffer = new StringBuilder();
        if( message != null ) {
            buffer.append(message).append(": ");
        }
        buffer.append("Invalid property '").append(propName);
        buffer.append("' with value: ").append(propValue);
        return buffer.toString();
    }
    
}
