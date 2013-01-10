vngx-jsch - A Java SSH implementation
=====================================

**vngx-jsch** is an updated version of the popular JSch SSH library 
written in pure Java.  It has been updated to Java 6 with all the latest 
language features and improved code clarity.

Improvements include:

* Javadoc comments!  Have you ever been frustrated at the lack of comments in the original JSch library?
* Improved error handling - many errors which were silently ignored or masked properly bubble up and offer more detailed descriptions.
* Performance improvements including code optimization and enhanced concurrency practices.
* Enhanced configuration for Sessions and configuration constants for specifying client-defined properties.
* Added support for SHA-256, HMAC-SHA-256, "diffie-hellman-group-exchange-sha256" and "diffie-hellman-group14-sha1" algorithms.
* Added support for more detailed application logging for debugging.
* Updated to more closely follow the official RFC specifications for SSH as well as added detailed documentation from RFCs into the comments.
* Maven build process
* OSGi compatible
 
Now available via any central Maven repo
=====================================
 just add the following to your pom.xml under dependencies:

    <dependency>
        <groupId>org.vngx</groupId>
        <artifactId>vngx-jsch</artifactId>
        <version>0.10</version>
    </dependency>
