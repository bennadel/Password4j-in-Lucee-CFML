<cfscript>

	passwordUtil = new Password([
		"./lib/password4j/commons-lang3-3.12.0.jar",
		"./lib/password4j/password4j-1.5.3.jar",
		"./lib/password4j/slf4j-api-1.7.30.jar",
		"./lib/password4j/slf4j-nop-1.7.30.jar"
	]);

	// For the sake of simplicity, assume this is a FORM POST over HTTPS.
	username = "ben@bennadel.com";
	password = "intelligentUrgency";

	authenticateUser( username, password );

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	/**
	* I attempt to authenticate the given credentials for the application login.
	*/
	public boolean function authenticateUser(
		required string username,
		required string password
		) {

		var expectedHash = getPasswordHashForUser( username );

		// Migrating password hashing algorithms only needs to happen once per user. As
		// such, we should optimize the login workflow to assume the user has the correct
		// hash; and then, FALL BACK to the old algorithm only as needed. In this case,
		// we want to get all users on the BCrypt algorithm so we're going to check for
		// the BCrypt outcome first.
		// --
		// NOTE: Since our PasswordUtil is expecting to verify against a BCrypt hash, we
		// need to wrap this in a Try/Catch as it will throw an error when attempting to
		// consume an MD5 hash as if it were a BCrypt hash.
		try {

			if ( passwordUtil.bcryptHashVerify( password, expectedHash ) ) {

				return( true );

			}

		} catch ( any error ) {

			systemOutput( "Could not verifying BCrypt hash, moving onto older hash.", true );

		}

		// Now that we've failed to verify the user's password against the BCrypt hash,
		// let's check to see if the password can be verified against the OLD, INSECURE
		// MD5 hash.
		if ( expectedHash == hash( password ) ) {

			systemOutput( "Older, insecure MD5 hash [#expectedHash#] verified for user.", true );

			// TIME TO MIGRATE THE HASHING ALGORITHM: This user's record is still using
			// the OLD, INSECURE MD5 hash. We need to update their record to use the
			// modern, BCrypt hash.
			setPasswordHashForUser( username, passwordUtil.bcryptHashGet( password ) );
			return( true );

		}

		// If we made it this far, none of the password hashing algorithms could be
		// verified - the user provided the wrong password.
		return( false );

	}


	/**
	* I get the persisted password hash for the given user.
	*/
	public string function getPasswordHashForUser( required string username ) {

		// Return the MD5-hash of the "intelligentUrgency".
		return( "d49a5b5dff1f7dfcc2fd3d0b85dcd0a3" );

	}


	/**
	* I persist the given password hash for the given user.
	*/
	public void function setPasswordHashForUser(
		required string username,
		required string passwordHash
		) {

		systemOutput( "Storing hash [#passwordHash#] for user [#username#]", true );

	}

</cfscript>
