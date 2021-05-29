<cfscript>

	// Create our Password4j wrapper.
	// --
	// NOTE: One of the coolest features of Lucee CFML is the fact that we can load Java
	// classes directly from a set of JAR files. I've downloaded the Password4j v1.5.3
	// files from the Maven repository:
	// - https://mvnrepository.com/artifact/com.password4j/password4j
	password = new Password([
		"./lib/password4j/commons-lang3-3.12.0.jar",
		"./lib/password4j/password4j-1.5.3.jar",
		"./lib/password4j/slf4j-api-1.7.30.jar",
		"./lib/password4j/slf4j-nop-1.7.30.jar"
	]);

	myPassword = "Ca$hRulezEverythingAroundM3!";

	// ------------------------------------------------------------------------------- //
	// ------------------------------------------------------------------------------- //

	timer
		label = "Testing BCrypt with defaults"
		type = "outline"
		{

		hashedPassword = password.bcryptHashGet( myPassword );

		dump( myPassword );
		dump( hashedPassword );
		dump( hashedPassword.len() );
		dump( password.bcryptHashVerify( myPassword, hashedPassword ) );

	}

	echo( "<hr />" );

	timer
		label = "Testing SCrypt with defaults"
		type = "outline"
		{

		hashedPassword = password.scryptHashGet( myPassword );

		dump( myPassword );
		dump( hashedPassword );
		dump( hashedPassword.len() );
		dump( password.scryptHashVerify( myPassword, hashedPassword ) );

	}

	echo( "<hr />" );

	timer
		label = "Testing Argon2 with defaults"
		type = "outline"
		{

		hashedPassword = password.argon2HashGet( myPassword );

		dump( myPassword );
		dump( hashedPassword );
		dump( hashedPassword.len() );
		dump( password.argon2HashVerify( myPassword, hashedPassword ) );

	}

</cfscript>
