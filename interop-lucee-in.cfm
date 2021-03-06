<cfscript>

	password = new Password([
		"./lib/password4j/commons-lang3-3.12.0.jar",
		"./lib/password4j/password4j-1.5.3.jar",
		"./lib/password4j/slf4j-api-1.7.30.jar",
		"./lib/password4j/slf4j-nop-1.7.30.jar"
	]);

	// Read-in the file generated by Adobe ColdFusion 2021 built-in functions.
	data = deserializeJson( fileRead( "./interop.json" ) );

	for ( test in data ) {

		switch ( test.algorithm ) {
			case "bcrypt":

				input = test.input;
				hashedInput = test.hashedInput;

				dump( password.bcryptHashVerify( input, hashedInput ) );

			break;
			case "scrypt":

				input = test.input;
				// CAUTION: I have to prepend "$s0" to get Password4j to like the hash
				// generated by the Adobe ColdFusion 2021 scrypt function.
				hashedInput = ( "$s0" & test.hashedInput );

				dump( password.scryptHashVerify( input, hashedInput ) );

			break;
		}

	}

</cfscript>
