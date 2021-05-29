<cfscript>

	password = new Password([
		"./lib/password4j/commons-lang3-3.12.0.jar",
		"./lib/password4j/password4j-1.5.3.jar",
		"./lib/password4j/slf4j-api-1.7.30.jar",
		"./lib/password4j/slf4j-nop-1.7.30.jar"
	]);

	// Configure Password4j defaults to use the same settings that Adobe ColdFusion 2021
	// generateBcryptHash() and generateScryptHash() functions will use if we don't pass-
	// in any additional options.
	password
		.withBcryptDefaults(
			version = "a",
			costFactor = 10
		)
		.withScryptDefaults(
			// CAUTION: The Adobe ColdFusion 2021 documentation says that the default
			// work factor it "16,348", which is the WRONG output of (2^14).
			workFactor = 16384,
			resources = 8,
			parallelisation = 1,
			outputLength = 32,
			saltLength = 8
		)
	;

	input = "Kablamo$auce";

	// When generating the Lucee CFML outputs, we'll just use the Password4j defaults.
	data = [
		{
			algorithm: "bcrypt",
			input: input,
			hashedInput: password.bcryptHashGet( input )
		},
		{
			algorithm: "scrypt",
			input: input,
			hashedInput: password.scryptHashGet( input )
		}
	];

	fileWrite( expandPath( "./interop.json" ), serializeJson( data ) );

</cfscript>
