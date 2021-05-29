<cfscript>

	input = "Kablamo$auce";

	data = [
		{
			algorithm: "bcrypt",
			input: input,
			hashedInput: generateBcryptHash( input )
		},
		{
			algorithm: "scrypt",
			input: input,
			hashedInput: generateScryptHash( input )
		}
	];

	fileWrite( expandPath( "./interop.json" ), serializeJson( data ) );

</cfscript>
