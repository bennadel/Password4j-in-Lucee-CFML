/**
* I provide a Lucee CFML wrapper around the Password4j Java library.
* 
* GitHub: https://github.com/Password4j/password4j
* Maven: https://mvnrepository.com/artifact/com.password4j/password4j
*/
component
	output = false
	hint = "I provide password hashing and verification functions (using Password4j)."
	{

	variables.defaults = {
		// These properties are described here:
		// - https://github.com/Password4j/password4j/wiki/Argon2
		argon2: {
			memory: 12,
			iterations: 20,
			parallelisation: 2,
			ouputLength: 32,
			type: "Argon2id",
			version: 19
		},
		// These properties are described here:
		// - https://github.com/Password4j/password4j/wiki/BCrypt
		bcrypt: {
			version: "B",
			costFactor: 10
		},
		// These properties are described here:
		// - https://github.com/Password4j/password4j/wiki/Scrypt
		scrypt: {
			workFactor: 32768,
			resources: 8,
			parallelisation: 1,
			outputLength: 64,
			// Added for Adobe ColdFusion 2021 interoperability.
			saltLength: 8
		}
	};

	/**
	* I initialize the password component with the given Password4j JAR paths.
	*/
	public void function init( required array jarPaths ) {

		variables.jarPaths = arguments.jarPaths;

	}

	// ---
	// PUBLIC METHODS.
	// ---

	/**
	* I generate an Argon2 hash of the given input using the given characteristics. All
	* characteristics are optional; and, any not provided will use the defined defaults.
	*/
	public string function argon2HashGet(
		required string input,
		numeric memory = defaults.argon2.memory,
		numeric iterations = defaults.argon2.iterations,
		numeric parallelisation = defaults.argon2.parallelisation,
		numeric ouputLength = defaults.argon2.ouputLength,
		string type = defaults.argon2.type,
		numeric version = defaults.argon2.version
		) {

		var enum = javaNew( "com.password4j.types.Argon2" );

		switch ( type ) {
			case "Argon2d":
			case "Argon2i":
			case "Argon2id":
				var enumToken = type.listRest( "2" ).ucase();
				var enumType = enum[ enumToken ];
			break;
			default:
				throw(
					type = "InvalidArgon2Type",
					message = "Valid argon2 types are: Argon2d, Argon2i, Argon2id (recommended)",
					detail = "Provided type: #type#"
				);
			break;
		}

		var hashingFunction = javaNew( "com.password4j.Argon2Function" )
			.getInstance( memory, iterations, parallelisation, ouputLength, enumType, version )
		;
		var hashedInput = javaNew( "com.password4j.Password" )
			.hash( input )
			.with( hashingFunction )
			.getResult()
		;

		return( hashedInput );

	}


	/**
	* I verify the Argon2 hash of the given input against the expected hash.
	* 
	* NOTE: All hash-algorithm characteristics will be pulled directly out of the
	* expected hash. As such, they do not need to be provided as arguments.
	*/
	public boolean function argon2HashVerify(
		required string input,
		required string hashedInput
		) {

		var hashingFunction = javaNew( "com.password4j.Argon2Function" )
			.getInstanceFromHash( hashedInput )
		;
		var isVerified = javaNew( "com.password4j.Password" )
			.check( input, hashedInput )
			.with( hashingFunction )
		;

		return( isVerified );

	}


	/**
	* I generate a BCrypt hash of the given input using the given characteristics. All
	* characteristics are optional; and, any not provided will use the defined defaults.
	*/
	public string function bcryptHashGet(
		required string input,
		string version = variables.defaults.bcrypt.version,
		numeric costFactor = variables.defaults.bcrypt.costFactor
		) {

		var enum = javaNew( "com.password4j.types.BCrypt" );

		switch ( version ) {
			case "a":
			case "b":
			case "x":
			case "y":
				var enumToken = version.ucase();
				var enumVersion = enum[ enumToken ];
			break;
			default:
				throw(
					type = "InvalidBcryptVersion",
					message = "Valid bcrypt versions are: a, b (recommended), x, y",
					detail = "Provided version: #version#"
				);
			break;
		}

		var hashingFunction = javaNew( "com.password4j.BCryptFunction" )
			.getInstance( enumVersion, costFactor )
		;
		var hashedInput = javaNew( "com.password4j.Password" )
			.hash( input )
			.with( hashingFunction )
			.getResult()
		;

		return( hashedInput );

	}


	/**
	* I verify the BCrypt hash of the given input against the expected hash.
	* 
	* NOTE: All hash-algorithm characteristics will be pulled directly out of the
	* expected hash. As such, they do not need to be provided as arguments.
	*/
	public boolean function bcryptHashVerify(
		required string input,
		required string hashedInput
		) {

		var hashingFunction = javaNew( "com.password4j.BCryptFunction" )
			.getInstanceFromHash( hashedInput )
		;
		var isVerified = javaNew( "com.password4j.Password" )
			.check( input, hashedInput )
			.with( hashingFunction )
		;

		return( isVerified );

	}


	/**
	* I generate a SCrypt hash of the given input using the given characteristics. All
	* characteristics are optional; and, any not provided will use the defined defaults.
	*/
	public string function scryptHashGet(
		required string input,
		numeric workFactor = defaults.scrypt.workFactor,
		numeric resources = defaults.scrypt.resources,
		numeric parallelisation = defaults.scrypt.parallelisation,
		numeric outputLength = defaults.scrypt.outputLength,
		numeric saltLength = defaults.scrypt.saltLength
		) {

		var hashingFunction = javaNew( "com.password4j.SCryptFunction" )
			.getInstance( workFactor, resources, parallelisation, outputLength )
		;
		var hashedInput = javaNew( "com.password4j.Password" )
			.hash( input )
			.addRandomSalt( saltLength )
			.with( hashingFunction )
			.getResult()
		;

		return( hashedInput );

	}


	/**
	* I verify the SCrypt hash of the given input against the expected hash.
	* 
	* NOTE: All hash-algorithm characteristics will be pulled directly out of the
	* expected hash. As such, they do not need to be provided as arguments.
	*/
	public boolean function scryptHashVerify(
		required string input,
		required string hashedInput
		) {

		var hashingFunction = javaNew( "com.password4j.SCryptFunction" )
			.getInstanceFromHash( hashedInput )
		;

		var isVerified = javaNew( "com.password4j.Password" )
			.check( input, hashedInput )
			.with( hashingFunction )
		;

		return( isVerified );

	}


	/**
	* I update the default arguments for the Argon2 hashing method.
	*/
	public any function withArgon2Defaults(
		numeric memory = defaults.argon2.memory,
		numeric iterations = defaults.argon2.iterations,
		numeric parallelisation = defaults.argon2.parallelisation,
		numeric ouputLength = defaults.argon2.ouputLength,
		string type = defaults.argon2.type,
		numeric version = defaults.argon2.version
		) {

		defaults.argon2.memory = memory;
		defaults.argon2.iterations = iterations;
		defaults.argon2.parallelisation = parallelisation;
		defaults.argon2.ouputLength = ouputLength;
		defaults.argon2.type = type;
		defaults.argon2.version = version;

		return( this );

	}


	/**
	* I update the default arguments for the BCrypt hashing method.
	*/
	public any function withBCryptDefaults(
		string version = defaults.bcrypt.version,
		string costFactor = defaults.bcrypt.costFactor
		) {

		defaults.bcrypt.version = version;
		defaults.bcrypt.costFactor = costFactor;

		return( this );

	}


	/**
	* I update the default arguments for the SCrypt hashing method.
	*/
	public any function withSCryptDefaults(
		numeric workFactor = defaults.scrypt.workFactor,
		numeric resources = defaults.scrypt.resources,
		numeric parallelisation = defaults.scrypt.parallelisation,
		numeric outputLength = defaults.scrypt.outputLength,
		numeric saltLength = defaults.scrypt.saltLength
		) {

		defaults.scrypt.workFactor = workFactor;
		defaults.scrypt.resources = resources;
		defaults.scrypt.parallelisation = parallelisation;
		defaults.scrypt.outputLength = outputLength;
		defaults.scrypt.saltLength = saltLength;

		return( this );

	}

	// ---
	// PRIVATE METHODS.
	// ---

	/**
	* I create the given Java class using the Password4j JAR paths.
	*/
	private any function javaNew( required string className ) {

		return( createObject( "java", className, jarPaths ) );

	}

}
