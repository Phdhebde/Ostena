use ostena_common::secret::SecretString;

// A struct holding a secret (such as a future Config field) cannot derive Debug.
#[derive(Debug)]
struct Credential {
    user: String,
    password: SecretString,
}

fn main() {}
