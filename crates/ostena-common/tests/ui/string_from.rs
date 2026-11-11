use ostena_common::secret::SecretString;

fn main() {
    let secret = SecretString::from(String::from("canary"));
    let _ = String::from(secret);
}
