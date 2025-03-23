use age::{secrecy::ExposeSecret as _, x25519::Identity};
use color_eyre::eyre::Result;

fn main() -> Result<()> {
    // Initialize error handling
    color_eyre::install()?;

    // Generate a new age identity
    let identity = Identity::generate();

    let key_string = identity.to_string();
    let key_string = key_string.expose_secret();

    // Print the key to stdout
    println!("Generated Age encryption key:");
    // We need to use the Display impl directly without Debug formatting
    print!("{}", key_string);
    println!();
    println!();
    println!("You can use this key as your ENCRYPTION_KEY environment variable.");
    println!("For example, add the following to your .env file:");
    print!("ENCRYPTION_KEY=\"{}\"", key_string);
    println!();

    Ok(())
}
