# Cipher Mode Demonstration

This project is a demonstration of how different cipher modes work.
You can either encrypt a file completely or pass the `--image` flag
to encrypt the image data inside a png file (for fancy demonstration).

Warning: The goal of this project is not to provide a way to encrypt
or decrypt files. The chosen key-derive algorithm (sha128) and block size is not secure
enough and with the initialization vector not being stored (full) decryption
is not possible (in a decent amount of time).

## Installation

```sh
git clone https://github.com/parallel-programming-hwr/cipher-mode-demonstration
cd cipher-mode-demonstration
cargo run --release -- <args>
```

## Usage

```
cipher-mode-demonstration 0.1.0
   
   USAGE:
       cipher-mode-demonstration [FLAGS] [OPTIONS] <input> <output>
   
   FLAGS:
       -h, --help       Prints help information
       -i, --image      If the output should be an image
       -V, --version    Prints version information
   
   OPTIONS:
       -m, --mode <mode>    The mode of operation that is being used One of ECB, CBC, CFB, CTR [default: CFB]
   
   ARGS:
       <input>     Input file for the plain text
       <output>    Output file for the ciphertext
```