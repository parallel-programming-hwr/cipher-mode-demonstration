use structopt::StructOpt;
use std::path::PathBuf;
use block_modes::{BlockMode, Ecb, Cbc, Cfb};
use ctr::Ctr128;
use aes::Aes128;
use block_modes::block_padding::ZeroPadding;
use rpassword::read_password_from_tty;
use sha2::{Sha256, Digest};
use rand::Rng;
use std::fs::{read, File};
use std::io::{BufWriter, Write};
use ctr::stream_cipher::{
    NewStreamCipher, SyncStreamCipher
};

use ctr::stream_cipher::generic_array::GenericArray;

type Aes128Ecb = Ecb<Aes128, ZeroPadding>;
type Aes128Cbc = Cbc<Aes128, ZeroPadding>;
type Aes128Cfb = Cfb<Aes128, ZeroPadding>;
type Aes128Ctr = Ctr128<Aes128>;


#[derive(StructOpt, Debug)]
struct Opt {
    /// Input file for the plain text
    #[structopt(parse(from_os_str))]
    input: PathBuf,

    /// Output file for the ciphertext
    #[structopt(parse(from_os_str))]
    output: PathBuf,

    /// The mode of operation that is being used
    /// One of ECB, CBC, CFB, CTR
    #[structopt(short, long, default_value = "CFB")]
    mode: String,

    /// If the output should be an image
    #[structopt(short, long)]
    image: bool,
}

fn main() {
    let opt: Opt = Opt::from_args();
    let mut writer = BufWriter::new(File::create(&opt.output).unwrap());
    if opt.image {
        let decoder = png::Decoder::new(File::open(opt.input).unwrap());
        let (info, mut reader) = decoder.read_info().unwrap();
        let mut img_buffer = vec![0; info.buffer_size()];
        reader.next_frame(&mut img_buffer).unwrap();
        let cipher = encrypt(&img_buffer, opt.mode);
        let mut encoder = png::Encoder::new(writer, info.width, info.height);
        encoder.set_color(info.color_type);
        encoder.set_depth(info.bit_depth);
        let mut writer = encoder.write_header().unwrap();
        writer.write_image_data(&cipher[..img_buffer.len()]).unwrap();
    } else {
        let contents = read(&opt.input).unwrap();
        let cipher = encrypt(&contents, opt.mode);
        println!("{:?}", cipher);
        writer.write_all(&cipher).unwrap();
        writer.flush().unwrap();
    }
}

fn encrypt(data: &[u8], mode: String) -> Vec<u8> {
    let key = get_key();
    match mode.as_str() {
        "ECB" => encrypt_ecb(data, &key),
        "CBC" => encrypt_cbc(data, &key),
        "CFB" => encrypt_cfb(data, &key),
        "CTR" => encrypt_ctr(data, &key),
        _ => panic!("Unknown Mode")
    }
}

fn encrypt_ecb(data: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = rand::thread_rng().gen::<[u8; 16]>();
    let cipher = Aes128Ecb::new_var(&key, &iv).unwrap();

    cipher.encrypt_vec(data)
}

fn encrypt_cbc(data: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = rand::thread_rng().gen::<[u8; 16]>();
    let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();

    cipher.encrypt_vec(data)
}

fn encrypt_cfb(data: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = rand::thread_rng().gen::<[u8; 16]>();
    let cipher = Aes128Cfb::new_var(&key, &iv).unwrap();

    cipher.encrypt_vec(data)
}

fn encrypt_ctr(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update( key);
    let nonce = hasher.finalize()[0..16].to_vec();
    let mut cipher = Aes128Ctr::new(GenericArray::from_slice(&key), GenericArray::from_slice(&nonce));
    let mut data = data.to_vec();
    cipher.apply_keystream(&mut data);

    data.to_vec()
}

fn get_key() -> Vec<u8> {
    let pw = read_password_from_tty(Some("Password: ")).unwrap();
    let mut hasher = Sha256::default();
    hasher.update(pw.as_bytes());

    hasher.finalize()[0..16].to_vec()
}