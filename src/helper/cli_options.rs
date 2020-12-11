use clap::Clap;


/// This tool decrypts backup files created & encrypted by Titanium Backup on Android.
/// You provide the input file and the target output file.
/// The passphrase is read from shell, then the file is decoded and written to the output file.
#[derive(Clap)]
#[clap(version = "0.1", author = "Jan <misternerd@users.noreply.github.com>")]
pub struct CliOpts {
    /// The encrypted input file, as created by Titanium Backup
    #[clap(short, long)]
    pub input_file: String,
    /// The output file, where you'd like to store the decrypted result
    #[clap(short, long)]
    pub output_file: String,
}