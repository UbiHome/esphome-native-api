use std::fs;
use std::io::Error;

use std::path::{Path, PathBuf};

fn main() {
    let mut config = prost_build::Config::new();
    // config.skip_debug(&["."]);
    config.out_dir("../src/generated");
    config.include_file("mod.rs");
    config.compile_protos(&["src/protos/api.proto"], &["./src/protos/"]).unwrap();


    // protobuf_codegen::Codegen::new()
    //     // Use `protoc` parser
    //     .protoc()
    //     // .protoc_path(&Path::new("/usr/local/bin/protoc"))
    //     // All inputs and imports from the inputs must reside in `includes` directories.
    //     .includes(&["src/protos"])
    //     // Path::new("/usr/local/include/google/protobuf/").to_owned(),
    //     // Inputs must reside in some of include paths.
    //     // .input("src/protos/apple.proto")
    //     .input("src/protos/api.proto")
    //     // Specify output directory
    //     .out_dir("../src/generated")
    //     .run_from_script();
}
