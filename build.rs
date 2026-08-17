// build.rs — link against IDA's libida/libidalib via idalib-build.
// IDADIR must point at the dir containing the `ida`/`idat` executables.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    idalib_build::configure_linkage()?;
    Ok(())
}
