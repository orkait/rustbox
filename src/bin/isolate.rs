use anyhow::Result;

fn main() -> Result<()> {
    rustbox::cli::run(rustbox::cli::CliMode::Isolate)
}
