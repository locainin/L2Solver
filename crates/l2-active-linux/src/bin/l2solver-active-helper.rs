fn main() {
    if l2_active_linux::run_helper().is_err() {
        std::process::exit(1);
    }
}
