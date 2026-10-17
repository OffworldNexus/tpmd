// The linker needs *something* to produce a Mach-O at $EXECUTABLE_PATH; the
// build's last phase immediately replaces it with the cargo-built daemon. Its
// code never ships and never runs.
int main(void) { return 0; }
