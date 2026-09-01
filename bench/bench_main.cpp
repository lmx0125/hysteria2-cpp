// bench_main.cpp - Main entry point for hy2 benchmarks.
#include "bench.hpp"

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    return hybench::BenchRunner::RunAll();
}
