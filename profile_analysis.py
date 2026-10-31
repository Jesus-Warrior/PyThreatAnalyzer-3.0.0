#!/usr/bin/env python3
"""Profile a representative PyThreatAnalyzer CLI scan without changing outputs."""
import argparse
import cProfile
import pstats

from cli import PyThreatAnalyzerCLI


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', help='Representative file to analyze')
    parser.add_argument('--stats', default='profile_analysis.prof', help='cProfile output file')
    parser.add_argument('--limit', type=int, default=20, help='Number of cumulative-time rows')
    args = parser.parse_args()

    cli = PyThreatAnalyzerCLI()
    profiler = cProfile.Profile()
    profiler.runcall(cli.scan_file, args.file)
    profiler.dump_stats(args.stats)
    pstats.Stats(profiler).strip_dirs().sort_stats('cumulative').print_stats(args.limit)
    print(f'Profile saved to {args.stats}')


if __name__ == '__main__':
    main()
