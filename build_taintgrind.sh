#!/bin/bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
valgrind_root="$(cd "$script_dir/.." && pwd)"
use_capstone=no

# Find out how far we can parallelize the build.
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)"
if [ -z "$jobs" ] || [ "$jobs" -lt 1 ]; then
    jobs=1
fi

download() {
    local url="$1"
    local output="$2"

    if command -v wget >/dev/null 2>&1; then
        wget "$url" -O "$output"
    elif command -v curl >/dev/null 2>&1; then
        curl -L "$url" -o "$output"
    else
        echo "Error: install wget or curl to download $url" >&2
        exit 1
    fi
}

patch_valgrind_build_files() {
    local makefile_am="$valgrind_root/Makefile.am"
    local configure_ac="$valgrind_root/configure.ac"

    if ! grep -Eq '^[[:space:]]*taintgrind([[:space:]\\]|$)' "$makefile_am"; then
        sed -i '/^[[:space:]]*none[[:space:]]*$/ {
            s/$/ \\/
            a\
		taintgrind
        }' "$makefile_am"
        echo "Patched Makefile.am: added taintgrind to TOOLS"
    fi

    if ! grep -Eq '^[[:space:]]*taintgrind/Makefile[[:space:]]*$' "$configure_ac"; then
        sed -i '/^[[:space:]]*shared\/Makefile[[:space:]]*$/i\
   taintgrind/Makefile\
   taintgrind/tests/Makefile
' "$configure_ac"
        echo "Patched configure.ac: added Taintgrind Makefiles"
    fi

    if ! grep -q 'enable-taintgrind-capstone' "$configure_ac"; then
        sed -i '/^# Ok\.  We.*done checking\./i\
AC_ARG_ENABLE([taintgrind-capstone],\
              AS_HELP_STRING([--enable-taintgrind-capstone],\
                             [use Capstone for Taintgrind assembly formatting]),\
              [], [enable_taintgrind_capstone=no])\
AM_CONDITIONAL([ENABLE_TAINTGRIND_CAPSTONE],\
               [test "x$enable_taintgrind_capstone" = xyes])\

' "$configure_ac"
        echo "Patched configure.ac: added optional Capstone support"
    fi
}

prepare_capstone() {
    local capstone_version
    local archive
    local source_dir

    capstone_version="$(sed -n 's/^CAPSTONE_VERSION = //p' "$script_dir/Makefile.tool.am")"
    if [ -z "$capstone_version" ]; then
        echo "Error: could not determine CAPSTONE_VERSION" >&2
        exit 1
    fi

    archive="$script_dir/capstone.tar.gz"
    source_dir="$script_dir/capstone-$capstone_version"

    if [ -d "$script_dir/capstone" ]; then
        echo "Using existing $script_dir/capstone"
        return
    fi

    if [ ! -f "$archive" ]; then
        download "https://github.com/aquynh/capstone/archive/$capstone_version.tar.gz" "$archive"
    fi

    cd "$script_dir"
    tar xf "$archive"
    patch -p1 -d "$source_dir" < "$script_dir/capstone-$capstone_version.patch"
    mv "$source_dir" "$script_dir/capstone"
}

main() {
    local configure_args=("--prefix=$valgrind_root/build")

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --with-capstone)
                use_capstone=yes
                ;;
            -h|--help)
                echo "Usage: $0 [--with-capstone]"
                return 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                echo "Usage: $0 [--with-capstone]" >&2
                return 2
                ;;
        esac
        shift
    done

    patch_valgrind_build_files
    if [ "$use_capstone" = yes ]; then
        prepare_capstone
        configure_args+=(--enable-taintgrind-capstone)
    fi

    # Build Taintgrind as part of the main Valgrind tree so vg-in-place finds
    # the tool under $valgrind_root/.in_place.
    cd "$valgrind_root"
    ./autogen.sh
    ./configure "${configure_args[@]}"
    make -j"$jobs"
    make install
    make check
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
