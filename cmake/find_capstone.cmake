#
# Copyright 2017, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# pkg_search_module() is used instead of find_package() to verify and modify
# capstone_CFLAGS. When capstone.pc reports multiple paths, CMake separates them
# with ';', which Makefile interprets as the end of a statement. Also, find the
# correct path to capstone.h to ensure src/capstone_wrapper.h compiles properly.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
	pkg_search_module(capstone capstone>=6.0 QUIET)
endif()

if(capstone_FOUND)
	# remove -I flag to get only the list of directories separated by ';'
	string(REPLACE "-I" "" capstone_paths "${capstone_CFLAGS}")

	# find capstone.h inside of available paths
	find_path(capstone_dir capstone.h PATHS ${capstone_paths} REQUIRED NO_DEFAULT_PATH)
	message(STATUS "Found capstone.h in: ${capstone_dir}")

	# set capstone_CFLAGS with only one directory containing capstone.h
	set(capstone_CFLAGS "-I${capstone_dir}")

	unset(capstone_paths)
	unset(capstone_dir)
else()
	message(FATAL_ERROR
"Unable to find capstone >= 6.0. Please install pkg-config and capstone development files, e.g.:
	sudo apt install pkg-config libcapstone-dev=6 (on Debian, Ubuntu)
or
	sudo dnf install capstone-devel=6 (on Fedora)
or see instructions for other ways of installing capstone: http://www.capstone-engine.org/download.html https://github.com/capstone-engine/capstone/blob/next/BUILDING.md
If casptone is installed, but cmake didn't manage to find it, there is a slight chance of fixing things by setting some of the following environment variables:
PKG_CONFIG_PATH, CMAKE_PREFIX_PATH, CMAKE_MODULE_PATH")
endif()
