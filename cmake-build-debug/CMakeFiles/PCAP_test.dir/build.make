# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.26

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/cmake-3.26.5-linux-aarch64/bin/cmake

# The command to remove a file.
RM = /opt/cmake-3.26.5-linux-aarch64/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/rafman/Desktop/pcap_test

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/rafman/Desktop/pcap_test/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/PCAP_test.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/PCAP_test.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/PCAP_test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/PCAP_test.dir/flags.make

CMakeFiles/PCAP_test.dir/main.cpp.o: CMakeFiles/PCAP_test.dir/flags.make
CMakeFiles/PCAP_test.dir/main.cpp.o: /home/rafman/Desktop/pcap_test/main.cpp
CMakeFiles/PCAP_test.dir/main.cpp.o: CMakeFiles/PCAP_test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rafman/Desktop/pcap_test/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/PCAP_test.dir/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/PCAP_test.dir/main.cpp.o -MF CMakeFiles/PCAP_test.dir/main.cpp.o.d -o CMakeFiles/PCAP_test.dir/main.cpp.o -c /home/rafman/Desktop/pcap_test/main.cpp

CMakeFiles/PCAP_test.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/PCAP_test.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rafman/Desktop/pcap_test/main.cpp > CMakeFiles/PCAP_test.dir/main.cpp.i

CMakeFiles/PCAP_test.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/PCAP_test.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rafman/Desktop/pcap_test/main.cpp -o CMakeFiles/PCAP_test.dir/main.cpp.s

CMakeFiles/PCAP_test.dir/pcap_input.cpp.o: CMakeFiles/PCAP_test.dir/flags.make
CMakeFiles/PCAP_test.dir/pcap_input.cpp.o: /home/rafman/Desktop/pcap_test/pcap_input.cpp
CMakeFiles/PCAP_test.dir/pcap_input.cpp.o: CMakeFiles/PCAP_test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rafman/Desktop/pcap_test/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/PCAP_test.dir/pcap_input.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/PCAP_test.dir/pcap_input.cpp.o -MF CMakeFiles/PCAP_test.dir/pcap_input.cpp.o.d -o CMakeFiles/PCAP_test.dir/pcap_input.cpp.o -c /home/rafman/Desktop/pcap_test/pcap_input.cpp

CMakeFiles/PCAP_test.dir/pcap_input.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/PCAP_test.dir/pcap_input.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rafman/Desktop/pcap_test/pcap_input.cpp > CMakeFiles/PCAP_test.dir/pcap_input.cpp.i

CMakeFiles/PCAP_test.dir/pcap_input.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/PCAP_test.dir/pcap_input.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rafman/Desktop/pcap_test/pcap_input.cpp -o CMakeFiles/PCAP_test.dir/pcap_input.cpp.s

CMakeFiles/PCAP_test.dir/ip_statistics.cpp.o: CMakeFiles/PCAP_test.dir/flags.make
CMakeFiles/PCAP_test.dir/ip_statistics.cpp.o: /home/rafman/Desktop/pcap_test/ip_statistics.cpp
CMakeFiles/PCAP_test.dir/ip_statistics.cpp.o: CMakeFiles/PCAP_test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rafman/Desktop/pcap_test/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/PCAP_test.dir/ip_statistics.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/PCAP_test.dir/ip_statistics.cpp.o -MF CMakeFiles/PCAP_test.dir/ip_statistics.cpp.o.d -o CMakeFiles/PCAP_test.dir/ip_statistics.cpp.o -c /home/rafman/Desktop/pcap_test/ip_statistics.cpp

CMakeFiles/PCAP_test.dir/ip_statistics.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/PCAP_test.dir/ip_statistics.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rafman/Desktop/pcap_test/ip_statistics.cpp > CMakeFiles/PCAP_test.dir/ip_statistics.cpp.i

CMakeFiles/PCAP_test.dir/ip_statistics.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/PCAP_test.dir/ip_statistics.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rafman/Desktop/pcap_test/ip_statistics.cpp -o CMakeFiles/PCAP_test.dir/ip_statistics.cpp.s

# Object files for target PCAP_test
PCAP_test_OBJECTS = \
"CMakeFiles/PCAP_test.dir/main.cpp.o" \
"CMakeFiles/PCAP_test.dir/pcap_input.cpp.o" \
"CMakeFiles/PCAP_test.dir/ip_statistics.cpp.o"

# External object files for target PCAP_test
PCAP_test_EXTERNAL_OBJECTS =

PCAP_test: CMakeFiles/PCAP_test.dir/main.cpp.o
PCAP_test: CMakeFiles/PCAP_test.dir/pcap_input.cpp.o
PCAP_test: CMakeFiles/PCAP_test.dir/ip_statistics.cpp.o
PCAP_test: CMakeFiles/PCAP_test.dir/build.make
PCAP_test: CMakeFiles/PCAP_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/rafman/Desktop/pcap_test/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable PCAP_test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/PCAP_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/PCAP_test.dir/build: PCAP_test
.PHONY : CMakeFiles/PCAP_test.dir/build

CMakeFiles/PCAP_test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/PCAP_test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/PCAP_test.dir/clean

CMakeFiles/PCAP_test.dir/depend:
	cd /home/rafman/Desktop/pcap_test/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rafman/Desktop/pcap_test /home/rafman/Desktop/pcap_test /home/rafman/Desktop/pcap_test/cmake-build-debug /home/rafman/Desktop/pcap_test/cmake-build-debug /home/rafman/Desktop/pcap_test/cmake-build-debug/CMakeFiles/PCAP_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/PCAP_test.dir/depend

