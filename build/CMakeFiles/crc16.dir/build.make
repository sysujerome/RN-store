# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

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


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/pjl/lab/RN-store

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/pjl/lab/RN-store/build

# Include any dependencies generated for this target.
include CMakeFiles/crc16.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/crc16.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/crc16.dir/flags.make

CMakeFiles/crc16.dir/src/crc16.c.o: CMakeFiles/crc16.dir/flags.make
CMakeFiles/crc16.dir/src/crc16.c.o: ../src/crc16.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/pjl/lab/RN-store/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/crc16.dir/src/crc16.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/crc16.dir/src/crc16.c.o   -c /home/pjl/lab/RN-store/src/crc16.c

CMakeFiles/crc16.dir/src/crc16.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/crc16.dir/src/crc16.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/pjl/lab/RN-store/src/crc16.c > CMakeFiles/crc16.dir/src/crc16.c.i

CMakeFiles/crc16.dir/src/crc16.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/crc16.dir/src/crc16.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/pjl/lab/RN-store/src/crc16.c -o CMakeFiles/crc16.dir/src/crc16.c.s

# Object files for target crc16
crc16_OBJECTS = \
"CMakeFiles/crc16.dir/src/crc16.c.o"

# External object files for target crc16
crc16_EXTERNAL_OBJECTS =

libcrc16.a: CMakeFiles/crc16.dir/src/crc16.c.o
libcrc16.a: CMakeFiles/crc16.dir/build.make
libcrc16.a: CMakeFiles/crc16.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/pjl/lab/RN-store/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library libcrc16.a"
	$(CMAKE_COMMAND) -P CMakeFiles/crc16.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/crc16.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/crc16.dir/build: libcrc16.a

.PHONY : CMakeFiles/crc16.dir/build

CMakeFiles/crc16.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/crc16.dir/cmake_clean.cmake
.PHONY : CMakeFiles/crc16.dir/clean

CMakeFiles/crc16.dir/depend:
	cd /home/pjl/lab/RN-store/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/pjl/lab/RN-store /home/pjl/lab/RN-store /home/pjl/lab/RN-store/build /home/pjl/lab/RN-store/build /home/pjl/lab/RN-store/build/CMakeFiles/crc16.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/crc16.dir/depend

