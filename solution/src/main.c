
#include "error_messages.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <unistd.h>

static const size_t FILE_PATH_ARGUMENT_INDEX = 1;
static const size_t SECTION_NAME_ARGUMENT_INDEX = 2;
static const size_t ARGUMENT_COUNT = 2;
static const size_t MAX_STRING_LENGTH_TO_COPARE = 10000;

struct ProgramConfiguration {
  char * file_path;
  char * section_name;
};

struct ProgramConfiguration build_program_configuration(int     argc,
                                                        char ** argv) {
  // argument with index zero is unspecified
  if (argc != ARGUMENT_COUNT + 1) {
    PRINT_ERROR_AND_EXIT(ARGUMENT_WRONG_COUNT);
  }

  return (struct ProgramConfiguration){
      .file_path = argv[FILE_PATH_ARGUMENT_INDEX],
      .section_name = argv[SECTION_NAME_ARGUMENT_INDEX],
  };
}

bool is_elf_file_valid(const Elf64_Ehdr * const header) {
  const unsigned char * const elf_identifier = header->e_ident;
  if (elf_identifier[EI_MAG0] != 0x7f || elf_identifier[EI_MAG1] != 'E'
      || elf_identifier[EI_MAG2] != 'L' || elf_identifier[EI_MAG3] != 'F') {
    return false;
  }

  return true;
}

void read_at_absolute_offset(const int    fd,
                             const off_t  offset,
                             void * const buffer,
                             size_t       size) {

  if (lseek(fd, offset, SEEK_SET) == -1) {
    PRINT_ERROR_AND_EXIT(LSEEK_FAILED);
  }

  const ssize_t read_status = read(fd, buffer, size);
  if (read_status == 0) {
    write(STDERR_FILENO, UNEXPECTED_EOF, sizeof(UNEXPECTED_EOF));
    // 
    _exit(EIO);
  }
  if (read_status == -1) {
    PRINT_ERROR_AND_EXIT(READ_FAILED);
  }
}

bool is_start_address_valid(const Elf64_Phdr * const header, const size_t address) {
  // segment should be both executable and readable to
  // deligate control to
  if (!((header->p_flags & PF_X) && (header->p_flags & PF_R))) {
    return false;
  }

  // if address out of bounds
  if (!(header->p_vaddr <= address && address < (header->p_vaddr + header->p_memsz))) {
    return false;
  }

  return true;
}

int build_segment_permissions(const Elf64_Phdr * const segment) {
    int segment_actual_permissions = PROT_NONE;
    if (segment->p_flags & PF_X) {
      segment_actual_permissions |= PROT_EXEC;
    }

    if (segment->p_flags & PF_W) {
      segment_actual_permissions |= PROT_WRITE;
    }

    if (segment->p_flags & PF_R) {
      segment_actual_permissions |= PROT_READ;
    }

    return segment_actual_permissions;
}

/// Consequentially load segments to the memory.
///
/// Segments act as an image. We should load all of
/// them regardless of section passed.
/// 
/// @return `true` if start address is valid in any of loaded segments
bool load_segments(const int elf_fd, const Elf64_Ehdr * const header, const Elf64_Addr start_address) {

  bool is_valid_start_address = false;

  for (size_t index = 0; index < header->e_phnum; index++) {

    Elf64_Phdr segment = {0};
    read_at_absolute_offset(
        elf_fd,
        (off_t)(header->e_phoff + header->e_phentsize * index),
        &segment,
        sizeof(Elf64_Phdr));

    if (segment.p_type != PT_LOAD) {
      continue;
    }

    // once start address is valid this condition never fires
    if (!is_valid_start_address) {
      is_valid_start_address = is_start_address_valid(&segment, start_address);
    }

    const size_t aligned_segment_start = segment.p_vaddr & (~(PAGE_SIZE - 1));
    // high bound minus lower actual bound
    const size_t actual_size
        = (segment.p_memsz + segment.p_vaddr) - aligned_segment_start;

    // Map memory according to program header.
    // fd and offset values are required by linux kernel documentation.
    uint8_t * const segment_pointer = mmap((void *)aligned_segment_start,
                                           actual_size,
                                           PROT_WRITE,
                                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                           -1,
                                           0);
    if ((size_t) segment_pointer != aligned_segment_start) {
      PRINT_ERROR_AND_EXIT(MMAP_FAILED);
    }

    // if file size is not zero, read the content
    if (segment.p_filesz > 0) {
      // despite allocating a whole page, we still need to place code onto
      // desired address
      read_at_absolute_offset(elf_fd,
                              (off_t)segment.p_offset,
                              (void *)segment.p_vaddr,
                              segment.p_filesz);
    }

    const int segment_actual_permissions = build_segment_permissions(&segment);
    if (mprotect((void *)aligned_segment_start,
                 actual_size,
                 segment_actual_permissions)) {
      PRINT_ERROR_AND_EXIT(MPROTECT_FAILED);
    }
  }

  return is_valid_start_address;
}

Elf64_Shdr get_section_header_at_index(const int                elf_fd,
                                       const Elf64_Ehdr * const header,
                                       const Elf64_Half         index) {

  if (index == 0) {
    _exit(EINVAL);
  }

  const off_t absolute_header_offset
      = (off_t)(header->e_shoff + header->e_shentsize * index);

  Elf64_Shdr section_header = {0};
  read_at_absolute_offset(
      elf_fd, absolute_header_offset, &section_header, sizeof(Elf64_Shdr));

  return section_header;
}

Elf64_Off get_string_table_absolute_offset(const int                elf_fd,
                                           const Elf64_Ehdr * const header) {
  if (header->e_shstrndx == SHN_UNDEF) {
    PRINT_ERROR_AND_EXIT(NO_STRING_TABLE);
  }

  return get_section_header_at_index(elf_fd, header, header->e_shstrndx)
      .sh_offset;
}

Elf64_Half find_section_index_by_name(const int                elf_fd,
                                      const Elf64_Ehdr * const header,
                                      const char * const       section_name) {

  const Elf64_Off string_table_base_offset
      = get_string_table_absolute_offset(elf_fd, header);

  // first section is always special zeroed section
  for (size_t section_index = 1; section_index < header->e_shnum;
       section_index++) {

    // using general function with multiplication under the hood
    // to avoid premature optimizations
    const Elf64_Shdr section
        = get_section_header_at_index(elf_fd, header, section_index);

    lseek(
        elf_fd, (off_t)(string_table_base_offset + section.sh_name), SEEK_SET);

    // strings are considered equal when:
    // - every character matches
    // - strings have same length
    char   current_character = 0;
    size_t string_index = 0;
    for (size_t i = 0; i < MAX_STRING_LENGTH_TO_COPARE; i++) {
      if (read(elf_fd, &current_character, 1) != 1) {
        PRINT_ERROR_AND_EXIT(SECTION_NAME_COMPARISON_FAILED);
      }

      // - every character matches
      if (current_character != section_name[string_index]) {
        break;
      }

      // can't check for string length in advance
      // this condition ensure end of comparison
      // when strings are equal
      // - strings have same length
      if (current_character == 0 && section_name[string_index] == 0) {
        return section_index;
      }

      string_index += 1;
    }
  }

  return SHN_UNDEF;
}

int main(int argc, char ** argv) {
  const struct ProgramConfiguration config
      = build_program_configuration(argc, argv);

  // could not find appropriate constant for no open flags (zero)
  const int elf_file_fd = open(config.file_path, 0, O_RDONLY);
  if (elf_file_fd == -1) {
    PRINT_ERROR_AND_EXIT(OPEN_FAILED);
  }
  // read elf header
  Elf64_Ehdr elf_file_header = {0};
  read_at_absolute_offset(elf_file_fd, 0, &elf_file_header, sizeof(Elf64_Ehdr));

  // validate elf header
  if (!is_elf_file_valid(&elf_file_header)) {
    PRINT_ERROR_AND_EXIT(INVALID_ELF);
  }

  // load start address
  const Elf64_Half start_section_index = find_section_index_by_name(
      elf_file_fd, &elf_file_header, config.section_name);

  const Elf64_Shdr start_section = get_section_header_at_index(
      elf_file_fd, &elf_file_header, start_section_index);

  const Elf64_Addr start_address = start_section.sh_addr;

  const bool is_valid_start_address = load_segments(elf_file_fd, &elf_file_header, start_address);
  if (!is_valid_start_address) {
    _exit(EINVAL);
  }

  close(elf_file_fd);

  void (*start)(void) = (void (*)(void))start_address;

  // if section was found, use it's address as a start address
  start();

  return 0;
}
