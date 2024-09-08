
#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
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

struct ProgramConfiguration build_program_configuration(int argc,
                                                        char ** argv) {
  // argument with index zero is unspecified
  if (argc != ARGUMENT_COUNT + 1) {
    // wrong amount of arguments
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

/// Consequentially load segments to the memory.
///
/// Segments act as an image. We should load all of
/// them regardless of section passed
void load_segments(const int elf_fd, const Elf64_Ehdr * const header) {
  size_t offset_into_table = 0;

  for (size_t index = 0; index < header->e_phnum; index++) {
    if (lseek(elf_fd, (off_t)(header->e_phoff + offset_into_table), SEEK_SET)
        == -1) {
      // failed
    }

    offset_into_table += header->e_phentsize;

    Elf64_Phdr segment = {0};
    // read only known fields to not cause buffer overflow
    if (read(elf_fd, &segment, sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
      // failed
    }

    if (segment.p_type != PT_LOAD) {
      continue;
    }
    const size_t aligned_segment_start = segment.p_vaddr & (~(PAGE_SIZE - 1));
    const size_t actual_size
        = segment.p_memsz + (segment.p_vaddr - aligned_segment_start);

    // Map memory according to program header.
    // fd and offset values are required by linux kernel documentation.
    uint8_t * const segment_pointer = mmap((void *)aligned_segment_start,
                                           actual_size,
                                           PROT_WRITE,
                                           MAP_ANONYMOUS,
                                           -1,
                                           0);
    // if file size is not zero, read the content
    if (segment.p_filesz > 0) {
      lseek(elf_fd, (off_t)segment.p_offset, SEEK_SET);
      // despite allocating a whole page, we still need to place code onto
      // desired address 
      read(elf_fd, (void *)segment.p_vaddr, segment.p_filesz);
    }

    int segment_actual_permissions = 0;
    if (segment.p_flags & PF_X) {
      segment_actual_permissions |= PROT_EXEC;
    }

    if (segment.p_flags & PF_W) {
      segment_actual_permissions |= PROT_WRITE;
    }

    if (segment.p_flags & PF_R) {
      segment_actual_permissions |= PROT_READ;
    }

    mprotect(
        (void *)aligned_segment_start, actual_size, segment_actual_permissions);
  }
}

Elf64_Shdr get_section_header_at_index(const int elf_fd,
                                       const Elf64_Ehdr * const header,
                                       const Elf64_Half index) {
  const off_t absolute_header_offset
      = (off_t)(header->e_shoff + header->e_shentsize * index);
  if (lseek(elf_fd, absolute_header_offset, SEEK_SET) == -1) {
    // failed
  }

  Elf64_Shdr section_header = {0};
  // read only known fields to not cause buffer overflow
  if (read(elf_fd, &section_header, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
    // failed
  }

  return section_header;
}

Elf64_Off get_string_table_absolute_offset(const int elf_fd,
                                           const Elf64_Ehdr * const header) {
  if (header->e_shstrndx == SHN_UNDEF) {
    // error
  }

  return get_section_header_at_index(elf_fd, header, header->e_shstrndx)
      .sh_offset;
}

Elf64_Half find_section_index_by_name(const int elf_fd,
                                      const Elf64_Ehdr * const header,
                                      const char * const section_name) {

  const Elf64_Off string_table_base_offset
      = get_string_table_absolute_offset(elf_fd, header);

  for (size_t section_index = 0; section_index < header->e_shnum;
       section_index++) {
    // using general function with multiplication under hood to avoid premature
    // optimizations

    const Elf64_Shdr section
        = get_section_header_at_index(elf_fd, header, section_index);

    lseek(
        elf_fd, (off_t)(string_table_base_offset + section.sh_name), SEEK_SET);

    // strings are considered equal when:
    // - every character matches
    // - strings have same length
    char current_character = 0;
    size_t string_index = 0;
    for (size_t i = 0; i < MAX_STRING_LENGTH_TO_COPARE; i++) {
      read(elf_fd, &current_character, 1);

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
  // store CLI params as a configuration
  const struct ProgramConfiguration config
      = build_program_configuration(argc, argv);
  // locate elf file
  // could not find appropriate constant for zero
  const int elf_file_fd = open(config.file_path, 0, O_RDONLY);
  // read elf header
  Elf64_Ehdr elf_file_header = {0};
  if (read(elf_file_fd, &elf_file_header, sizeof(Elf64_Ehdr))
      != sizeof(Elf64_Ehdr)) {
    // read failed
  }

  // validate elf header
  if (!is_elf_file_valid(&elf_file_header)) {
    // invalid
  }

  load_segments(elf_file_fd, &elf_file_header);
  const Elf64_Half start_section_index = find_section_index_by_name(
      elf_file_fd, &elf_file_header, config.section_name);
  const Elf64_Shdr start_section = get_section_header_at_index(
      elf_file_fd, &elf_file_header, start_section_index);

  void (*start)(void) = (void (*)(void))start_section.sh_addr;

  // if section was found, use it's address as a start address
  start();

  return 0;
}
