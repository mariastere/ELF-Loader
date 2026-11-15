// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <sys/random.h>

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

static size_t align_down_to_page(size_t x, size_t page_size)
{
	return x - (x % page_size);
}

static size_t align_up_to_page(size_t x, size_t page_size)
{
	if (x % page_size == 0)
		return x;
	else
		return x + page_size - (x % page_size);
}

static int elf_flags_to_prot(Elf64_Word p_flags)
{
	int prot = 0;

	if (p_flags & PF_R)
		prot = prot | PROT_READ;
	if (p_flags & PF_W)
		prot = prot | PROT_WRITE;
	if (p_flags & PF_X)
		prot = prot | PROT_EXEC;
	return prot;
}

uint64_t *prepare_random(uint64_t *stack_ptr, void **random_ptr)
{
	stack_ptr = (uint64_t *)((uintptr_t)stack_ptr - 16);
	stack_ptr = (uint64_t *)((uintptr_t)stack_ptr & ~0xF);

	unsigned char random_bytes[16];

	for (int i = 0; i < 16; i++)
		random_bytes[i] = (unsigned char)(i * 13 + 42);

	memcpy(stack_ptr, random_bytes, 16);
	*random_ptr = stack_ptr;
	return stack_ptr;
}

uint64_t *push_aux_values(uint64_t *stack_ptr, void *random_ptr, uint64_t page_size, Elf64_Ehdr *elf_header, Elf64_Phdr *phdrs, char **env_ptrs, int envc,  char **arg_ptrs, int argc)
{
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)0;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)AT_NULL;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)random_ptr;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)AT_RANDOM;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)page_size;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)AT_PAGESZ;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)elf_header->e_phnum;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)AT_PHNUM;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)elf_header->e_phentsize;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)AT_PHENT;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)(elf_header->e_phoff + (uintptr_t)((Elf64_Addr)phdrs[0].p_vaddr - phdrs[0].p_offset));
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)AT_PHDR;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)elf_header->e_entry;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = (uint64_t)AT_ENTRY;
	stack_ptr = stack_ptr - 1;
	*stack_ptr = 0;
	for (int i = envc - 1; i >= 0; i--) {
		stack_ptr = stack_ptr - 1;
		*stack_ptr = (uint64_t)env_ptrs[i];
	}
	stack_ptr = stack_ptr - 1;
	*stack_ptr = 0;
	for (int i = argc - 1; i >= 0; i--) {
		stack_ptr = stack_ptr - 1;
		*stack_ptr = (uint64_t)arg_ptrs[i];
	}
	stack_ptr = stack_ptr - 1;
	*stack_ptr = argc;
	return stack_ptr;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);

	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */

	Elf64_Ehdr *elf_header = (Elf64_Ehdr *)elf_contents;

	if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "Not a valid Elf file\n");
		exit(3);
	}
	if (elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	/**
	 * TODO: Load PT_LOAD segments
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD segment:
	 * - Map the segments in memory. Permissions can be RWX for now.
	 */
	Elf64_Phdr *phdrs = (Elf64_Phdr *)((char *)elf_contents + elf_header->e_phoff);
	int prog_hdr_nr = elf_header->e_phnum;
	size_t page_size = (size_t) sysconf(_SC_PAGE_SIZE);

	for (int i = 0; i < prog_hdr_nr; ++i) {
		Elf64_Phdr *progr_hdr = &phdrs[i];

		if (progr_hdr->p_type != PT_LOAD)
			continue;
		Elf64_Addr map_addr = align_down_to_page(progr_hdr->p_vaddr, page_size);
		size_t map_offset = progr_hdr->p_vaddr - map_addr;
		size_t map_len = align_up_to_page(map_offset + progr_hdr->p_memsz, page_size);
		void *m = mmap((void *)map_addr, map_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

		if (m == MAP_FAILED) {
			fprintf(stderr, "mmap error\n");
			exit(1);
		}
		void *dest = (char *)m + map_offset;
		void *src = (char *)elf_contents + progr_hdr->p_offset;

		if (progr_hdr->p_filesz > 0)
			memcpy(dest, src, (size_t)progr_hdr->p_filesz);
		if (progr_hdr->p_memsz > progr_hdr->p_filesz)
			memset((char *)dest + progr_hdr->p_filesz, 0, (size_t)(progr_hdr->p_memsz - progr_hdr->p_filesz));
	}
	size_t stack_size = page_size * 8;
	void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	/**
	 * TODO: Load Memory Regions with Correct Permissions
	 * For each PT_LOAD segment:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */

	for (int i = 0; i < prog_hdr_nr; ++i) {
		Elf64_Phdr *progr_hdr = &phdrs[i];

		if (progr_hdr->p_type != PT_LOAD)
			continue;

		Elf64_Addr map_addr = align_down_to_page(progr_hdr->p_vaddr, page_size);
		size_t map_offset = progr_hdr->p_vaddr - map_addr;
		size_t map_len = align_up_to_page(map_offset + progr_hdr->p_memsz, page_size);

		int prot = elf_flags_to_prot(progr_hdr->p_flags);

		if (mprotect((void *)map_addr, map_len, prot) < 0) {
			fprintf(stderr, "mprotect error\n");
			exit(1);
		}
	}
	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */
	//void *sp = NULL;
	void *sp = (char *)stack + stack_size;
	uint64_t *stack_ptr = (uint64_t *)sp;

	void *random_ptr = NULL;

	stack_ptr = prepare_random(stack_ptr, &random_ptr);
	int envc = 0;

	while (envp[envc] != NULL)
		envc++;
	char **env_ptrs = malloc(sizeof(char *) * (envc + 1));

	for (int i = envc - 1; i >= 0; i--) {
		size_t len = strlen(envp[i]) + 1;

		stack_ptr = (uint64_t *)((char *)stack_ptr - len);
		memcpy(stack_ptr, envp[i], len);
		env_ptrs[i] = (char *)stack_ptr;
	}
	env_ptrs[envc] = NULL;
	char **arg_ptrs = malloc(sizeof(char *) * (argc + 1));

	for (int i = argc - 1; i >= 0; i--) {
		size_t len = strlen(argv[i]) + 1;

		stack_ptr = (uint64_t *)((char *)stack_ptr - len);
		memcpy(stack_ptr, argv[i], len);
		arg_ptrs[i] = (char *)stack_ptr;
	}
	arg_ptrs[argc] = NULL;
	stack_ptr = (uint64_t *)(((uintptr_t)stack_ptr) & ~0x7);

	stack_ptr = push_aux_values(stack_ptr, random_ptr, page_size, elf_header, phdrs, env_ptrs, envc, arg_ptrs, argc);
	sp = stack_ptr;

	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

	// TODO: Set the entry point and the stack pointer
	//void (*entry)() = NULL;
	void (*entry)() = (void (*)()) (elf_header->e_entry);

	free(arg_ptrs);

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
