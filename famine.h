#ifndef FAMINE_H
# define FAMINE_H

# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <string.h>
# include <unistd.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <sys/ptrace.h>
# include <fcntl.h>
# include <elf.h>
# include <dirent.h>

# define PROC_SIZE_MAX 64
# define signature	"Famine version 1.0 (c)oded feb-2021 by gdelabro"

typedef struct s_famine
{
	int			bits_added;
	Elf64_Phdr	*data;
}			t_famine;

void	check_proc(void);
void	check_debugger(void);

void	init_check_address(void *ptr, int size);
int		is_in_address(void *ptr);
int		is_str_in_address(char *str);
void	*get_ptr_start(void);
void	*get_ptr_end(void);

void	process_directory(char *dir_name);
void	process_file(char *name, char *path);

int		is_infected(char *ptr);

#endif