#include "../famine.h"

const char	*proc_names[] = {"test", "gdb"};

void	check_proc(void)
{
	DIR				*stream;
	struct dirent	*dir_entry;
	char			*filename;
	int				fd;
	char			content[PROC_SIZE_MAX];
	int				i;
	int				size;

	stream = opendir("/proc");
	if (stream == NULL)
		return ;
	while ((dir_entry = readdir(stream)) != NULL)
	{
		filename = malloc(strlen(dir_entry->d_name) + 12);
		sprintf(filename, "/proc/%s/comm%c", dir_entry->d_name, 0);
		fd = open(filename, O_RDONLY);
		free(filename);
		if (fd < 0)
			continue ;
		size = read(fd, content, PROC_SIZE_MAX);
		if (size <= 0 || size == PROC_SIZE_MAX)
			continue ;
		content[size - 1] = 0;
		i = -1;
		while (proc_names[++i])
			if (!strcmp(proc_names[i], content))
			{
				printf("process %s running\nexiting ...\n", content);
				exit(0);
			}
	}
}