#include "../famine.h"

void	*my_address_pages(int mode, void *ptr, uint32_t size)
{
	static void		*ptr_start = NULL;
	static void		*ptr_end = NULL;

	if (!mode)
	{
		ptr_start = ptr;
		ptr_end = ptr + size;
	}
	if (mode == 2)
	{
		if (ptr < ptr_start || ptr > ptr_end)
			return (NULL);
		return ((void*)1);
	}
	if (mode == 3)
		return (ptr_start);
	if (mode == 4)
		return (ptr_end);
	return (NULL);
}

void	init_check_address(void *ptr, int size)
{
	my_address_pages(0, ptr, size);
}

int	is_in_address(void *ptr) 
{
	int	ret;

	ret = (int)(long long int)my_address_pages(2, ptr, 0);
	return (ret);
}

int		is_str_in_address(char *str)
{
	int i;

	i = -1;
	while (++i)
	{
	if (!is_in_address(str + i))
		return (0);
	if (!str[i])
		return (1);
	}
	return (1);
}

void	*get_ptr_start(void)
{
	return (my_address_pages(3, NULL, 0));
}

void	*get_ptr_end(void)
{
	return (my_address_pages(4, NULL, 0));
}