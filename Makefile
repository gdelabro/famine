# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2020/10/23 19:47:08 by gdelabro          #+#    #+#              #
#    Updated: 2021/02/17 18:21:20 by gdelabro         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = famine

SRC_PATH = src
SRC_NAME = main.c process_file.c check_address.c check_already_infected.c

OBJ_PATH = obj
OBJ_NAME = $(SRC_NAME:.c=.o)

CC = gcc
CFLAGS = -Wall -Werror -Wextra

SRC = $(addprefix $(SRC_PATH)/,$(SR_NAME))
OBJ = $(addprefix $(OBJ_PATH)/,$(OBJ_NAME))

all: $(NAME)


$(NAME): $(OBJ)
	@printf "\n"
	@$(CC) $^ -o $@
	@echo "Compilation of \033[33;1m$(NAME)\033[0;1m: [\033[1;32mOK\033[0;1m]\033[0m"

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c
	@printf "\033[34;1m| \033[0;1m"
	@mkdir $(OBJ_PATH) 2> /dev/null || true
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -f $(OBJ)
	@rm -rf $(OBJ_PATH)
	@echo "\033[33;1m$(NAME)\033[0;1m: objects deleted"

fclean: clean
	@rm -rf $(NAME)
	@rm -rf woody
	@echo "\033[33;1m$(NAME)\033[0;1m: $(NAME) deleted"

re: fclean all

.PHONY: all clean fclean re
