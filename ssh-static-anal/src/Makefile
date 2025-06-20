.RECIPEPREFIX:=>

CXX=g++
CXXFLAGS=-O0 -ggdb3 -fsanitize=address -DDEBUG
WARN=-Wall -Wextra -Werror

SRC=cmn.cc main.cc pe.cc scan.cc 
OBJ=${SRC:%.c=%.o}
TGT=ssh-anal


TGT: ${OBJ}
> ${CXX} -o ${TGT} ${OBJ}

%.o: %.c
> ${CXX} ${CXXFLAGS} ${WARN} -c $< -o $@
