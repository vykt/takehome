.RECIPEPREFIX:=>

CXX=g++
CXXFLAGS=
WARN=-Wall -Wextra -Werror

ifeq($(build),debug)
	CXXFLAGS += -O0 -ggdb3 -fsanitize=address -DDEBUG
else
	CXXFLAGS += -O2 -flto
endif

SRC=cmn.cc main.cc
OBJ=${SRC:%.c=%.o}
TGT=ssh-anal


TGT: ${OBJ}
> ${CXX} -o ${TGT} ${OBJ}

%.o: %.c:
> ${CXX} ${CXXFLAGS} ${WARN} -c $< -o $@

clean:
> -rm ${OBJ} ${TGT}
