.RECIPEPREFIX:=>

CXX=g++
CXXFLAGS=-O0 -ggdb3 -fsanitize=address -DDEBUG
WARN=-Wall -Wextra -Werror

SRC=cmn.cc main.cc pe.cc scan.cc 
OBJ=${SRC:%.cc=%.o}
TGT=ssh-anal


TGT: ${OBJ}
> ${CXX} ${CXXFLAGS} -o ${TGT} ${OBJ}

%.o: %.cc
> ${CXX} ${CXXFLAGS} ${WARN} -c $< -o $@

clean:
> -rm $(TGT)
> -rm $(OBJ)
