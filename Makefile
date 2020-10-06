executable = my_tar
source = main.c

build: $(executable)

$(executable) : $(source)
	gcc $(source) -Wall -Werror -o $(executable)

clean:
	rm $(executable)
